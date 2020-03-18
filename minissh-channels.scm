(import gochan matchable
        srfi-69 srfi-18
        (only (chicken tcp) tcp-read-timeout)
        (only (chicken memory) move-memory!)
        (chicken port)
        (chicken string)
        (chicken io)
        (chicken condition))

(define %current-ssh-rcid   (make-parameter #f)) (define %current-ssh-lcid   (make-parameter #f))
(define %current-ssh-rws    (make-parameter #f)) (define %current-ssh-lws    (make-parameter (* 1 1024)))
(define %current-ssh-rmps   (make-parameter #f)) (define %current-ssh-lmps   (make-parameter 32767))
(define %current-ssh-chan  (make-parameter #f))
(define current-ssh-user   (make-parameter #f))
(define current-ssh-userpk (make-parameter #f))
(define current-datachan   (make-parameter #f))

(define %current-ssh-state (make-parameter (vector #f #f #f #f)))
(define (current-ssh-command)     (vector-ref (%current-ssh-state) 0))
(define (current-terminal-width)  (vector-ref (%current-ssh-state) 1))
(define (current-terminal-height) (vector-ref (%current-ssh-state) 2))
(define (current-terminal-modes)  (vector-ref (%current-ssh-state) 3))

;; lowest remote window size
(define current-ssh-watermark/minimum   (make-parameter (* 1024 1024)))
;; remote window size increment once below current-ssh-watermark/minimum
(define current-ssh-watermark/increment (make-parameter (* 1024 1024)))
;; remote window size will always be between these two values

(define (channels-accept ssh proc #!key (tcp-read-timeout tcp-read-timeout))
  (define chan-network-read  (gochan 0)) ;; from separate reader thread to main loop
  (define chan-output (gochan 0)) ;; from channel threads to main loop
  ;; TODO: clean up these
  (define lcid->thread (make-hash-table))
  (define lcid->rcid (make-hash-table))
  (define lcid->state  (make-hash-table))
  (define lcid->datachan (make-hash-table))
  (define lcid->lwschan (make-hash-table))
  (define lcid 100)

  (tcp-read-timeout #f)
  (thread-start!
   (make-thread
    (lambda ()
      (let loop ()
        (let ((msg (next-payload ssh)))
          (unless (eof-object? msg) ;; currently unimplemented, getting errors instead
            (gochan-send chan-network-read msg)
            (loop)))))
    ;;                  ,-- remote port number
    (conc "minissh@" (cadr (receive (tcp-port-numbers (ssh-ip ssh)))))))

  ;; we need chan-output when we must notify of bigger window size.
  (define (gochan->input-port gochan)

    (let ((buffer "") (pos 0)) ;; buffer is #f for #!eof

      (define (fill!)
        (let loop ()
          (when (and buffer (>= pos (string-length buffer)))
            (gochan-select
             ((gochan -> msg closed?)
              (if closed?
                  (set! buffer #f)
                  (begin
                    (%current-ssh-lws (- (%current-ssh-lws) (string-length msg)))
                    (when (<= (%current-ssh-lws) (current-ssh-watermark/minimum))
                      (%current-ssh-lws (+ (%current-ssh-lws) (current-ssh-watermark/increment)))
                      (gochan-send chan-output `(lws ,(%current-ssh-rcid) ,(current-ssh-watermark/increment))))
                    (set! buffer msg)
                    (set! pos 0)
                    (loop))))))))

      (make-input-port
       (lambda () ;; read
         (fill!)
         (if buffer
             (let ((c (string-ref buffer pos)))
               (set! pos (+ 1 pos))
               c)
             #!eof))
       (lambda () ;; ready?
         (fill!)
         (if buffer
             (if (>= pos (string-length buffer))
                 #t
                 #f) ;;; <-- TODO: gochan-select with 0 timeout
             #t)) ;; <-- eof is always ready
       (lambda () ;; close
         (gochan-close gochan))
       (lambda () ;; peek
         (fill!)
         (if buffer
             (string-ref buffer pos)
             #!eof))
       (lambda (port len dest offset) ;; read-string!
         (let loop ((want len)
                    (offset offset)
                    (filled 0))

           (if buffer
               ;;      ,-- number of bytes left in buffer
               (let ((got (- (string-length buffer) pos)))
                 (if (>= got want) ;; we have enough to fill dest
                     (begin
                       ;;            from   to   bytes from-offset to-offset
                       (move-memory! buffer dest want  pos         offset)
                       (set! pos (+ pos want))
                       (+ filled want))
                     (begin ;; we don't have enough, but fill in what we have and retry
                       (move-memory! buffer dest got   pos         offset)
                       (set! pos (+ pos got))
                       (fill!) ;; obs: this _must_ replace our buffer now
                       (loop (- want got)
                             (+ offset got)
                             (+ filled got)))))
               ;; eof:
               filled))))))



  (let loop ()
    (gochan-select
     ((chan-network-read -> msg closed?)
      (match msg

        (('channel-open type rcid rws rmax-ps)
         (let ((state (vector #f #f #f #f))
               (datachan (gochan 1024))  ;; incoming channel-data
               (lwschan  (gochan 1024))) ;; incoming window-adjust

           (set! lcid (+ lcid 1)) ;; TODO: do something better here?
           (hash-table-set! lcid->rcid      lcid rcid)
           (hash-table-set! lcid->state     lcid state)
           (hash-table-set! lcid->datachan  lcid datachan)
           (hash-table-set! lcid->lwschan   lcid lwschan)
           (hash-table-set!
            lcid->thread
            lcid
            (thread-start!
             (lambda ()

               (%current-ssh-rcid rcid)
               (%current-ssh-rws  rws)
               (%current-ssh-rmps rmax-ps)
               (%current-ssh-lcid lcid)
               (%current-ssh-state state) ;; read-only from this thread
               (current-datachan datachan)

               (current-input-port (gochan->input-port (current-datachan)))

               ;; TODO: make this robust somehow.
               ;; (current-error-port
               ;;  (make-output-port
               ;;   (lambda (str) (gochan-send chan-output `(data ,(%current-ssh-rcid) ,str 1)))
               ;;   (lambda ()    (gochan-send chan-output `(close ,(%current-ssh-rcid))))))

               (let ((cop
                      (make-output-port
                       (lambda (str)
                         (let loop ((str str))
                           (define (send! str)
                             (%current-ssh-rws (- (%current-ssh-rws) (string-length str)))
                             (gochan-send chan-output `(data ,(%current-ssh-rcid) ,str)))
                           ;;       ,-- number of bytes we can send
                           (let ((limit (min (%current-ssh-rws) (%current-ssh-rmps))))
                             (if (<= (string-length str) limit) ;; room for all
                                 (unless (equal? "" str)
                                   (send! str))
                                 (if (> limit 0) ;; room for more
                                     (begin (send! (substring str 0 limit))
                                            (loop  (substring str limit)))
                                     ;; room for no more, wait for window-adjust
                                     ;; TODO: handle closed lwschan
                                     (begin (%current-ssh-rws (+ (%current-ssh-rws) (gochan-recv lwschan)))
                                            (loop str)))))))
                       (lambda ()    (gochan-send chan-output `(close ,(%current-ssh-rcid)))))))
                 (current-output-port cop)
                 (dynamic-wind
                     (lambda () #f)
                     (lambda ()
                       (let ((result (proc)))
                         (gochan-send chan-output `(exit-status ,(%current-ssh-rcid)
                                                                ,(if (number? result) result 0)))))
                     (lambda () (close-output-port cop)))))))
           (unparse-channel-open-confirmation ssh rcid lcid (%current-ssh-lws) (%current-ssh-lmps))))

        (('channel-request lcid 'pty-req want-reply? term
                           width/characters height/rows ;; numbers
                           width/pixels height/pixels ;; numbers, usuall 0
                           modes)                     ;; blob
         ;; TODO: make denying this possible
         ;; TODO: give this as an event to channel-thread
         (let ((v (hash-table-ref lcid->state lcid)))
           (vector-set! v 1 width/characters)
           (vector-set! v 2 height/rows)
           (vector-set! v 3 modes))
         (when want-reply?
           (unparse-channel-success ssh (hash-table-ref lcid->rcid lcid))))

        (('channel-request lcid 'shell want-reply?)
         ;; TODO: make denying this possible
         ;; TODO: ensure ssh-op isn't closed before trying to write (we see many Broken pipe errors)
         (when want-reply? (unparse-channel-success ssh (hash-table-ref lcid->rcid lcid))))

        (('channel-request lcid 'exec want-reply? cmd) ;; cmd as in `ssh you@host "cmd string here"`
         (vector-set! (hash-table-ref lcid->state lcid) 0 cmd)
         (when want-reply? (unparse-channel-success ssh (hash-table-ref lcid->rcid lcid))))

        (('channel-data lcid str)
         ;; TODO: handle window size decrement somewhere
         (let* ((t (hash-table-ref lcid->thread lcid (lambda () #f)))
                (ts (and t (thread-state t))))
           (if (or (eq? ts 'terminated)
                   (eq? ts 'dead))
               (begin
                 (unparse-channel-close ssh (hash-table-ref lcid->rcid lcid))
                 (hash-table-delete! lcid->thread lcid)
                 (hash-table-delete! lcid->datachan lcid))
               (let ((chan (hash-table-ref lcid->datachan lcid (lambda () #f))))
                 (and chan (gochan-send chan str))))))

        (('channel-window-adjust lcid increment)
         (gochan-send (hash-table-ref lcid->lwschan lcid) increment))

        (('channel-eof lcid)
         (gochan-close (hash-table-ref lcid->datachan lcid)))

        (('channel-close lcid) ;; noop if already closed
         (gochan-close (hash-table-ref lcid->datachan lcid)))

        (('disconnect reason-code description language)
         ;; TODO: make this accessible to user apps. description from
         ;; OpenSSH is "disconnected by user" on C-d.
         #f)

        (else (error "unknown packet" msg))))

     ((chan-output -> msg closed?)
      (match msg
        (('channel-open-confirmation rcid lcid lws lmps)
         (unparse-channel-open-confirmation ssh rcid lcid lws lmps))
        (('data rcid data)
         (unparse-channel-data ssh rcid data))
        (('data rcid data idx)
         (unparse-channel-extended-data ssh rcid idx data))
        (('close rcid)
         (unparse-channel-eof ssh rcid)
         (unparse-channel-close ssh rcid))
        (('lws rcid increment)
         (unparse-channel-window-adjust ssh rcid increment))
        (('exit-status rcid exit-status)
         (unparse-channel-request ssh rcid 'exit-status #f exit-status))
        (else (error "unknown packet from thread" msg)))))
    (loop)))
