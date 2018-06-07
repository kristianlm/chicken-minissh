;; included from minissh.scm

(use gochan)


(define-record-type ssh-channel
  (%make-ssh-channel ssh type ;; type is almost always "session"
                     cid ;; same id for sender and receiver
                     mutex cv
                     max-ps
                     bytes/read bytes/write) ;; window sizes
  ;; TODO: field for max packet size
  ;; TODO: field for exit-status, exec command?
  ssh-channel?
  (ssh  ssh-channel-ssh)
  (type ssh-channel-type)
  (cid  ssh-channel-cid)
  (mutex ssh-channel-mutex)
  (cv    ssh-channel-cv)
  (max-ps      ssh-channel-max-ps)
  (bytes/read  ssh-channel-bytes/read  %ssh-channel-bytes/read-set!)
  (bytes/write ssh-channel-bytes/write %ssh-channel-bytes/write-set!))

(define (make-ssh-channel ssh type cid bytes/read bytes/write max-ps)
  (assert (ssh? ssh))
  (assert (string? type))
  (assert (integer? cid))
  (assert (integer? bytes/read))
  (assert (integer? bytes/write))
  (%make-ssh-channel ssh type cid
                     (make-mutex) (make-condition-variable)
                     max-ps
                     bytes/read bytes/write))

;; add it to the ssh channel hash-table
(define (handle-channel-open ssh type cid ws-remote max-ps)

  (define ws-local #x000010)
  (define max-packet-size #x800000)

  (unparse-channel-open-confirmation
   ssh cid cid ws-local max-packet-size)

  (set! (ssh-channel ssh cid)
        (make-ssh-channel ssh type cid
                          ws-local
                          ws-remote
                          max-ps)))

(define (handle-channel-close ssh cid)
  (hash-table-delete! (ssh-channels ssh) cid))

(define (handle-channel-data ssh cid str #!optional (increment #x10000000))

  (define ch (ssh-channel ssh cid))
  (define m (ssh-channel-mutex ch))

  (mutex-lock! m)

  (%ssh-channel-bytes/read-set!
   ch (- (ssh-channel-bytes/read ch) (string-length str)))

  ;; only 1MB left of window? give client more window space.
  ;; TODO: make this customizable
  (when (<= (ssh-channel-bytes/read ch) (* 1 1024 1024))
    (%ssh-channel-bytes/read-set!
     ch (+ (ssh-channel-bytes/read ch) increment))
    (unparse-channel-window-adjust ssh cid increment))

  (mutex-unlock! m))

;; ====================

(define (ssh-channel-write ch str stderr?)
  (assert (string? str))

  ;; transport layer limits packet sizes too
  (define max-ps (min (ssh-channel-max-ps ch) 32768))
  (define (send! str)
    (if stderr?
        (unparse-channel-extended-data (ssh-channel-ssh ch)
                                       (ssh-channel-cid ch)
                                       1
                                       str)
        (unparse-channel-data (ssh-channel-ssh ch)
                              (ssh-channel-cid ch)
                              str))

    (%ssh-channel-bytes/write-set! ch (- (ssh-channel-bytes/write ch)
                                         (string-length str))))
  (define m (ssh-channel-mutex ch))

  (let loop ((str str))
    (define limit (min max-ps (ssh-channel-bytes/write ch)))
    (mutex-lock! m)
    (if (<= (string-length str) limit)
        (if (string-null? str)
            (mutex-unlock! m)  ;; don't send empty data packets
            (begin (send! str) ;; room for everything
                   (mutex-unlock! m)))
        (if (> limit 0) ;; room for some
            (begin
              (send! (substring str 0 limit))
              (mutex-unlock! m)
              (loop (substring str limit)))
            (begin ;; room for nothing, wait
              (mutex-unlock! m (ssh-channel-cv ch))
              (loop str))))))


(define (run-channels ssh #!key
                      (exec (lambda (ssh cmd) (display "channel-request `exec` unhandled\r\n" (current-error-port))))
                      (shell (lambda (ssh) (display "channel-request `shell` unhandled (try invoking ssh client with arguments)\r\n" (current-error-port))))
                      (unhandled (lambda (x continue)
                                   (ssh-log-ignore/parsed ssh x)
                                   (continue))))

  (unless (ssh-user ssh)
    (error "run-channels called before userauth"))

  (define ssh-channel-gochan
    (let ((ht (make-hash-table)))
     (getter-with-setter
      (lambda (cid) (hash-table-ref ht cid))
      (lambda (cid chan) (hash-table-set! ht cid chan)))))

  (define (with-channel-io cid thunk)
    (define chan (ssh-channel-gochan cid))
    (parameterize
        ((current-output-port
          (make-output-port
           (lambda (str)
             (##sys#with-print-length-limit ;; <-- avoid ##sys#print exits
              #f (lambda () (ssh-channel-write (ssh-channel ssh cid) str #f))))
           (lambda ()
             (unparse-channel-eof ssh cid)
             (unparse-channel-close ssh cid))))

         (current-error-port
          (make-output-port
           (lambda (str)
             (##sys#with-print-length-limit ;; <-- avoid ##sys#print exits
              #f (lambda () (ssh-channel-write (ssh-channel ssh cid) str #t))))
           (lambda ()
             (unparse-channel-eof ssh cid)
             (unparse-channel-close ssh cid))))

         (current-input-port
          (let ((buffer "") (pos 0)) ;; buffer is #f for #!eof
            (make-input-port
             (lambda ()
               (if buffer
                   (let loop ()
                     (if (>= pos (string-length buffer))
                         (gochan-select
                          ((chan -> msg closed?)
                           (cond (closed? (set! buffer #f) #!eof)
                                 (else
                                  (set! buffer msg)
                                  (set! pos 0)
                                  (loop)))))
                         (let ((c (string-ref buffer pos)))
                           (set! pos (+ 1 pos))
                           c)))
                   #!eof))
             (lambda () #t)
             void))))
      (handle-exceptions
          e (begin (close-output-port (current-output-port))
                   (close-input-port (current-input-port))
                   ((current-exception-handler) e))
          (thunk)
          (close-output-port (current-output-port))
          ;; current-error-port same as current-output-port
          (close-input-port (current-input-port)))))

  (tcp-read-timeout #f)
  (let loop ()
    (match (next-payload ssh)

      (('channel-open type cid ws max-packet)
       (handle-channel-open ssh type cid ws max-packet)
       (set! (ssh-channel-gochan cid) (gochan 0))
       (loop))

      (('channel-request cid 'exec want-reply? command)
       (unparse-channel-success ssh cid)
       (go (with-channel-io cid (lambda () (exec ssh command))))
       (loop))

      (('channel-request cid 'shell want-reply?)
       (unparse-channel-success ssh cid)
       (go (with-channel-io cid (lambda () (shell ssh))))
       (loop))

      (('channel-data cid str)
       (handle-channel-data ssh cid str)
       (gochan-send (ssh-channel-gochan cid) str)
       (loop))

      (('channel-eof cid)
       (gochan-close (ssh-channel-gochan cid))
       (loop))

      (('channel-close cid)
       (gochan-close (ssh-channel-gochan cid))
       (handle-channel-close ssh cid)
       (loop))

      (('channel-window-adjust cid increment)
       (let ((ch (ssh-channel ssh cid)))

         (define m (ssh-channel-mutex ch))
         (mutex-lock! m)

         (%ssh-channel-bytes/write-set!
          ch (+ (ssh-channel-bytes/write ch) increment))

         (condition-variable-broadcast! (ssh-channel-cv ch))

         (mutex-unlock! m)

         (loop)))

      (('disconnect reason message language))

      (else (unhandled else loop)))))
