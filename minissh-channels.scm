;; included from minissh.scm

(use gochan)


(define-record-type ssh-channel
  (%make-ssh-channel ssh type ;; type is almost always "session"
                     cid ;; same id for sender and receiver
                     bytes/read bytes/write) ;; window sizes
  ;; TODO: field for max packet size
  ;; TODO: field for exit-status, exec command?
  ssh-channel?
  (ssh  ssh-channel-ssh)
  (type ssh-channel-type)
  (cid  ssh-channel-cid)
  (bytes/read  ssh-channel-bytes/read  %ssh-channel-bytes/read-set!)
  (bytes/write ssh-channel-bytes/write %ssh-channel-bytes/write-set!))

(define (make-ssh-channel ssh type cid bytes/read bytes/write)
  (assert (ssh? ssh))
  (assert (string? type))
  (assert (integer? cid))
  (assert (integer? bytes/read))
  (assert (integer? bytes/write))
  (%make-ssh-channel ssh type cid bytes/read bytes/write))

;; add it to the ssh channel hash-table
(define (handle-channel-open ssh type cid ws-remote max)

  (define ws-local #x000010)
  (define max-packet-size #x800000)

  (unparse-channel-open-confirmation
   ssh cid cid ws-local max-packet-size)

  (set! (ssh-channel ssh cid)
        (make-ssh-channel ssh type cid
                          ws-local
                          ws-remote)))

(define (handle-channel-close ssh cid)
  (hash-table-delete! (ssh-channels ssh) cid))

(define (handle-channel-data ssh cid str #!optional (increment #x10000000))

  (define ch (ssh-channel ssh cid))
  (%ssh-channel-bytes/read-set!
   ch (- (ssh-channel-bytes/read ch) (string-length str)))

  ;; only 1MB left of window? give client more window space.
  ;; TODO: make this customizable
  (when (<= (ssh-channel-bytes/read ch) (* 1 1024 1024))
    (%ssh-channel-bytes/read-set!
     ch (+ (ssh-channel-bytes/read ch) increment))
    (unparse-channel-window-adjust ssh cid increment)))

;; ====================

(define (ssh-channel-write ch str #!optional stderr?)
  (assert (string? str))
  (define len (string-length str))
  (when (< (ssh-channel-bytes/write ch) len)
    ;;(print "TODO: handle wait for window adjust")
    )
  (if stderr?
      (unparse-channel-extended-data (ssh-channel-ssh ch)
                                     (ssh-channel-cid ch)
                                     1
                                     str)
      (unparse-channel-data (ssh-channel-ssh ch)
                            (ssh-channel-cid ch)
                            str))
  (%ssh-channel-bytes/write-set!
   ch (- (ssh-channel-bytes/write ch) len)))


(define (run-channels ssh #!key
                      (exec (lambda (ssh cmd) (display "channel-request `exec` unhandled\r\n" (current-error-port))))
                      (shell (lambda (ssh) (display "channel-request `shell` unhandled (try invoking ssh client with arguments)\r\n" (current-error-port)))))

  (unless (ssh-user ssh)
    (error "run-channels called before userauth"))

  (define ht (make-hash-table))
  (define chan-send (gochan 0))

  (define (with-channel-io cid thunk)
    (define chan (hash-table-ref ht cid))
    (parameterize
        ((current-output-port
          (make-output-port
           (lambda (str) (gochan-send chan-send (list cid str #f)))
           (lambda ()    (gochan-send chan-send (list cid 'close)))))
         (current-error-port
          (make-output-port
           (lambda (str) (gochan-send chan-send (list cid str #t)))
           (lambda ()    (gochan-send chan-send (list cid 'close)))))
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
      (thunk)
      ;; (close-output-port (current-output-port)) obs: only 1 close per channel
      (close-output-port (current-error-port))))

  (go (let loop ()
        (gochan-select
         ((chan-send -> msg)
          (match msg
            ((cid 'close)
             (unparse-channel-eof ssh cid)
             (unparse-channel-close ssh cid))
            ((cid str stderr?)
             (ssh-channel-write (ssh-channel ssh cid) str stderr?)))
          (loop)))))

  (tcp-read-timeout #f)
  (let loop ()
    (match (next-payload ssh)

      (('channel-open type cid ws max-packet)
       (handle-channel-open ssh type cid ws max-packet)
       (hash-table-set! ht cid (gochan 0))
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
       (gochan-send (hash-table-ref ht cid) str)
       (loop))

      (('channel-eof cid)
       (gochan-close (hash-table-ref ht cid))
       (loop))

      (('channel-close cid)
       (gochan-close (hash-table-ref ht cid))
       (handle-channel-close ssh cid)
       (loop))

      (('disconnect reason message language))

      (else (ssh-log "IGNORING : " (wots (write else)))
            (loop)))))
