;;; this example tries to demonstrate a chat over SSH. much like the
;;; ssh.chat project.
(import minissh (chicken io) gochan chicken.string srfi-18 (chicken time posix)
        chicken.file chicken.port base64
        minissh.core chicken.condition
        chicken.irregex
        matchable nrepl matchable
        srfi-69 ;; hash-tables
        chicken.random
        (prefix utf8 utf8.))

(include "examples/pty.scm")

(define host-pk
  "AAAAC3NzaC1lZDI1NTE5AAAAIIfd+rbtTF2hJJbnnbQxtp2UVrUWkQtnsT8CL9iLpZBZ")
(define host-sk ;; the secret key would normally be kept safe
  #${ba72291c15494ee02003b3c0bb0f8507a6a803850aa811d015b141a193e2447d
     87ddfab6ed4c5da12496e79db431b69d9456b516910b67b13f022fd88ba59059})

(define (print-help)
  (print "commands:\r
 /help\r
 /exit\r
 /users\r"))

(define (greeting)
  (print ";; Welcome to secure CHICKEN chat
;; Or, it might have been secure if the secret key
;; wasn't committed in the official repo. Everything
;; you send is broadcast to everyone.
;; Problems? <enter>~.<enter> forces ssh disconnect"))

(define chan #f)
(define current-channel (make-parameter #f))

;; config file for replacing host keys etc
(if (file-exists? ".server-chat.scm")
    (load         ".server-chat.scm"))

(print "running minissh chat server
test with: ssh localhost -p 22022 chat")

(define _userpks (make-hash-table))
(define userpk
  (getter-with-setter
   (lambda (user) (hash-table-ref _userpks user (lambda () #f)))
   (lambda (user pk) (hash-table-set! _userpks user pk) (userpk user))))
(define (userpks) (hash-table-keys _userpks))

(define (print-users)
  (print "/users " (hash-table-size _userpks) ":\r")
  (hash-table-for-each
   _userpks
   (lambda (user pk) (print pk " " user))))

(define bc (gochan 0))
(define msgs (gochan 0))

;; this is a publish-subscribe pattern of some sort. we chain the
;; gocha's together, starting with the top-level bc (later
;; replaced). when the gochan is closed, it points to the gochan that
;; will get the next message (in the close flag). this ensures that no
;; messages get lost, and nobody misses a gochan instance in the
;; middle of the chain. GC should pick up unreferenced gochan's
;; backwards in the chain.
(define (broadcast! msg)
  (let ((chan-next (gochan 0)))
    (gochan-close bc (list chan-next msg))
    (set! bc chan-next)))

(define (print-msg user msg self?)
  (let ((color (if self? 33 34)))
    (display (conc "\r\x1b[K\x1b[32m" (time->string (seconds->local-time) "%H:%M")
                   " \x1b[" color "m" user "\x1b[0m")))
  (if (string? msg)
      (print " " msg) ;;  ,-- eg 'joined or 'eof
      (print " \x1b[31m" msg "\x1b[0m")))

(define publisher
  (let ((ht (make-hash-table)))
    (getter-with-setter
     (lambda (pid) (hash-table-ref ht pid (lambda ()#f)))
     (lambda (pid v) (hash-table-set! ht pid v)))))

(define (handle-chat ch user pk)

  (define alive (gochan 0))
  (define e (make-edit))

  (define (refresh* e)
    (edit-render e (max 0 (- (or (channel-terminal-width ch) 60) (utf8.string-length user) 2))
                 #:prefix (conc  "\r\x1b[K[\x1b[33m" user "\x1b[0m] ")))

  (define (refresh e) ;; avoids ugly print race-conditions
    (gochan-send alive #f))

  (define (clear) (display "\r\x1b[K"))
  (when (channel-terminal ch)
    (current-input-port (make-pty-readline-port #:edit e
                                                #:update refresh
                                                #:done (lambda (e) #f)
                                                #:keystroke (lambda (e cmd) (if (eq? cmd 'C-c)
                                                                                (begin (clear)
                                                                                       (print-users)
                                                                                       (refresh e) "")
                                                                                #f))))
    (current-output-port (make-pty-output-port)))

  (define (chat)
    (greeting)
    (thread-start!
     (lambda ()
       (let ((ceh (current-exception-handler)))
         (current-exception-handler (lambda (e) (gochan-close alive) (ceh e))))
       (call/cc
        (lambda (quit)
          (let loop ()
            (let ((body (read-line)))
              (cond ((eof-object? body))
                    ((equal? body "") (loop))
                    ((equal? body "/help")  (clear) (print-help)  (refresh e) (loop))
                    ((equal? body "/users") (clear) (print-users) (refresh e) (loop))
                    ((equal? body "/exit"))
                    ((eq? (string-ref body 0) #\/) (clear) (print "unknown command " body) (refresh e) (loop))
                    (else
                     (broadcast! (list user body))
                     (loop)))))))
       (gochan-close alive)))

    ;; ignore ping channel failures, they are just to avoid TCP
    ;; connections dying.
    (set! (ssh-handler (channel-ssh ch) 'channel-failure) (lambda (ssh p) #f))

    (let ((tick (gochan-tick (* 30 1000)))
          (bc bc)) ;; grab bc now so we're sure we get our own broadcast
      (broadcast! (list user 'joined))
      (let loop ((bc bc))
        (gochan-select
         ((bc -> _ msg)
          (match msg
            ((bc (from msg))
             (print-msg from msg (equal? user from))
             (display (conc "\x1b]0;chat " user ": " msg "\x07")) ;; set terminal title
             (refresh* e)
             (loop bc))))
         ((alive -> request closed?)
          (refresh* e)
          (if closed?
              (broadcast! (list user 'left))
              (loop bc)))
         ((tick -> t closed?)
          ;; keep TCP connection alive by sending a custom channel
          ;; request (which will fail).
          (unparse-channel-request (channel-ssh ch) (channel-rcid ch) 'keepalive@minissh #t)
          (loop bc))))
      (unparse-channel-request (channel-ssh ch) (channel-rcid ch) 'exit-status #f 0)
      (channel-eof ch)
      (channel-close ch)))


  (define (handle-pub users)
    (let ((users (alist->hash-table (map (lambda (u) (cons u #t)) users))) ;; list->set
          (pid (base64-encode (random-bytes (make-string 18))))
          (chan (gochan 0))
          (sub->chan (make-hash-table)))
      (set! (publisher pid) chan)
      (let ((info (with-output-to-string (lambda ()
                                           (print "publishing on: ssh <host> sub '" pid "'\r")
                                           (hash-table-for-each users
                                                                (lambda (user ch)
                                                                  (print "subscriber " (userpk user) " " user)))))))
        (channel-write ch info 'stderr))
      (define (status! user)
        (let ((msg (conc
                    "waiting for subscribers (" (hash-table-size sub->chan) "/" (hash-table-size users) ")"
                    (if user
                        (conc " incoming: "
                              (with-output-to-string (lambda () (write user))))
                        "")
                    "\n")))
          ;; notify publisher
          (channel-write ch msg 'stderr)
          ;; notify subscribers
          (hash-table-for-each sub->chan
                               (lambda (user ch)
                                 (handle-exceptions
                                     e (begin (ssh-log "bad write: " e))
                                     (channel-write ch msg 'stderr))))))
      (status! #f)
      (define (subscribers-wait-all)
        (let loop ()
          (if (= (hash-table-size users) (hash-table-size sub->chan))
              #t
              (gochan-select
               ((chan -> user.ch closed?)
                (if (hash-table-ref users (car user.ch) (lambda () #f))
                    (begin
                      (hash-table-set! sub->chan (car user.ch) (cadr user.ch))
                      (status! (car user.ch))
                      (loop))
                    (begin (gochan-send (cadr user.ch) "bad user")
                           (gochan-close (cadr user.ch)))))))))
      (ssh-log "waiting for subscribers " ch)
      (subscribers-wait-all)
      (set! (publisher pid) #f)
      (ssh-log "waiting for subscribers done " ch)
      (handle-exceptions e (begin (ssh-log "bad read: " e))
                         (let loop ()
                           (let ((str (car (receive (channel-read ch)))))
                             (unless (eof-object? str)
                               ;;(ssh-log "GOT: " str)
                               (hash-table-for-each sub->chan
                                                    (lambda (user ch)
                                                      (handle-exceptions
                                                          e (begin (ssh-log "bad write: " e))
                                                          (channel-write ch str))))
                               (loop)))))
      (ssh-log "publisher EOF")
      (hash-table-for-each sub->chan (lambda (u ch) (channel-eof ch) (channel-close ch)))
      (channel-eof ch)
      (channel-close ch)))

  (define (handle-sub pid)
    (let ((chan (publisher pid)))
      (if chan
          (begin (ssh-log "sub attempt success " user " " chan)
                 (gochan-send chan (list user ch)))
          (begin (ssh-log "sub attempt failure " user " " chan "")
                 (channel-write ch (conc "bad subscribtion " pid "\r\n") 'stderr)
                 (channel-eof ch)
                 (channel-close ch)))))

  (match (cond ((channel-command ch) => (lambda (cmd) (irregex-split `(+ " ") cmd)))
               (else #f))
    (("pub" . users) (handle-pub users))
    (("sub" pid) (handle-sub pid))
    ((or #f ("chat")) (chat))
    (else (channel-write ch (conc "unknown command: " else "\r\n"))
          (channel-eof ch)
          (channel-close ch))))


(thread-start! (lambda () (import nrepl) (nrepl 1234 host: "127.0.0.1")))
(ssh-server-start
 host-pk host-sk
 (lambda (ssh)
   (set! _ssh ssh)
   (userauth-accept ssh
                    publickey:
                    (lambda (user type pk signed?)
                      (if signed?
                          (equal? pk (or (userpk user)
                                         (set! (userpk user) pk)))
                          #t)))
   (port-for-each
    (lambda (ch)
      (thread-start!
       (lambda ()
         (current-channel ch)
         (current-output-port (channel-output-port ch))
         (current-input-port  (channel-input-port ch))
         (handle-chat ch (ssh-user ssh) (ssh-user-pk ssh)))))
    (lambda () (channel-accept ssh pty: #t)))))
