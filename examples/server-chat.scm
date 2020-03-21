;;; this example tries to demonstrate a chat over SSH. much like the
;;; ssh.chat project.
(import minissh (chicken io) gochan chicken.string srfi-18 (chicken time posix)
        chicken.file chicken.port
        minissh.core chicken.condition
        matchable nrepl
        srfi-69 ;; hash-tables
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
                                                                                       (print-help)
                                                                                       (refresh e) "")
                                                                                #f))))
    (current-output-port (make-pty-output-port)))


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

  (let ((bc bc)) ;; grab bc now so we're sure we get our own broadcast
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
            (loop bc)))))))

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
         (with-channel-ports
          ch (lambda ()
               (handle-chat ch (ssh-user ssh) (ssh-user-pk ssh)))))))
    (lambda () (channel-accept ssh pty: #t)))))
