(import minissh nrepl gochan
        srfi-69 srfi-18
        (chicken tcp) (chicken port) (chicken io) (chicken condition))

;; the secret key would normally be kept safe
(define host-pk
  "AAAAC3NzaC1lZDI1NTE5AAAAIIfd+rbtTF2hJJbnnbQxtp2UVrUWkQtnsT8CL9iLpZBZ")
(define host-sk
  #${ba72291c15494ee02003b3c0bb0f8507a6a803850aa811d015b141a193e2447d
     87ddfab6ed4c5da12496e79db431b69d9456b516910b67b13f022fd88ba59059})

(print "test with: ssh localhost -p 22022 chat")

(define _userpks (make-hash-table))
(define userpk
  (getter-with-setter
   (lambda (user) (hash-table-ref _userpks user (lambda () #f)))
   (lambda (user pk) (hash-table-set! _userpks user pk) (userpk user))))
(define (userpks) (hash-table-keys _userpks))

(define bc (gochan 0))
(define msgs (gochan 0))

(define chat-thread
  (begin (handle-exceptions e (void) (thread-terminate! chat-thread))
         (thread-start!
          (lambda ()
            (let loop ()
              (gochan-select
               ((msgs -> msg)
                (gochan-close bc msg)
                (set! bc (gochan 0))
                (loop))))))))


(define (print-users)
  (hash-table-for-each
   _userpks
   (lambda (user pk) (print pk " " user))))

(define (handle-chat ssh)

  (gochan-send msgs (list (ssh-user ssh) 'join))

  (print ";; Welcome to secure CHICKEN chat")
  (print ";; This might have been secure if the secret key wasn't committed.")
  (print ";; ")
  (print ";; Everything you send is broadcast to everyone.")
  (print ";; Type (users) to see list of users")

  (define (prompt)
    (display (ssh-user ssh))
    (display "> "))

  (define alive (gochan 0))

  (thread-start!
   (lambda ()
     (let loop ()
       (prompt)
       (define msg (read-line))
       (unless (eof-object? msg)
         (if (equal? "(users)" msg)
             (print-users)
             (gochan-send msgs (list (ssh-user ssh) msg)))
         (thread-sleep! 0.1) ;; async gets nasty quickly
         (loop))
       (gochan-send msgs (list (ssh-user ssh) 'eof))
       (gochan-close alive))))

  (let loop ()
    (gochan-select
     ((bc -> _ msg)
      (display "\r>>")
      (write msg) (display "          \n")
      (loop))
     ((alive -> _)))))

(ssh-server-start
 host-pk host-sk
 (lambda (ssh)

   (userauth-accept ssh
                    publickey:
                    (lambda (user type pk signed?)
                      (if signed?
                          (equal? (or (userpk user)
                                      ;; register first-time user:
                                      (set! (userpk user) pk))
                                  pk)
                          #t)))
   (tcp-read-timeout #f)
   (port-for-each
    (lambda (ch)
      (thread-start!
       (lambda ()
         (with-channel-ports
          ch (lambda ()
               (if (equal? (channel-command ch) "chat")
                   (handle-chat ssh)
                   (print "unknown command: " (channel-command ch) ", try chat")))))))
    (lambda () (channel-accept ssh)))))
