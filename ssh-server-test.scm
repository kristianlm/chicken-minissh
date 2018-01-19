(use srfi-18 matchable)
(include "core.scm")

(define (handle-client ssh)
  (eval `(set! ssh ',ssh)) ;; for debuggin

  ;; authentication stage
  (run-userauth
   ssh
   publickey:
   (lambda (user type pk signed?) ;; type is always ssh-ed25519 for now
     ;; the base64 part of ~/.ssh/id_ed25519.pub # `ssh-keygen -t ed25519` to make one
     (equal? (base64-decode "AAAAC3NzaC1lZDI1NTE5AAAAIIfCLvPNQ7EwQpwvMNNkM4JX7iyKFSrkEW0vrjwWU63I")
             pk))
   password:
   (lambda (user pw)
     (and (equal? user "guest") ;; this is a bad idea
          (equal? pw "guest")))
   banner:
   (lambda (user)
     (write-banner ssh (conc "Welcome, " user "\n"))))

  (ssh-setup-channel-handlers! ssh)

  (assert (ssh-user ssh)) ;; this is a good idea
  (print "starting channel loop")
  (let loop ()
    (let* ((parsed (next-payload ssh)))
      (match parsed
        (('channel-data cid str)
         (ssh-channel-write (ssh-channel ssh cid) (string-upcase str)))
        (('channel-request cid 'exec reply? "test")
         (ssh-channel-write (ssh-channel ssh cid)
                            "seems to be working.\n"))
        (('channel-request cid 'exec reply? command)
         (ssh-channel-write (ssh-channel ssh cid)
                            (conc "sorry, I don't want to run `" command "`\n"
                                  "try `test` instead.\n"))
         (ssh-channel-close (ssh-channel ssh cid)))
        (('channel-request cid 'pty-req reply? term w h _ _ rest)
         (ssh-channel-write (ssh-channel ssh cid)
                            (conc "awww, " term " is my favorite.\r\n"
                                  "unfortunately, I can't find anything to support raw pty-mode\r\n"
                                  "so things get really messy here.\r\n"
                                  "using the arrow keys is fun.\r\n"
                                  "exit ssh with <RET> ~ .\r\n")))
        (else (print "unhandled " (wots (write parsed))))))
    (print "RELOOP")
    (loop)))

(define server-thread
  (thread-start!
   (lambda ()
     (ssh-server-start
      (base64-decode
       (conc "iWtDZXdl/UeN3q7sq2QWN2Ymv3ggveJRBvn1a+rMC5oz"
             "ziKH/lXlMW8jcNK4xeJLBrkSpSoLtxgz8nT24inEtQ=="))
      (base64-decode "M84ih/5V5TFvI3DSuMXiSwa5EqUqC7cYM/J09uIpxLU=")
      (lambda (ssh) (handle-client ssh))))))
