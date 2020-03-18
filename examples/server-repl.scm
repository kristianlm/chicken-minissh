(import minissh nrepl tweetnacl (chicken tcp) (chicken port) srfi-18)

;; the secret key would normally be kept safe
(define host-pk
  "AAAAC3NzaC1lZDI1NTE5AAAAIIfd+rbtTF2hJJbnnbQxtp2UVrUWkQtnsT8CL9iLpZBZ")
(define host-sk
  #${ba72291c15494ee02003b3c0bb0f8507a6a803850aa811d015b141a193e2447d
     87ddfab6ed4c5da12496e79db431b69d9456b516910b67b13f022fd88ba59059})

(print "test with: ssh localhost -p 22022 repl # any user, any password")

(ssh-server-start
 host-pk host-sk
 (lambda (ssh)
   (eval `(set! ssh ',ssh))
   (userauth-accept ssh password: (lambda _ #t) publickey: (lambda _ #t))
   (channels-accept ssh (lambda ()
                          (print "try ssh, (ssh-user ssh), (ssh-user-pk ssh)"
                                 " or (kexinit-start ssh)")
                          (nrepl-loop)))))
