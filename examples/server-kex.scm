(cond-expand
 (chicken-5 (import minissh nrepl matchable tweetnacl
                    (chicken tcp) (chicken port)))
 (else (use minissh nrepl matchable tweetnacl)))

;; the default /dev/random causes hangs
(current-entropy-port (open-input-file "/dev/urandom"))

;; the secret key would normally be kept safe
(define host-pk
  "AAAAC3NzaC1lZDI1NTE5AAAAIIfd+rbtTF2hJJbnnbQxtp2UVrUWkQtnsT8CL9iLpZBZ")
(define host-sk
  #${ba72291c15494ee02003b3c0bb0f8507a6a803850aa811d015b141a193e2447d
     87ddfab6ed4c5da12496e79db431b69d9456b516910b67b13f022fd88ba59059})

(print "this example server keeps reinitializing the kex
(key exchange) process. it is useful to stress-test this part of
the system. your ssh client should output an infinite
stream of \"kex\" messages (slowly, since transport cipher is
renegotiated every time) and will hopefully never halt.

test with: ssh localhost -p 22022 kex # any user, any passsord")

(ssh-server-start
 host-pk host-sk
 (lambda (ssh)
   (userauth-accept ssh password: (lambda _ #t) publickey: (lambda _ #t))
   (tcp-read-timeout #f)
   (port-for-each
     (lambda (ch)
       (with-channel-ports
        ch (lambda ()
             (let loop ((n 0))
               (print "kex " n)
               (ssh-log "calling kexinit-start")
               (kexinit-start ssh)
               (loop (+ n 1))))))
     (lambda () (channel-accept ssh)))))
