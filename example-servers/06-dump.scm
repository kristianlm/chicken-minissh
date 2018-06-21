(use minissh)

;; the default /dev/random causes hangs
(use tweetnacl) (current-entropy-port (open-input-file "/dev/urandom"))

;; the secret key would normally be kept safe
(define host-sk #${ba72291c15494ee02003b3c0bb0f8507a6a803850aa811d015b141a193e2447d87ddfab6ed4c5da12496e79db431b69d9456b516910b67b13f022fd88ba59059})
(define host-pk #${87ddfab6ed4c5da12496e79db431b69d9456b516910b67b13f022fd88ba59059})

(print "test with: ssh localhost -p 22022 dump # any user, any passsord")

(ssh-server-start
 host-pk host-sk
 (lambda (ssh)
   (userauth-accept ssh password: (lambda (user password) #t) publickey: (lambda _ #t))
   (tcp-read-timeout #f)
   (port-for-each
    (lambda (ch)
      (thread-start!
       (lambda ()
         (define s (make-string (* 32 1024) #\.))
         (let loop ((n 1))
           (ssh-log "step " n)
           (channel-write ch s)
           (loop (+ 1 n))))))
    (lambda () (channel-accept ssh)))))
