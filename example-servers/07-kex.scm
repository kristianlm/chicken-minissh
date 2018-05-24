(use minissh nrepl matchable)

;; the default /dev/random causes hangs
(use tweetnacl) (current-entropy-port (open-input-file "/dev/urandom"))

;; the secret key would normally be kept safe
(define host-sk #${ba72291c15494ee02003b3c0bb0f8507a6a803850aa811d015b141a193e2447d87ddfab6ed4c5da12496e79db431b69d9456b516910b67b13f022fd88ba59059})
(define host-pk #${87ddfab6ed4c5da12496e79db431b69d9456b516910b67b13f022fd88ba59059})

(print "this example server keeps reinitializing the kex
(key exchange) process. it is useful to stress-test this part of
the system. your ssh client should output an infinite
stream of \"kex\" messages (slowly, since transport cipher is
renegotiated every time) and will hopefully never halt.

test with: ssh localhost -p 22022 kex < /dev/null # any user, any passsord")

(ssh-server-start
 host-pk host-sk
 (lambda (ssh)
   (run-userauth ssh password: (lambda (user password) #t))

   (define cid
     (let loop ()
       (match (next-payload ssh)
         (('channel-open type cid . blablabla) cid)
         (else (print "ignoring packet " else) (loop)))))

   (unparse-channel-open-confirmation ssh cid cid 32767 327676)

   (read-payload/expect ssh 'channel-request)
   (unparse-channel-success ssh cid)

   (read-payload/expect ssh 'channel-eof)

   (let loop ((n 0))
     (unparse-channel-data ssh cid (conc "kex " n "\n"))
     (run-kex ssh)
     (loop (+ n 1)))))
