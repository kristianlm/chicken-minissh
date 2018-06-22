(use minissh)

;; the default /dev/random causes hangs
(use tweetnacl) (current-entropy-port (open-input-file "/dev/urandom"))

;; the secret key would normally be kept safe
(define host-pk
  "AAAAC3NzaC1lZDI1NTE5AAAAIIfd+rbtTF2hJJbnnbQxtp2UVrUWkQtnsT8CL9iLpZBZ")
(define host-sk
  #${ba72291c15494ee02003b3c0bb0f8507a6a803850aa811d015b141a193e2447d
     87ddfab6ed4c5da12496e79db431b69d9456b516910b67b13f022fd88ba59059})

(print "test with: ssh guest@localhost -p 22022 # and password 1234")

(ssh-server-start
 host-pk host-sk
 (lambda (ssh)
   (userauth-accept
    ssh
    password:
    (lambda (user password)
      (and (equal? user "guest")
           (equal? password "1234")))
    banner:
    (lambda (user granted? pk64)
      (if (equal? user "guest")
          (if granted? "Welcome!\n" "Try with password '1234'\n")
          (if granted? (error "this should never happen")
              (conc "Won't allow user '" user "'\n"
                    "Try guest\n")))))))
