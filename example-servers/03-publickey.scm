(use minissh base64)

;; the default /dev/random causes hangs
(use tweetnacl) (current-entropy-port (open-input-file "/dev/urandom"))

;; the secret key would normally be kept safe
(define host-sk #${ba72291c15494ee02003b3c0bb0f8507a6a803850aa811d015b141a193e2447d87ddfab6ed4c5da12496e79db431b69d9456b516910b67b13f022fd88ba59059})
(define host-pk #${87ddfab6ed4c5da12496e79db431b69d9456b516910b67b13f022fd88ba59059})

(define id_ed25519.pub
  (make-pathname (list (get-environment-variable "HOME") ".ssh")
                 "id_ed25519.pub"))

(unless (file-exists? id_ed25519.pub)
  (print "could not find " id_ed25519.pub)
  (print)
  (print "you can generate one with:")
  (print "    ssh-keygen -t ed25519")
  (exit 1))

;; extract the public-key part of openssh's ~/.ssh/id_ed25519.pub
(define user-pk
  (symbol->string
   (with-input-from-file id_ed25519.pub
     (lambda () (read) (read)))))

(print "accepting all users with public key:\n" user-pk)
(print "test with: ssh localhost -p 22022 # no password this time!")
(print "or with:   ssh anyone@localhost -p 22022")

(ssh-server-start
 host-pk host-sk
 (lambda (ssh)
   (userauth-accept
    ssh
    publickey:
    (lambda (user type pk signed?)
      (define pk64 (base64-encode pk))
      (print "your publickey:\n" pk64 " vs expected:\n" user-pk)
      (equal? pk64 user-pk))
    banner:
    (lambda (user)
      (unparse-userauth-banner ssh (conc "Welcome, '" user "'\n") "")))))
