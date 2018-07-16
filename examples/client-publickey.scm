(cond-expand
 (chicken-5 (import minissh tweetnacl (chicken port)
                    (chicken process-context)))
 (else (use minissh tweetnacl)))

(ssh-log? #f)

;; the default /dev/random causes hangs
(current-entropy-port (open-input-file "/dev/urandom"))

;; generated with (ssh-keygen 'ed25519)
(define pk "AAAAC3NzaC1lZDI1NTE5AAAAIHqxQfb1habVfT2eC9LfKyXq84k1aU+ylV8qwVPeeyxv")
(define sk
  #${6f3404cc41d9e4b0c98f708f222706ac1c4d5bf9d2dadaad128abbcda763062a
     7ab141f6f585a6d57d3d9e0bd2df2b25eaf38935694fb2955f2ac153de7b2c6f})
(define user (get-environment-variable "USER"))
(define cmd  "date")

(print "example to connect to sshd running on 127.0.0.1:22")
(print "will run command: " cmd)
(print "will try user: " user)
(print "grant access with: echo 'ssh-ed25519 " pk " client-publickey.scm' >> ~/.ssh/authorized_keys")

(define ssh (ssh-connect "127.0.0.1" 22 (lambda (pk)
                                          (print "allowing server " pk)
                                          #t)))

(or (userauth-publickey ssh user pk sk)
    (error "login failed for " user pk))

(define ch (channel-exec ssh cmd))
(port-for-each display (lambda () (channel-read ch)))

