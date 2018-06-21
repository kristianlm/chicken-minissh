;; included from minissh.scm
;;
;; there should probably be a minissh-server.scm but I'm not that well
;; organized.

(define (ssh-connect host port verifier #!key (connect tcp-connect))
  (receive (ip op) (connect host port)
    ;;                  server?  ports host-pk signer verifier
    (define ssh (make-ssh #f    ip op   #f     #f     verifier))
    (run-protocol-exchange ssh)
    (kexinit-start ssh)
    ssh))

(define (userauth-password ssh user password)
  (unparse-service-request ssh "ssh-userauth")
  (read-payload/expect ssh 'service-accept)
  (unparse-userauth-request ssh user "ssh-connection" 'password #f password)
  (read-payload/expect ssh 'userauth-success)
  (%ssh-user-set! ssh user))

;; TODO: rename and move in with the other guys
;;                          string blob blob
(define (publickey-sign ssh user   pk   sk)
  (alg-ed25519-add
   (string->blob
    (substring
     ((asymmetric-sign sk)
      (userauth-publickey-signature-blob
       ssh user
       (string->blob
        (wots (ssh-write-string "ssh-ed25519")
              (ssh-write-string (blob->string pk))))))
     0 64))))

(define (userauth-publickey ssh user pk sk)
  (unparse-service-request ssh "ssh-userauth")
  (read-payload/expect ssh 'service-accept)
  (unparse-userauth-request ssh user "ssh-connection"
                            'publickey #t 'ssh-ed25519
                            (string->blob
                             (wots ;; TODO: make pk consistent! ssh-ed25519 prefix in our out!?
                              (ssh-write-string "ssh-ed25519")
                              (ssh-write-blob pk)))
                            (publickey-sign ssh user pk sk))
  (read-payload/expect ssh 'userauth-success)
  (%ssh-user-set! ssh user))


