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
  (match (next-payload ssh)
    (('userauth-success) (%ssh-user-set! ssh user) #t)
    (('userauth-failure list partial?) #f)
    (else (error "unexpected packet" else))))

;; TODO: rename and move in with the other guys
;;                          string string blob
(define (publickey-sign ssh user   pk64   sk)
  (alg-ed25519-add
   (string->blob
    (substring
     ((asymmetric-sign sk)
      (userauth-publickey-signature-blob ssh user pk64))
     0 64))))

(define (userauth-publickey ssh user pk64 sk)
  (unparse-service-request ssh "ssh-userauth")
  (read-payload/expect ssh 'service-accept)
  (unparse-userauth-request ssh user "ssh-connection"
                            'publickey #t 'ssh-ed25519
                            pk64
                            (publickey-sign ssh user pk64 sk))
  (match (next-payload ssh)
    (('userauth-success) (%ssh-user-set! ssh user) #t)
    (('userauth-failure list partial?) #f)
    (else (error "unexpected packet" else))))


