(load "core.scm")

(begin
  (define scalarmult-base #${09000000 00000000    00000000 00000000
                             00000000 00000000    00000000 00000000})
  
  (define serversk (blob->string #${ed523a02c8a8cbd7334944228b842b3d
                                    dc4a9820e95292791ede88acf91cdd70}))
  
  (define serverpk (blob->string (scalarmult (string->blob serversk)
                                             scalarmult-base)))
  ;; tinyssh ed25519.pk (string-length server-sign-pk)
  (define server-sign-pk
    (base64-decode "CH9faUvRATVNkOlbUgKvAQJllDiQmRgcLOxA0yvUygg="))
  (define server-sign-sk
    (base64-decode (conc "D3vomT+w+/2YDvaUR9dtWg0m/0BQosbvX/Z7LZgqtR4I"
                         "f19pS9EBNU2Q6VtSAq8BAmWUOJCZGBws7EDTK9TKCA==")))) 

(define (write-signpk pk)
  (define type "ssh-ed25519")
  ;;(assert (= (string-length pk) 32))
  (write-buflen
   (conc (u2s (string-length type)) type
         (u2s (string-length pk))   pk)))

;; (wots (write-signpk "x123456789 123456789 12345678912"))

;; https://tools.ietf.org/html/rfc5656#section-4
(define (hashcontent hellorecv hellosend
                     kexrecv kexsend
                     server-sign-pk
                     clientpk serverpk
                     sharedsecret)
  (with-output-to-string
    (lambda ()
      (write-buflen hellorecv)
      (write-buflen hellosend)
      (write-buflen kexrecv)
      (write-buflen kexsend)
      (write-signpk server-sign-pk)
      (write-buflen clientpk)
      (write-buflen serverpk)
      (write-buflen sharedsecret))))

(define (curve25519-dh server-sk client-pk)
  (blob->string (scalarmult (string->blob server-sk)
                            (string->blob client-pk))))

(define (handle-client ip op)
  (eval `(begin (set! ip ',ip) (set! op ',op)))

  (define hellosend "SSH-2.0-klmssh_0.1 testing123") ;; TODO: randomize
  (display (conc hellosend "\r\n") op)
  
  (define helloreceive (read-line ip)) ;; TODO: read-line until "SSH-" prefix
  ;;(print "helloreceive: " (wots (write helloreceive)))

  (define kexsend (wots (kx-payload)))
  ;;(print "kexsend: " (wots (write kexsend)))
  (write-payload kexsend op)
  (define kexrecv (read-payload ip))
  ;;(print "kexrecv: " (wots (write kexrecv)))

  (define next-packet (read-payload ip))

  (define clientpk
    (wifs next-packet
          (print "packet type: " (read-byte))
          (read-buflen)))

  (eval `(set! clientpk ,clientpk))
  (print "serverpk " (string->blob serverpk))
  (print "clientpk " (string->blob clientpk))

  (define sharedsecret (curve25519-dh serversk clientpk))
  (eval `(set! K ,sharedsecret))

  (print "shared secret " (string->blob sharedsecret))

  (define hashing
    (hashcontent helloreceive hellosend
                 kexrecv kexsend
                 server-sign-pk
                 clientpk serverpk
                 sharedsecret))  

  (define hash (sha256 hashing))
  (define sid hash) ;; session_id
  
  (print "hash: " (string->blob hash))

  (print "signing " (string->blob hash) " pk " (string->blob server-sign-pk))
  (define signature (substring ((asymmetric-sign (string->blob server-sign-sk)) hash) 0 64))
  (print "signature: " (string->blob signature))


  (write-payload
   (wots (write-byte 31) ;; SSH_MSG_KEXDH_REPLY
         (write-signpk server-sign-pk)
         (write-buflen serverpk)
         (write-signpk signature))
   op)

  (write-payload
   (wots (write-byte 21) ;; SSH_MSG_NEWKEYS
         )
   op)

  (define newkeys (read-payload ip))

  (define (kex-derive-key id)
    (string->blob (kex-derive-keys64 id sharedsecret hash sid)))

  ;;(print "derived key A" (kex-derive-key "A"))
  ;;(print "derived key B" (kex-derive-key "B"))
  (define key-c2s (kex-derive-key "C"))
  (define key-s2c (kex-derive-key "D"))
  ;;(print "derived key E" (kex-derive-key "E"))
  ;;(print "derived key F" (kex-derive-key "F"))


  (define key-c2s-main   (string->blob (substring (blob->string key-c2s) 0 32)))
  (define key-c2s-header (string->blob (substring (blob->string key-c2s) 32 64)))

  (current-payload-reader (make-payload-reader/chacha20 key-c2s-main key-c2s-header))

  (define packet (read-payload ip))
  (print "client requesting service: " (wots (write packet)))
  (unless (equal? "\x05\x00\x00\x00\fssh-userauth" packet)
    (error "something's not right here"))

  (define key-s2c-main   (string->blob (substring (blob->string key-s2c) 0 32)))
  (define key-s2c-header (string->blob (substring (blob->string key-s2c) 32 64)))

  (current-payload-writer (make-payload-writer/chacha20 key-s2c-main key-s2c-header))
  (write-payload "\x06\x00\x00\x00\fssh-userauth" op)
  (print "next: " (wots (write (read-payload ip))))
  )


(quote
 (begin
   (define ss (tcp-listen 2222))
   (thread-start!
    (lambda ()
      (let loop ()
        (receive (ip op) (tcp-accept ss)
          (print "incoming: " ip " " op)
          (thread-start!
           (lambda () (handle-client ip op))))
        (loop))))))

