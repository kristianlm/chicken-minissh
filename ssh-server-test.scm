(use srfi-18)
(include "core.scm")

(define server-sign-pk
  (base64-decode "M84ih/5V5TFvI3DSuMXiSwa5EqUqC7cYM/J09uIpxLU="))
(define server-sign-sk
  (base64-decode (conc "iWtDZXdl/UeN3q7sq2QWN2Ymv3ggveJRBvn1a+rMC5oz"
                       "ziKH/lXlMW8jcNK4xeJLBrkSpSoLtxgz8nT24inEtQ==")))

(define (write-signpk pk)
  (define type "ssh-ed25519")
  ;;(assert (= (string-length pk) 32))
  (write-buflen
   (conc (u2s (string-length type)) type
         (u2s (string-length pk))   pk)))

(define (handle-client ip op)

  (define ssh (make-ssh ip op))
  (eval `(set! ssh ',ssh))

  (run-protocol-exchange ssh)
  (run-kex ssh)
  
  (define packet (read-payload/expect ssh 'service-request))
  (unless (equal? "\x05\x00\x00\x00\fssh-userauth" packet)
    (error "something's not right here"))

  (write-payload ssh "\x06\x00\x00\x00\fssh-userauth")

  ;; write welcome banner
  (quote
   (write-payload ssh (wots (write-byte (payload-type->int 'userauth-banner))
                            (write-buflen "access granted. welcome. don't do evil, do good.\n")
                            (write-buflen "none"))))


  (read-payload/expect ssh 'userauth-request)
  (write-payload ssh (wots (write-byte (payload-type->int 'userauth-success))))

   ;;; e.g.  "Z\x00\x00\x00\asession\x00\x00\x00\x01\x00 \x00\x00\x00\x00\x80\x00"
  (read-payload/expect ssh 'channel-open)

  ;; TODO: parse this properly
  (define channelid "\x00\x00\x00\x01") ;; OpenSSH on arch linux
  (eval `(set! channelid ',channelid))
  ;; (define channelid "\x00\x00\x00\x00") ;; OpenSSH on mac

  (write-payload ssh
                 (wots
                  (write-byte (payload-type->int 'channel-open-confirmation))
                  (display channelid)          ;; sender cid
                  (display "\x00\x00\x00\x01") ;; my cid
                  (display (u2s #x000010)) ;; window size
                  (display (u2s #x008000)))) ;; max packet size

  (read-payload/expect ssh 'channel-request)

  (write-payload ssh
                 (wots (write-byte (payload-type->int 'channel-success))
                       (display channelid)))

  (write-payload ssh
                 (wots (write-byte (payload-type->int 'channel-data))
                       (display channelid)
                       (write-buflen "CHISSH> ")))

  (write-payload ssh
                 (wots
                  (write-byte (payload-type->int 'channel-request))
                  (display channelid)
                  (write-buflen "exit-status")
                  (display "\x00") ;; «want reply» I think
                  (display "\x00\x00\x00\x06")) ;; exit_status
                 )

  (quote
   (write-payload ssh (wots (write-byte (payload-type->int 'channel-eof))
                            (display channelid))))

  (quote
   (write-payload ssh (wots (write-byte (payload-type->int 'channel-close))
                            (display channelid))))


  (let loop ()
    (read-payload ssh)
    (loop)))

(define (ssh-server-start port)
  (define ss (tcp-listen port))
  (let loop ()
    (receive (ip op) (tcp-accept ss)
      (print "incoming: " ip " " op)
      (thread-start!
       (lambda () (handle-client ip op))))
    (loop)))



