(use srfi-18 matchable)
(include "core.scm")

(define (handle-client ssh)
  (eval `(set! ssh ',ssh)) ;; for debuggin

  (let ((parsed (next-payload ssh)))
    (unless (equal? `(service-request "ssh-userauth") parsed)
      (error "expecting serviece-request \"ssh-userauth\"" parsed)))

  (write-payload ssh "\x06\x00\x00\x00\fssh-userauth")

  (unless (equal? 'userauth-request (car (next-payload ssh)))
    (error "really expecting userauth-request here" ))
  (write-payload ssh (wots (write-payload-type 'userauth-success)))

  (ssh-setup-channel-handlers! ssh)

  (print "starting channel loop")
  (let loop ()
    (let* ((parsed (next-payload ssh)))
      (match parsed
        (('channel-data cid str)
         (ssh-channel-write (ssh-channel ssh cid) (string-upcase str)))
        (('channel-request cid 'exec reply? "test")
         (ssh-channel-write (ssh-channel ssh cid)
                            "seems to be working.\n"))
        (('channel-request cid 'exec reply? command)
         (ssh-channel-write (ssh-channel ssh cid)
                            (conc "sorry, I don't want to run `" command "`\n")))
        (else (print "unhandled " (wots (write parsed))))))
    (print "RELOOP")
    (loop)))

(define server-thread
  (thread-start!
   (lambda ()
     (ssh-server-start
      (base64-decode
       (conc "iWtDZXdl/UeN3q7sq2QWN2Ymv3ggveJRBvn1a+rMC5oz"
             "ziKH/lXlMW8jcNK4xeJLBrkSpSoLtxgz8nT24inEtQ=="))
      (base64-decode "M84ih/5V5TFvI3DSuMXiSwa5EqUqC7cYM/J09uIpxLU=")
      (lambda (ssh) (handle-client ssh))))))
