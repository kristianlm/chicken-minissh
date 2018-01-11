(use srfi-18 matchable)
(include "core.scm")

(define (handle-client ssh)
  (eval `(set! ssh ',ssh)) ;; for debuggin

  (let ((parsed (next-payload ssh)))
    (unless (equal? `(service-request "ssh-userauth") parsed)
      (error "expecting serviece-request \"ssh-userauth\"" parsed)))

  (write-payload ssh "\x06\x00\x00\x00\fssh-userauth")

  (read-payload/expect ssh 'userauth-request)
  (write-payload ssh (wots (write-byte (payload-type->int 'userauth-success))))

  (print "starting channel loop")
  (let loop ()
    (let* ((payload (read-payload ssh))
           (parsed (handle-payload ssh payload)))
      (match parsed
        (('channel-data cid str)
         (ssh-channel-write (ssh-channel ssh cid) (string-upcase str)))
        (else #t)))
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
      (lambda (ssh) (handle-client ssh))
      port: 2222))))
