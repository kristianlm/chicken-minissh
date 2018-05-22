(use srfi-18 matchable minissh base64 tweetnacl nrepl)

;; /dev/urandom is cryptographically secure a while after boot
(current-entropy-port (open-input-file "/dev/urandom"))

;; current-input/output/error-port bound to ssh sessions here
(define (handle-exec ssh cmd)
  (cond ((equal? cmd "repl")
         (nrepl-loop)) ;; needs nrepl:0.5

        ((equal? cmd "dump")
         (let loop ()
           (display ".")
           (loop)))
        ((equal? cmd "speed")
         (define bytes 0)
         (define start (current-milliseconds))
         (let loop ()
           (unless (string-null? (read-string 1024))
             (set! bytes (+ bytes 1024))
             (define elapsed (- (current-milliseconds) start))
             (when (> elapsed 1000)
               (print "speed: " (floor (/ bytes (/ elapsed 1000))) " bytes/s")
               (set! bytes 0)
               (set! start (current-milliseconds)))
             (loop))))
        ((equal? cmd "loop")
         (let loop ()
           (print "loop loop loop\r")
           (thread-sleep! 1)
           (loop)))
        (else (print "unknown command `" cmd "`. try one of: repl dump speed loop"))))

(define (handle-client ssh)
  (eval `(set! ssh ',ssh)) ;; for debuggin

  ;; authentication stage
  (run-userauth
   ssh
   publickey:
   (lambda (user type pk signed?) ;; type is always ssh-ed25519 for now
     ;; the base64 part of ~/.ssh/id_ed25519.pub # `ssh-keygen -t ed25519` to make one
     (equal? (base64-decode "AAAAC3NzaC1lZDI1NTE5AAAAIJ5tybkMmIMqQ6uUEE/knJJHECWbQB1By9Oko3OQfv3T")
             pk))
   password:
   (lambda (user pw)
     (and (equal? user "guest") ;; this is a bad idea
          (equal? pw "guest")))
   banner:
   (lambda (user)
     (unparse-userauth-banner ssh (conc "Welcome, " user "\n") "")))

  (assert (ssh-user ssh)) ;; this is a good idea
  (run-channels ssh exec: handle-exec))

(define server-thread
  (thread-start!
   (lambda ()
      ;; keys made with (make-asymmetric-sign-keypair)
     (ssh-server-start
      (base64-decode "M84ih/5V5TFvI3DSuMXiSwa5EqUqC7cYM/J09uIpxLU=")
      (base64-decode (conc "iWtDZXdl/UeN3q7sq2QWN2Ymv3ggveJRBvn1a+rMC5oz"
                           "ziKH/lXlMW8jcNK4xeJLBrkSpSoLtxgz8nT24inEtQ=="))
      (lambda (ssh) (handle-client ssh))))))
