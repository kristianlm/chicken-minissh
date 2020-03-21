(import minissh nrepl (chicken tcp) (chicken port) srfi-18 chicken.condition)
(include "examples/pty.scm")

;; the secret key would normally be kept safe
(define host-pk
  "AAAAC3NzaC1lZDI1NTE5AAAAIIfd+rbtTF2hJJbnnbQxtp2UVrUWkQtnsT8CL9iLpZBZ")
(define host-sk
  #${ba72291c15494ee02003b3c0bb0f8507a6a803850aa811d015b141a193e2447d
     87ddfab6ed4c5da12496e79db431b69d9456b516910b67b13f022fd88ba59059})

(print "test with: ssh localhost -p 22022 repl # any user, any password")

(define current-channel (make-parameter #f))

;; setting up all three current-ports is not as easy as it sounds,
;; specially in the repl context.
(define (with-safe-ports ip op ep)
  ;; first off: the repl writes the results with a
  ;; print-length-limit. this is terrific, because it means your repl
  ;; session isn't flooded when you enter (make-vector 10000 "haha").
  ;; however, the ports that we're using are printing out things like
  ;; logs inside display callback procedures. these logs count towards
  ;; the final print-length-limit and causes major confusion. hence
  ;; the ##sys#with-print-length-limit.
  (define (print-length-limitless op)
    (make-output-port
     (lambda (str)
       (##sys#with-print-length-limit ;; <-- avoid ##sys#print exits
        #f (lambda () (display str op))))
     (lambda () (close-output-port op))))

  ;; secondly, we'd like the REPL's errors and warning to go to
  ;; (current-error-port), as is default. this can easily cause infine
  ;; loops, however: errors can happen during the display callback
  ;; procedure of current-error-port. this is (hopefully!) avoided
  ;; below.
  (let ((cep (current-error-port))
        (ceh (current-exception-handler)))
    (current-exception-handler (lambda (e) (current-error-port cep) (ceh e))))

  (current-input-port  ip)
  (current-output-port (print-length-limitless op))
  (current-error-port  (print-length-limitless ep)))

(ssh-server-start
 host-pk host-sk
 (lambda (ssh)
   (eval `(set! ssh ',ssh))
   (userauth-accept ssh password: (lambda _ #t) publickey: (lambda _ #t))
   (tcp-read-timeout #f)
   (port-for-each
    (lambda (ch)
      (thread-start!
       (lambda ()
         (current-channel ch)
         (let ((ip (channel-input-port ch))
               (op (channel-output-port ch))
               (ep (channel-error-port ch)))
           (with-safe-ports
            (if (channel-terminal ch) (make-pty-readline-port
                                       ip: ip op: op prefix: "#;> "
                                       keystroke: (lambda (e cmd) (if (eq? 'delete cmd) #!eof #f))) ip)
            (if (channel-terminal ch) (make-pty-output-port   op: op) op)
            (if (channel-terminal ch) (make-pty-output-port   op: ep) ep))

           (print "try ssh, (ssh-user ssh), (ssh-user-pk ssh) or (kexinit-start ssh)")
           (print "or (channel-terminal (current-channel))")
           (when (channel-terminal ch)
             (print "obs: running in PTY-mode, this can get messy"))

           (nrepl-loop)
           (unless (port-closed? (ssh-ip ssh))
             (channel-eof ch)
             (channel-close ch))))))
    (lambda () (channel-accept ssh pty: #t)))))
