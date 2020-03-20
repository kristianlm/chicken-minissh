(import minissh
        (chicken port)
        (chicken io)
        (chicken process) (chicken process-context))

(ssh-log? #f)

(define user (get-environment-variable "USER"))
(define cmd  "date")

(print "example to connect to sshd running on 127.0.0.1:22")
(print "will run command: " cmd)
(print "will try user: " user)

(define ssh (ssh-connect "127.0.0.1" 22 (lambda (pk) #t)))

(system "stty -echo")
(display "password: ")
(define password (read-line))
(newline)
(system "stty echo")
(print "please wait ...")
(or (userauth-password ssh user password)
    (error "login failed for " user))

(define ch (channel-exec ssh cmd))
(port-for-each display (lambda () (channel-read ch)))

