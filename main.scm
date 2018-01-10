(include "ssh-server-test.scm")

(ssh-server-start 2222)
;; (thread-start! (lambda () (ssh-server-start 2222)))
