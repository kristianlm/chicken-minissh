(import minissh (chicken io) (chicken string))

;;(ssh-log-payload? #t)
(ssh-log? #f)

;; the secret key would normally be kept safe
(define host-pk
  "AAAAC3NzaC1lZDI1NTE5AAAAIIfd+rbtTF2hJJbnnbQxtp2UVrUWkQtnsT8CL9iLpZBZ")
(define host-sk
  #${ba72291c15494ee02003b3c0bb0f8507a6a803850aa811d015b141a193e2447d
     87ddfab6ed4c5da12496e79db431b69d9456b516910b67b13f022fd88ba59059})

(display
 (conc "one-shot ssh server: accept one client, print its data to stdout, then exit.
run server like this:
  csi -s server-recv.scm | sha1sum
then run client like this:
  dd if=/dev/zero bs=1M count=128 | sha1sum
  ba713b819c1202dcb0d178df9d2b3222ba1bba44  -
  dd if=/dev/zero bs=1M count=128 | pv | ssh localhost -p 22022 send
")
 (current-error-port))

(ssh-server-start
 host-pk host-sk
 ;;      ,-- keep server stdout (otherwise it'd be an echo back to client)
 (let ((op (current-output-port)))
   (lambda (ssh)
     (userauth-accept ssh password: (lambda _ #t) publickey: (lambda _ #t))
     (call/cc
      (lambda (exit)
        (channels-accept
         ssh (lambda ()
               (let ((buff (make-string (* 1024 1024))))
                 (let loop ()
                   (let ((read (read-string! #f buff)))
                     (unless (= 0 read)
                       (display (if (= read (string-length buff)) buff (substring buff 0 read)) op)
                       (loop)))))
               (exit #f)))))))
 ;; OBS! undocumented API! prevent spawn a new thread, and exit after
 ;; handling first session.
 spawn: (lambda (thunk) (thunk) #f))
