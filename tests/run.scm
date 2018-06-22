(use test minissh base64 matchable)

(ssh-log? #f)

(test
 "channel-data: simple parse -> unparse"
 `(channel-data 1 "hei")
 (parse-channel-data (unparse-channel-data #f 1 "hei")))

(test
 "channel-data: unparse"
 "\x5E\x00\x00\x00\x01\x00\x00\x00\x03hei"
 (unparse-channel-data #f 1 "hei"))

(test
 "userauth-request: unparse"
 "2\x00\x00\x00\busername\x00\x00\x00\asession\x00\x00\x00\tpublickey\x01\x00\x00\x00\x0essh***-ed25519\x00\x00\x00\x01\x00\x00\x00\x00\x01\x44"
 (unparse-userauth-request
  #f "username" "session" 'publickey
  #t 'ssh***-ed25519 "AA==" #${44}))

(test
 "channel-open: parse"
 `(channel-open "session" 1 2 3)
 (parse-channel-open "Z\x00\x00\x00\asession\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00\x00\x03"))

(test
 "channel-request: parse"
 `(channel-request 1 exec #t "test")
 (parse-channel-request "b\x00\x00\x00\x01\x00\x00\x00\x04exec\x01\x00\x00\x00\x04test"))

(test
 "userauth-request: parse->unparse"
 `(userauth-request "tst" "ssh-connection" none)
      (parse-userauth-request "2\x00\x00\x00\x03tst\x00\x00\x00\x0essh-connection\x00\x00\x00\x04none"))

(test
 "userauth-request: parse publickey (no signature)"
 `(userauth-request "tst" "ssh-connection" publickey #f ssh-ed25519
                    "AAAAC3NzaC1lZDI1NTE5AAAAIIfCLvPNQ7EwQpwvMNNkM4JX7iyKFSrkEW0vrjwWU63I")
 (parse-userauth-request
  "2\x00\x00\x00\x03tst\x00\x00\x00\x0essh-connection\x00\x00\x00\tpublickey\x00\x00\x00\x00\vssh-ed25519\x00\x00\x003\x00\x00\x00\vssh-ed25519\x00\x00\x00 \207\302.\363\315C\2610B\234/0\323d3\202W\356,\212\x15*\344\x11m/\256<\x16S\255\310"))

(test
 "userauth-request: parse publickey (with signature)"
 `(userauth-request "heisann" "ssh-connection" publickey #t ssh-ed25519
                    "AAAAC3NzaC1lZDI1NTE5AAAAIIfCLvPNQ7EwQpwvMNNkM4JX7iyKFSrkEW0vrjwWU63I"
                    #${0000000b7373682d6564323535313900000040c03980691aa4b93f4afae6224e428fa2b5ac9aaff052fc421aee64989e19a6397e590ecd65ebd1effe7cec0fecd971eb4b7ad7203634b56da598f33d3feac400})

 (parse-userauth-request
  (blob->string #${320000000768656973616e6e0000000e7373682d636f6e6e656374696f6e0000
                   00097075626c69636b6579010000000b7373682d656432353531390000003300
                   00000b7373682d656432353531390000002087c22ef3cd43b130429c2f30d364
                   338257ee2c8a152ae4116d2fae3c1653adc8000000530000000b7373682d6564
                   323535313900000040c03980691aa4b93f4afae6224e428fa2b5ac9aaff052fc
                   421aee64989e19a6397e590ecd65ebd1effe7cec0fecd971eb4b7ad7203634b5
                   6da598f33d3feac400})))

(test
 "userauth-request: parse password"
 `(userauth-request "tst" "ssh-connection" password #f "3777")
 (parse-userauth-request "2\x00\x00\x00\x03tst\x00\x00\x00\x0essh-connection\x00\x00\x00\bpassword\x00\x00\x00\x00\x043777"))

(test-group
 "string->mpint"
 (test "no leading zeros not negative" "\x01AB" (string->mpint "\x01AB"))
 (test "no leading zeros negative" "\x00\x80AB" (string->mpint "\x80AB"))
 (test "leading zeros not negative" "\x01AB" (string->mpint "\x00\x00\x01AB"))
 (test "leading zeros negative" "\x00\x80AB" (string->mpint "\x00\x00\x00\x80AB"))
 (test "1 leading zero negative" "\x00\x80AB" (string->mpint "\x00\x80AB")))

;; custom pretend ssh session
(define (incoming packets writer)
  (%make-ssh #t 'ip 'op 'host-pk64 'signer 'verifier 'sid "user"
             #f ;; ssh-user-pk
             "hello server" "hello client" 0 0 ;; seqnums
             (let ((packets packets)) ;; <-- reader
               (lambda (a)
                 (thread-sleep! 0.1)
                 (if packets
                     (let ((t (car packets)))
                       (cond ((pair? (cdr packets))
                              (set! (car packets) (cadr packets))
                              (set! (cdr packets) (cddr packets)))
                             (else (set! packets #f)))
                       (t))
                     #!eof)))
             writer
             (make-queue)
             (make-mutex) (make-mutex) ;; read write
             (make-condition-variable) ;; ssh-read-cv
             #f             ;; kex/sent
             #f             ;; specific
             (make-hash-table) (make-mutex))) ;; ssh-channels ssh-channels-mutex

(let* ((wait (lambda () (thread-yield!)))
       (bytes 0)
       (here 0)
       (reader-test-done #f)
       (cid #f)
       (adjust (lambda (bytes) (unparse-channel-window-adjust #f cid bytes)))
       (ssh
        (incoming
         (list (lambda () (unparse-channel-open #f "session" 444 4 1000))
               (lambda () (unparse-channel-request #f cid 'exec #t "my command"))
               (lambda () (wait) (test 1 here)(test 4 bytes) (adjust 1))
               (lambda () (wait) (test 5 bytes) (adjust 1))
               (lambda () (wait) (test 6 bytes) (adjust 1))
               (lambda () (wait) (test 2 here) (test 7 bytes) (adjust 128))
               (lambda () (wait) (test 3 here) (test 9 bytes)
                       (set! reader-test-done #t)
                       (unparse-disconnect #f 0 "test over" "")))
         ;; discard written packets, but count bytes through cid 1:
         (lambda (ssh x)
           (match (payload-parse x)
             (('channel-open-confirmation rcid lcid ws max-ps)
              (set! cid lcid))
             (('channel-data 444 str)
              (set! bytes (+ bytes (string-length str))))
             (('channel-data cid str)
              (error "unexpected cid" cid))
             (else))))))
  (print "============================================================")

  (let ((ch (channel-accept ssh)))
    (test "my command" (channel-command ch))
    (thread-start!
     (lambda ()
       (ssh-log "STARTING")
       (channel-write ch "abc") (set! here 1)
       (channel-write ch "def") (set! here 2)
       (channel-write ch "ghi") (set! here 3))))

  ;; loop throuhg all incoming data etc
  (port-for-each values (lambda () (channel-accept ssh)))

  (test #t reader-test-done))

;; ============================================================
;; server <-> client test

;; the default /dev/random causes hangs
(use tweetnacl) (current-entropy-port (open-input-file "/dev/urandom"))


;; the secret key would normally be kept safe

(define server-pk
  "AAAAC3NzaC1lZDI1NTE5AAAAIMBYnuh7LwwbNZMSLsVhF89lOwXUxr13cAY+SCrVCSbz")
(define server-sk
  #${4ce01388de1c552570c969a1da8ce3916cdb85bd0b82993ddb780a7d2d46044f
     c0589ee87b2f0c1b3593122ec56117cf653b05d4c6bd7770063e482ad50926f3})

(define client-pk
  "AAAAC3NzaC1lZDI1NTE5AAAAIEPRg0+7VfsR2lmAZ8GVgFA3rbT7NulEfTotVuPS66t+")
(define client-sk
  #${6d46a4737e343ab8bde34f3050daed1fe3a7c7dbb79962a9190e1f6c90779a9f
     43d1834fbb55fb11da598067c195805037adb4fb36e9447d3a2d56e3d2ebab7e})

(print "test with: ssh localhost -p 22022 repl # any user, any password")

(define port 22021)
;; ==================== server ====================
(thread-start!
 (lambda ()
   (ssh-server-start
    server-pk server-sk
    (lambda (ssh)
      (userauth-accept ssh publickey: (lambda (user type pk signed?)
                                        (equal? client-pk pk)))
      (tcp-read-timeout #f)
      (port-for-each
       (lambda (ch)
         (thread-start!
          (lambda ()
            (channel-write ch "hello world\n")
            (channel-eof ch)
            (channel-close ch))))
       (lambda () (channel-accept ssh))))
    port: port)))

;; ==================== client ====================

(thread-sleep! 0.1) ;; give server some time to initialize
(define ssh (ssh-connect "127.0.0.1" port (lambda (pk) (equal? pk server-pk))))
(userauth-publickey ssh "minissh" client-pk client-sk)

(define ch (channel-exec ssh "my command"))
(test "channel cmd loopback"  "my command" (channel-command ch))
(test "channel read" "hello world\n" (channel-read ch))



(test-exit)
