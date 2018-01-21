(use tcp ssh tweetnacl sha2 matchable)

(begin

  (receive (ip op) (tcp-connect "127.0.0.1" 22)

    (set! (tcp-read-timeout) 5000)
    (define ssh (make-ssh #f ip op #f #f))

    (run-protocol-exchange ssh)
    (run-kex ssh)
    ;; transport layer is all set! everything is encrypted from here on
    (write-payload ssh "\x05\x00\x00\x00\fssh-userauth")
    (read-payload/expect ssh 'service-accept)
    ;; TODO: now we have to log somehow

    (close-input-port ip)
    (close-output-port op)))



