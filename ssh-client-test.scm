(use tcp)

(begin



  
  (define (handle-payload payload)
    (with-input-from-string payload
      (lambda ()
        (define payload_type (read-byte))
        (print "payload type: " payload_type)
        (case payload_type
          ((20) (SSH_MSG_KEXINIT))
          (else (print "don't know how to handle payload_type " payload_type))))))

  
  (receive (ip op) (tcp-connect "127.0.0.1" 22022)

    (set! (tcp-read-timeout) 1000)
    (print "protocol version exchange: " (read-line ip))
    (display "SSH-2.0-klm_1.2\r\n" op)
    (print "protocol version exchange replied")

    (set! PACKET1 (read-packet ip))
    (define payload (packet-payload PACKET1))
    ;;(handle-payload payload)

    ;;(print "payload: ")
    ;;(write payload)
    (newline)

    (write-packet (wots (ssh2-packet (wots (kx-payload)) "")) op)
    ;;(display (conc (u2s 1) "\x14") op)
    ;;(write-packet (wots (ssh2-packet "\x01" "")))
    ;;(write-packet (wots (ssh2-packet (wots (kx-payload)) "")) op)
    (print "reading next packet")
    ;; initiate with (bullshit) client public key 
    (write-packet (wots (ssh2-packet "\x1e\x00\x00\x00 _2345678 2345678 2345678 2345678" "")) op)
    (define pak (read-packet ip))
    ;;(print "second pak: " (wots (write pak)))
  
    (close-input-port ip)
    (close-output-port op)))



