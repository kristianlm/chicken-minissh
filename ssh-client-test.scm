(use tcp)

(begin

  (define (SSH_MSG_KEXINIT op)
    
    (define cookie (read-string 16)) ;; random bytes
    (print "cookie: " (tostr cookie))

    (define (read-name-list)
      (define len (s2u (read-string 4)))
      (string-split (read-string len) ","))

    (define-syntax pprint
      (syntax-rules ()
        ((_ var)
         (begin
           (print 'var " (" (length var) ")")
           (for-each (lambda (name) (print "  " (tostr name))) var)))))
    
    (define kex_algorithms (read-name-list))
    (define server_host_key_algorithms (read-name-list))
    (define encryption_algorithms_client_to_server (read-name-list))
    (define encryption_algorithms_server_to_client (read-name-list))
    (define mac_algorithms_client_to_server (read-name-list))
    (define mac_algorithms_server_to_client (read-name-list))
    (define compression_algorithms_client_to_server (read-name-list))
    (define compression_algorithms_server_to_client (read-name-list))
    (define languages_client_to_server (read-name-list))
    (define languages_server_to_client (read-name-list))

    (define first_kex_packet_follows (read-byte))
    (define reserved00 (s2u (read-string 4)))
    (assert (= 0 reserved00))

    (pprint kex_algorithms)
    (pprint server_host_key_algorithms)
    (pprint encryption_algorithms_client_to_server)
    (pprint encryption_algorithms_server_to_client)
    (pprint mac_algorithms_client_to_server)
    (pprint mac_algorithms_server_to_client)
    (pprint compression_algorithms_client_to_server)
    (pprint compression_algorithms_server_to_client)
    (pprint languages_client_to_server)
    (pprint languages_server_to_client)
    (print "first_kex_packet_follows: " first_kex_packet_follows)

    )

  
  (define (handle-payload payload)
    (with-input-from-string payload
      (lambda ()
        (define payload_type (read-byte))
        (print "payload type: " payload_type)
        (case payload_type
          ((20) (SSH_MSG_KEXINIT #f))
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



