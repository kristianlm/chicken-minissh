(use tcp srfi-18 srfi-69 srfi-13 ports
     (only tweetnacl asymmetric-box-secretkeybytes current-entropy-port
           asymmetric-sign asymmetric-verify
           symmetric-verify symmetric-sign)
     (only sha2 sha256-primitive)
     (only message-digest message-digest-string)
     (only matchable match)
     (only chacha20 chacha-iv! chacha-encrypt! make-chacha)
     (only data-structures conc intersperse rassoc string-split)
     (only extras read-string read-line read-byte write-byte))

(include "scalarmult.scm") ;; <-- get scalarmult* from tweetnacl?

(define-record-type ssh
  (%make-ssh server?
             ip op
             hostkey-pk hostkey-signer ;; string and procedure
             sid user
             hello/server   hello/client
             seqnum/read    seqnum/write
             payload-reader payload-writer
             handlers
             channels)
  ssh?
  (server?        ssh-server?        %ssh-server-set!)
  (ip             ssh-ip)
  (op             ssh-op)
  (hostkey-pk     ssh-hostkey-pk     %ssh-hostkey-pk-set!)
  (hostkey-signer ssh-hostkey-signer %ssh-hostkey-signer-set!)
  (sid            ssh-sid            %ssh-sid-set!)
  (user           ssh-user           %ssh-user-set!)
  (hello/server   ssh-hello/server   %ssh-hello/server-set!)
  (hello/client   ssh-hello/client   %ssh-hello/client-set!)
  (seqnum/read    ssh-seqnum/read    %ssh-seqnum/read-set!)
  (seqnum/write   ssh-seqnum/write   %ssh-seqnum/write-set!)
  (payload-reader ssh-payload-reader %ssh-payload-reader-set!)
  (payload-writer ssh-payload-writer %ssh-payload-writer-set!)
  (handlers       ssh-handlers)
  (channels       ssh-channels))

(define (make-ssh server? ip op hostkey-pk signer)
  (assert (input-port? ip))
  (assert (output-port? op))
  (when server?
    (assert hostkey-pk)
    (assert signer))
  (%make-ssh server?
             ip op
             hostkey-pk signer
             #f #f ;; sid user
             #f #f ;; hellos
             0 0   ;; sequence numbers
             read-payload/none
             write-payload/none
             (make-hash-table)
             (make-hash-table)))

(define ssh-handler
  (getter-with-setter
   (lambda (ssh pt)     (hash-table-ref  (ssh-handlers ssh) pt (lambda () #f)))
   (lambda (ssh pt val) (hash-table-set! (ssh-handlers ssh) pt val))))

(define ssh-channel
  (getter-with-setter
   (lambda (ssh cid)     (hash-table-ref  (ssh-channels ssh) cid))
   (lambda (ssh cid val) (hash-table-set! (ssh-channels ssh) cid val))))

(define-record-type ssh-channel
  (%make-ssh-channel ssh type
                     cid ;; same id for sender and receiver
                     bytes/read bytes/write) ;; window sizes
  ;; TODO: field for max packet size
  ;; TODO: field for exit-status, exec command?
  ssh-channel?
  (ssh  ssh-channel-ssh)
  (type ssh-channel-type)
  (cid  ssh-channel-cid)
  (bytes/read  ssh-channel-bytes/read  %ssh-channel-bytes/read-set!)
  (bytes/write ssh-channel-bytes/write %ssh-channel-bytes/write-set!))

(define (make-ssh-channel ssh type cid bytes/read bytes/write)
  (assert (ssh? ssh))
  (assert (string? type))
  (assert (integer? cid))
  (assert (integer? bytes/read))
  (assert (integer? bytes/write))
  (%make-ssh-channel ssh type cid bytes/read bytes/write))

(define *payload-types*
  `( ;; from https://tools.ietf.org/html/rfc4253#section-12
    (disconnect                 . 1)
    (ignore                     . 2)
    (unimplemented              . 3)
    (debug                      . 4)
    (service-request            . 5)
    (service-accept             . 6)
    (kexinit                   . 20)
    (newkeys                   . 21)
    ;; don't know where this comes from:
    (kexdh-init                . 30)
    (kexdh-reply               . 31)
    ;; from https://tools.ietf.org/html/rfc4252#section-6
    (userauth-request          . 50)
    (userauth-failure          . 51)
    (userauth-success          . 52)
    (userauth-banner           . 53)
    (userauth-pk-ok            . 60)
    ;; from https://tools.ietf.org/html/rfc4254#section-9
    (global-request            . 80)
    (request-success           . 81)
    (request-failure           . 82)
    (channel-open              . 90)
    (channel-open-confirmation . 91)
    (channel-open-failure      . 92)
    (channel-window-adjust     . 93)
    (channel-data              . 94)
    (channel-extended-data     . 95)
    (channel-eof               . 96)
    (channel-close             . 97)
    (channel-request           . 98)
    (channel-success           . 99)
    (channel-failure          . 100)))

(define (payload-type->int payload-type)
  (cond ((assoc payload-type *payload-types*) => cdr)
        (else (error "payload-type not found" payload-type))))
;; (payload-type->int 'channel-eof)

;; ====================

(define (sha256 str)
  (message-digest-string (sha256-primitive) str 'string))

(define-syntax wots
  (syntax-rules ()
    ((_ body ...)
     (with-output-to-string (lambda () body ...)))))

(define-syntax wifs
  (syntax-rules ()
    ((_ str body ...)
     (with-input-from-string str (lambda () body ...)))))

(define (s2u s)
  (with-input-from-string s
    (lambda ()
      (port-fold (lambda (x s) (+ (* 256 s) x)) 0 read-byte))))

(define (u2s n)
  (let ((s (make-string 4)))
    (string-set! s 0 (integer->char (arithmetic-shift n -24)))
    (string-set! s 1 (integer->char (arithmetic-shift n -16)))
    (string-set! s 2 (integer->char (arithmetic-shift n -8)))
    (string-set! s 3 (integer->char (arithmetic-shift n -0)))
    s))

(define (read-string/check len ip)
  (let ((result (read-string len ip)))
    (unless (= len (string-length result))
      (error (conc "unexpected EOF. wanted " len " bytes, got") result))
    result))

(define (ssh-write-string packet #!optional (op (current-output-port)))
  (display (u2s (string-length packet)) op)
  (display packet op))

(define (ssh-write-symbol packet #!optional (op (current-output-port)))
  (ssh-write-string (symbol->string packet) op))

(define (ssh-write-uint32 n #!optional (op (current-output-port)))
  (display (u2s n) op))

(define (ssh-write-boolean n #!optional (op (current-output-port)))
  (write-byte (if n 1 0)))

(define (ssh-write-msgno type #!optional (op (current-output-port)))
  (write-byte (payload-type->int type) op))

;; see https://tools.ietf.org/html/rfc4251#section-5
(define (ssh-write-list l)
  ;; TODO: check for any #\, in items
  (define s (string-join (intersperse l ",") ""))
  (display "\x00\x00\x00") ;; TODO proper uint32
  (write-byte (string-length s))
  (display s))

;; prefix "bignum" with 00 if first byte is negative (in two's
;; complement). mpints are described in https://tools.ietf.org/html/rfc4251#section-5
(define (string->mpint str)
  (if (>= (char->integer (string-ref str 0)) 128)
      (string-append "\x00" str)
      str))

(define (write-mpint/positive str)
  (ssh-write-string (string->mpint str)))

(define (write-payload/none ssh payload)
  (ssh-write-string (wots (payload-pad payload 8 4)) (ssh-op ssh)))

(define (write-payload ssh payload)
  (with-output-to-port (current-error-port)
    (lambda () (print "==== SENDING #" (ssh-seqnum/write ssh) " <" (payload-type payload) "> "
                 (wots (write payload)))))
  ((ssh-payload-writer ssh) ssh payload)
  (%ssh-seqnum/write-set! ssh (+ 1 (ssh-seqnum/write ssh))))

(define (make-payload-writer/chacha20 key-main key-header)
  
  (define chacha-s-main (make-chacha key-main))
  (define chacha-s-header (make-chacha key-header))

  (define (chacha-encrypt ssh chacha counter str)
    (chacha-iv! chacha
                (string->blob (conc "\x00\x00\x00\x00" (u2s (ssh-seqnum/write ssh))))
                counter)
    (chacha-encrypt! chacha str))
  
  (define (write-payload/chacha20 ssh payload)
  
    (define pak (wots (payload-pad payload 8 0)))
    ;;(print "SENDING: " (wots (write pak)))
 
    (define pak* (chacha-encrypt ssh chacha-s-main #${01000000 00000000} pak))
    (define paklen (u2s (string-length pak)))
    (define paklen* (chacha-encrypt ssh chacha-s-header #${00000000 00000000} paklen))
  
    (define poly (string->blob (chacha-encrypt ssh chacha-s-main #${00000000 00000000} (make-string 32 #\null))))
    (define auth ((symmetric-sign poly) (conc paklen* pak*) tag-only?: #t))
    (assert (= 16 (string-length auth)))

    (let ((op (ssh-op ssh)))
      (display paklen* op)
      (display pak* op)
      (display auth op)))

  write-payload/chacha20)

;; add padding to payload (producing a proper SSH2 packet).
;; for chacha20, the paklen-size is 0 (those 4 bytes are considered part of aadlen instead)
(define (payload-pad payload #!optional (bs 8) (paklen-size 4) mac)
  ;; (packet_length || padding_length || payload || random padding) % bd == 0

  (define padding
    (let* ((padlen* (- bs (modulo (+ paklen-size 1 (string-length payload)) bs)))
           (padlen (if (< padlen* 4) (+ bs padlen*) padlen*)))
      (make-string padlen #\P))) ;; TODO randomize
  
  (write-byte (string-length padding))
  (display payload)
  (display padding)
  (when mac (display mac)))


(define (kx-payload)
  (display "\x14")           ;; SSH_MSG_KEXINIT
  (display (read-string 16 (current-entropy-port)))

  (ssh-write-list '("curve25519-sha256@libssh.org")) ;; kex_algorithms
  (ssh-write-list '("ssh-ed25519")) ;; server_host_key_algorithms
  (ssh-write-list '("chacha20-poly1305@openssh.com")) ;; encryption_algorithms_c->s
  (ssh-write-list '("chacha20-poly1305@openssh.com")) ;; encryption_algorithms_s->c
  (ssh-write-list '()) ;; mac_algorithms_client_to_server
  (ssh-write-list '()) ;; mac_algorithms_server_to_client
  (ssh-write-list '("none")) ;; compression_algorithms_client_to_server
  (ssh-write-list '("none")) ;; compression_algorithms_server_to_client
  (ssh-write-list '()) ;; languages_client_to_server
  (ssh-write-list '()) ;; languages_server_to_client
  (display "\x00") ;; first_kex_packet_follows
  (display "\x00\x00\x00\x00") ;; reserved00
  )

(define (packet-payload packet)
  (define padding_length (s2u (substring packet 0 1)))
  ;;(print "padding is " padding_length " bytes")
  
  (define payload_end (- (string-length packet) padding_length))
  (substring packet 1 payload_end))

(define (payload-type payload)
  (let* ((t (char->integer (string-ref payload 0)))
         (pair (rassoc t *payload-types*)))
    (and pair (car pair))))

;; (payload-type "\x06") (payload-type "\xff")

(define (ssh-read-string #!optional (ip (current-input-port)))
  (define packet_length (s2u (read-string/check 4 ip)))
  (read-string/check packet_length ip))

(define (ssh-read-symbol #!optional (ip (current-input-port)))
  (string->symbol (ssh-read-string ip)))

(define (ssh-read-uint32 #!optional (ip (current-input-port)))
  (s2u (read-string/check 4 ip)))

(define (ssh-read-boolean #!optional (ip (current-input-port)))
  (if (= 0 (read-byte)) #f #t))

(define (ssh-read-signpk #!optional (ip (current-input-port)))
  (define type "ssh-ed25519")
  ;;(assert (= (string-length pk) 32))
  (wifs (ssh-read-string)
        (assert (equal? type (ssh-read-string)))
        (ssh-read-string)))

(define (ssh-read-msgno #!key expect (ip (current-input-port)))
  (let ((result (payload-type (read-string/check 1 ip))))
    (unless (eq? (or expect result) result)
      (error "payload-type mismatch" result expect))
    result))

(define (ssh-read-list)
    (define len (s2u (read-string 4)))
    (string-split (read-string len) ","))

(define (read-payload/none ssh)
  (packet-payload (ssh-read-string (ssh-ip ssh))))


(define (make-payload-reader/chacha20 key-main key-header)
  (define chacha-header (make-chacha key-header))
  (define chacha-main   (make-chacha key-main))

  (define (chacha-decrypt ssh chacha counter ciphertext)
    (chacha-iv! chacha ;; TODO support 8-byte sequence numbers:
                (string->blob (conc "\x00\x00\x00\x00" (u2s (ssh-seqnum/read ssh))))
                counter)
    (chacha-encrypt! chacha ciphertext))
  
  (define (read-payload/chacha20 ssh)

    (define ip (ssh-ip ssh))
    (define paklen* (read-string/check 4 ip))
    (define paklen (s2u (chacha-decrypt ssh chacha-header #${00000000 00000000} paklen*)))
    ;;(print "paklen " paklen)
    (unless (< paklen (* 1024 64)) (error "paklen too big?" paklen))
    (define pak* (read-string/check paklen ip))
    (define mac  (read-string/check 16 ip))
    
    (define poly-key (string->blob (chacha-decrypt ssh chacha-main #${00000000 00000000} (make-string 32 #\null))))
    ;; (print "poly-key " poly-key)
    (unless ((symmetric-verify poly-key) mac (conc paklen* pak*))
      (error "poly1305 signature failed (key,mac,content)"
             poly-key
             (string->blob mac)
             (string->blob (conc paklen* pak*))))
    
    (define pak (chacha-decrypt ssh chacha-main #${01000000 00000000} pak*))
    ;;(print "pak: " (wots (write pak)))

    (packet-payload pak))
  
  read-payload/chacha20)

;; like read-payload, but without kexinit handler
(define (read-payload* ssh)

  (let ((payload ((ssh-payload-reader ssh) ssh)))
    (with-output-to-port (current-error-port)
      (lambda ()
        (print "==== RECV #" (ssh-seqnum/read ssh)
               " " (wots (write (payload-parse payload))) " ;; "
               (wots (write (substring/shared
                             payload
                             0 (min 256 (string-length payload))))))))
    (%ssh-seqnum/read-set! ssh (+ 1 (ssh-seqnum/read ssh)))
    payload))

;; read the next packet from ssh and extract its payload
(define (read-payload ssh)
  (let ((payload (read-payload* ssh)))
    (if (eq? 'kexinit (payload-type payload))
        (begin
          (print "============ RERUNNING KEXINITT ===============")
          (run-kex ssh payload)
          (read-payload ssh))
        payload)))

(define (read-payload/expect ssh expected-payload-type)
  (let ((payload (read-payload ssh)))
    (unless (eq? (payload-type payload) expected-payload-type)
      (error (conc "expected " expected-payload-type  " got")
             (payload-type payload) payload))
    payload))

(define (make-curve25519-keypair)

  (define scalarmult-base #${09000000 00000000    00000000 00000000
                             00000000 00000000    00000000 00000000})

  ;; this drains /dev/random very quickly it seems.
  ;; TODO: find a better way.
  (let* ((sk (read-string asymmetric-box-secretkeybytes
                          (current-entropy-port)))
         (pk (blob->string (scalarmult* (string->blob sk)
                                       scalarmult-base))))
    (values sk pk)))

(define (curve25519-dh server-sk client-pk)
  (blob->string (scalarmult* (string->blob server-sk)
                             (string->blob client-pk))))

(define (ssh-write-signpk pk)
  (define type "ssh-ed25519")
  ;;(assert (= (string-length pk) 32))
  (ssh-write-string
   (conc (u2s (string-length type)) type
         (u2s (string-length pk))   pk)))

(define (ssh-server/client ssh send recv)
  (if (ssh-server? ssh)
      (values send recv)
      (values recv send)))

;; produce hash H according to https://tools.ietf.org/html/rfc4253#section-8
(define (exchange-hash ssh
                       kexrecv kexsend
                       local-pk remote-pk
                       host-pk
                       sharedsecret)

  (define-values (kex/server kex/client)
      (ssh-server/client ssh kexsend kexrecv))

  (define-values (serverpk clientpk)
    (ssh-server/client ssh local-pk remote-pk))

  (let ((content (wots
                  (ssh-write-string (ssh-hello/client ssh))
                  (ssh-write-string (ssh-hello/server ssh))
                  (ssh-write-string kex/client)
                  (ssh-write-string kex/server)
                  (ssh-write-signpk host-pk)
                  (ssh-write-string clientpk)
                  (ssh-write-string serverpk)
                  (write-mpint/positive sharedsecret))))
    ;;(print "hashcontent: " (string->blob content))
    (sha256 content)))

;; derive a 64 byte key from curve25519 shared secret and exchange
;; hash. see https://tools.ietf.org/html/rfc4253#section-7.2
(define (kex-derive-keys64 c K H session-id)
  (assert (>= (string-length K) 32))
  (assert (= (string-length H) 32))
  (assert (= (string-length session-id) 32))
  (assert (= (string-length c) 1)) ;; make sure we're doing one of A B C D E F.
  (assert (memq (string-ref c 0) '(#\A #\B #\C #\D #\E #\F)))
  (define K1 (sha256 (string-append (u2s (string-length K)) K H c session-id)))
  (define K2 (sha256 (string-append (u2s (string-length K)) K H K1)))
  (string-append K1 K2))


;; ==================== parsing

(define (SSH_MSG_KEXINIT)

  (define cookie (read-string 16)) ;; random bytes
  (print "cookie: " (wots (write cookie)))

  (define-syntax pprint
    (syntax-rules ()
      ((_ var)
       (begin
         (print 'var " (" (length var) ")")
         (for-each (lambda (name) (print "  " (wots (write name)))) var)))))

  (define kex_algorithms (ssh-read-list))
  (define server_host_key_algorithms (ssh-read-list))
  (define encryption_algorithms_client_to_server (ssh-read-list))
  (define encryption_algorithms_server_to_client (ssh-read-list))
  (define mac_algorithms_client_to_server (ssh-read-list))
  (define mac_algorithms_server_to_client (ssh-read-list))
  (define compression_algorithms_client_to_server (ssh-read-list))
  (define compression_algorithms_server_to_client (ssh-read-list))
  (define languages_client_to_server (ssh-read-list))
  (define languages_server_to_client (ssh-read-list))

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


;; kex/read is an optional string representing the received KEXINIT
;; payload (reads next packet if not specified).
(define (run-kex ssh #!optional kex/read)

  (unless (and (ssh-hello/server ssh)
               (ssh-hello/client ssh))
    (error "run-protocol-exchange not run"))

  (define kex/write (wots (kx-payload)))
  (write-payload ssh kex/write)

  (unless kex/read
    (set! kex/read (read-payload* ssh))
    (unless (eq? 'kexinit (payload-type kex/read))
      (error "kex fault: expected kexinit, got " (wots (write (payload-parse kex/read))))))

  (define (xhash! remote-pk local-pk sharedsecret host-pk)
    (define hash
      (exchange-hash ssh
                     kex/read kex/write
                     local-pk remote-pk
                     host-pk
                     sharedsecret))

    ;; first exchange has = session id (unchanged, even after rekeying)
    (unless (ssh-sid ssh)
      (%ssh-sid-set! ssh hash))

    hash)

  (define (init-server)
    (define kexdh-init (read-payload/expect ssh 'kexdh-init))
    (define client-pk (wifs kexdh-init
                            (read-byte) ;; ignore payload type
                            (ssh-read-string)))

    (define-values (server-sk server-pk) (make-curve25519-keypair))
    (define sharedsecret (string->mpint (curve25519-dh server-sk client-pk)))
    (define hash (xhash! client-pk server-pk sharedsecret (ssh-hostkey-pk ssh)))
    (define signature (substring ((ssh-hostkey-signer ssh) hash) 0 64))

    (write-payload ssh
                   (wots (ssh-write-msgno 'kexdh-reply)
                         (ssh-write-signpk (ssh-hostkey-pk ssh))
                         (ssh-write-string server-pk)
                         (ssh-write-signpk signature)))

    (values sharedsecret hash))

  (define (init-client)
    (print "RUNNING CLIENT KEX")
    (define-values (client-sk client-pk)
      (make-curve25519-keypair))

    (write-payload ssh
                   (wots (ssh-write-msgno 'kexdh-init)
                         (ssh-write-string client-pk)))

    (define kexdh-reply (payload-parse (read-payload/expect ssh 'kexdh-reply)))
    (match kexdh-reply
      (('kexdh-reply host-pk server-pk signature)
       (define sharedsecret (string->mpint (curve25519-dh client-sk server-pk)))
       (define hash (xhash! server-pk client-pk sharedsecret host-pk))
       ;; TODO: verify signature against server-host-key
       (%ssh-hostkey-pk-set! ssh host-pk)
       (values sharedsecret hash))))

  (define-values (sharedsecret hash)
    (if (ssh-server? ssh)
        (init-server)
        (init-client)))

  (write-payload ssh (wots (ssh-write-msgno 'newkeys)))
  (read-payload/expect ssh 'newkeys)

  (define (kex-derive-key id)
    (kex-derive-keys64 id sharedsecret hash (ssh-sid ssh)))

  ;; see https://tools.ietf.org/html/rfc4253#section-7.2
  (define-values (key-s2c key-c2s)
    (ssh-server/client ssh
                       (kex-derive-key "D")
                       (kex-derive-key "C")))

  (define key-c2s-main   (string->blob (substring key-c2s 0 32)))
  (define key-c2s-header (string->blob (substring key-c2s 32 64)))

  (define key-s2c-main   (string->blob (substring key-s2c 0 32)))
  (define key-s2c-header (string->blob (substring key-s2c 32 64)))

  (%ssh-payload-reader-set! ssh (make-payload-reader/chacha20 key-c2s-main key-c2s-header))
  (%ssh-payload-writer-set! ssh (make-payload-writer/chacha20 key-s2c-main key-s2c-header)))

(include "parsing.scm")

(define (handle-channel-open ssh type cid ws-remote max)

  (define ws-local #x000010)

  (write-payload ssh
                 (wots
                  (ssh-write-msgno 'channel-open-confirmation)
                  (ssh-write-uint32 cid)        ;; client cid
                  (ssh-write-uint32 cid)        ;; server cid (same)
                  (ssh-write-uint32 ws-local)   ;; window size
                  (ssh-write-uint32 #x800000))) ;; max packet size

  (set! (ssh-channel ssh cid)
        (make-ssh-channel ssh type cid
                          ws-local
                          ws-remote)))

(define (handle-channel-close ssh cid)
  (hash-table-delete! (ssh-channels ssh) cid))

(define (handle-channel-data ssh cid str #!optional (increment #x10000000))

  (define ch (ssh-channel ssh cid))
  (%ssh-channel-bytes/read-set!
   ch (- (ssh-channel-bytes/read ch) (string-length str)))

  (when (<= (ssh-channel-bytes/read ch) 0)
    (%ssh-channel-bytes/read-set!
     ch (+ (ssh-channel-bytes/read ch) increment))
    (write-payload
     ssh
     (wots (ssh-write-msgno 'channel-window-adjust)
           (ssh-write-uint32 cid)
           (ssh-write-uint32 increment)))))

(define (handle-channel-eof ssh cid)
  ;; TODO: mark channel as "closed"?
  (void))

(define (handle-channel-request ssh cid type want-reply? . rest)
  (write-payload ssh
                 (wots (ssh-write-msgno 'channel-success)
                       (ssh-write-uint32 cid))))

(define (ssh-channel-write ch str)
  (assert (string? str))
  (define len (string-length str))
  (when (< (ssh-channel-bytes/write ch) len)
    (print "TODO: handle wait for window adjust"))
  (write-payload (ssh-channel-ssh ch)
                 (wots (ssh-write-msgno 'channel-data)
                       (ssh-write-uint32 (ssh-channel-cid ch))
                       (ssh-write-string str)))
  (%ssh-channel-bytes/write-set!
   ch (- (ssh-channel-bytes/write ch) len)))

(define (ssh-channel-close ch)
  (write-payload (ssh-channel-ssh ch)
                 (wots (ssh-write-msgno 'channel-close)
                       (ssh-write-uint32 (ssh-channel-cid ch)))))

(define (ssh-setup-channel-handlers! ssh)
  ;; it's probably important to not allow this too early:
  (assert (ssh-hello/server ssh))
  (assert (ssh-hello/client ssh))
  (assert (ssh-user ssh))
  (set! (ssh-handler ssh 'channel-open)     handle-channel-open)
  (set! (ssh-handler ssh 'channel-request)  handle-channel-request)
  (set! (ssh-handler ssh 'channel-data)     handle-channel-data)
  (set! (ssh-handler ssh 'channel-eof)      handle-channel-eof)
  (set! (ssh-handler ssh 'channel-close)    handle-channel-close))

(define (payload-parse payload)
  (cond ((assoc (payload-type payload) *payload-parsers*) =>
         (lambda (pair) ((cdr pair) payload)))
        (else (list (payload-type payload) 'unparsed payload))))

(define (handle-parsed-payload ssh parsed)
  (cond ((ssh-handler ssh (car parsed)) =>
           (lambda (handler)
             (apply handler (cons ssh (cdr parsed)))
             parsed))
          (else parsed)))

;; TODO: find a good (but shorter) name for parsed-payload
(define (next-payload ssh)
  (let* ((parsed (payload-parse (read-payload ssh))))
    (handle-parsed-payload ssh parsed)
    parsed))

(define (ssh-server-start server-host-key-secret
                          server-host-key-public
                          handler
                          #!key (port 22022))
  (define ss (tcp-listen port))
  (let loop ()
    (receive (ip op) (tcp-accept ss)
      (print "incoming: " ip " " op)
      (thread-start!
       (lambda ()
         (define ssh
           (make-ssh #t
                     ip op
                     server-host-key-public
                     (asymmetric-sign (string->blob server-host-key-secret))))
         (run-protocol-exchange ssh)
         (run-kex ssh)
         (handler ssh))))
    (loop)))


;; ==================== protocol exchange ====================

;; from https://tools.ietf.org/html/rfc4253#section-4.2
;; The server MAY send other lines of data before sending the version
;; string.  Each line SHOULD be terminated by a Carriage Return and
;; Line Feed.  Such lines MUST NOT begin with "SSH-", and SHOULD be
;; encoded in ISO-10646 UTF-8 [RFC3629] (language is not specified).
(define (read-protocol-exchange ip)
  (let loop ((line (read-line ip)))
    (if (string-prefix? "SSH-" line)
        line
        (loop (read-line ip)))))

;; TODO: randomize greeting
(define (run-protocol-exchange ssh #!optional
                               (protocol "SSH-2.0")
                               (version "chicken-ssh_0.1")
                               (comment (wots (display (string->blob (read-string 6 (current-entropy-port)))))))

  (define %ssh-hello/write-set!
    (if (ssh-server? ssh)
        %ssh-hello/server-set!
        %ssh-hello/client-set!))
  (define %ssh-hello/read-set!
    (if (ssh-server? ssh)
        %ssh-hello/client-set!
        %ssh-hello/server-set!))

  (define greeting (conc protocol "-" version " " comment))
  (display (conc greeting "\r\n") (ssh-op ssh))
  (%ssh-hello/write-set! ssh greeting)

  (%ssh-hello/read-set! ssh (read-protocol-exchange (ssh-ip ssh))))


(define (unparse-userauth-banner msg #!optional (language ""))
  (wots (ssh-write-msgno 'userauth-banner)
        (ssh-write-string msg)
        (ssh-write-string language)))

(define (ssh-write-banner ssh msg #!optional (language ""))
  (when (ssh-user ssh)
    (error "cannot write banner message after authentication is complete"))
  (write-payload ssh (unparse-userauth-banner msg language)))

;; ==================== userauth ====================

(define (pk->pkblob pk)
  (wifs pk
        (assert (equal? "ssh-ed25519" (ssh-read-string)))
        (ssh-read-string)))

(define (sign->signblob sign)
  (wifs sign
        (assert (equal? "ssh-ed25519" (ssh-read-string)))
        (ssh-read-string)))

(define (userauth-publickey-signature-blob ssh user pk)
  (wots
   (ssh-write-string (ssh-sid ssh)) ;; session identifier
   (ssh-write-msgno 'userauth-request)
   (ssh-write-string user)
   (ssh-write-string "ssh-connection") ;; service name
   (ssh-write-string "publickey")
   (ssh-write-boolean #t)
   (ssh-write-string "ssh-ed25519")
   (ssh-write-string pk)))

(define (userauth-publickey-verify ssh user pk signature)
  (define signbuff (userauth-publickey-signature-blob ssh user pk))
  ((asymmetric-verify (string->blob (pk->pkblob pk)))
   (conc (sign->signblob signature) signbuff)))

;; publickey must return true if a (user pk) login would be ok (can be called multiple times)
;; password must return true if (user password) loging would be ok
;; banner gets called after successful authenticaion, but before sending 'userauth-success
(define (run-userauth ssh #!key publickey password banner)

  (define (fail! #!optional partial?)
    (define auths
      (append (if publickey '("publickey") '())
              (if password  '("password")  '())))
    (write-payload ssh (wots (ssh-write-msgno 'userauth-failure)
                             (ssh-write-list auths)
                             (ssh-write-boolean partial?))))
  (let loop ()

    (match (next-payload ssh)

      (('service-request "ssh-userauth")
       (write-payload ssh (wots (ssh-write-msgno 'service-accept)
                                (ssh-write-string "ssh-userauth")))
       (loop))

      ;; client asks if pk would be ok (since the actual signing is expensive)
      (('userauth-request user "ssh-connection" 'publickey #f 'ssh-ed25519 pk)
       (cond ((and publickey (publickey user 'ssh-ed25519 pk #f))
              ;; tell client pk will be accepted if upcoming signature verifies
              (write-payload ssh (wots (ssh-write-msgno 'userauth-pk-ok)
                                       (ssh-write-string "ssh-ed25519")
                                       (ssh-write-string pk)))
              (loop))
             (else
              (fail!)
              (loop))))
      ;; login with pk and signature
      (('userauth-request user "ssh-connection" 'publickey #t 'ssh-ed25519 pk sign)
       (cond ((and publickey
                   (userauth-publickey-verify ssh user pk sign)
                   (publickey user 'ssh-ed25519 pk #t))
              (if banner (banner user))
              (%ssh-user-set! ssh user)
              (write-payload ssh (wots (ssh-write-msgno 'userauth-success))))
             ;; success, no loop ^
             (else
              (write-payload ssh
                             (unparse-userauth-banner
                              (conc "signature verification failed. this is most likely a bug in this egg.\n")))
              (fail!)
              (loop))))
      ;; password login
      (('userauth-request user "ssh-connection" 'password #f plaintext-password)
       (cond ((and password (password user plaintext-password))
              (if banner (banner user))
              (%ssh-user-set! ssh user)
              (write-payload ssh (wots (ssh-write-msgno 'userauth-success))))
             ;; success, no loop ^
             (else
              (fail!)
              (loop))))
      ;; invalid log                             ,-- eg. 'none
      (('userauth-request user "ssh-connection" type . whatever)
       (fail!)
       (loop))

      (otherwise
       (write-payload ssh
                      (unparse-userauth-banner
                       (conc "unexpected packet " (wots (write otherwise)))))
       (fail!)
       (loop)))))
