(use tcp base64 tweetnacl sha2 message-digest)
(use chacha)

(define-record-type ssh
  (%make-ssh ip op sid
             hello/read hello/write
             seqnum/read    seqnum/write
             payload-reader payload-writer
             handlers
             channels)
  ssh?
  (ip ssh-ip)
  (op ssh-op)
  (sid ssh-sid %ssh-sid-set!)
  (hello/read ssh-hello/read %ssh-hello/read-set!)
  (hello/write ssh-hello/write %ssh-hello/write-set!)
  (seqnum/read  ssh-seqnum/read  %ssh-seqnum/read-set!)
  (seqnum/write ssh-seqnum/write %ssh-seqnum/write-set!)
  (payload-reader ssh-payload-reader %ssh-payload-reader-set!)
  (payload-writer ssh-payload-writer %ssh-payload-writer-set!)
  (handlers ssh-handlers)
  (channels ssh-channels))


(define (make-ssh ip op)
  (assert (input-port? ip))
  (assert (output-port? op))
  (%make-ssh ip op
             #f #f ;; hello
             #f 0 0
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
  (or (alist-ref payload-type *payload-types*)
      (error "payload-type not found" payload-type)))
;; (payload-type->int 'channel-eof)


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
                               (version "minissh_0.1")
                               (comment "testing1234"))
  (define greeting (conc protocol "-" version " " comment))
  (display (conc greeting "\r\n") (ssh-op ssh))
  (%ssh-hello/write-set! ssh greeting)
  
  (%ssh-hello/read-set! ssh (read-protocol-exchange (ssh-ip ssh))))

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

(define-syntax wifp
  (syntax-rules ()
    ((_ port body ...)
     (with-input-from-port port (lambda () body ...)))))

(define (tostr o)
  (with-output-to-string
    (lambda () (write o))))

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

(define (write-buflen packet #!optional (op (current-output-port)))
  (display (u2s (string-length packet)) op)
  (display packet op))

(define (write-u32 n #!optional (op (current-output-port)))
  (display (u2s n) op))

(define (write-payload-type type #!optional (op (current-output-port)))
  (write-byte (payload-type->int type) op))

;; prefix "bignum" with 00 if first byte is negative (in two's
;; complement). mpints are described in https://tools.ietf.org/html/rfc4251#section-5
(define (string->mpint str)
  (if (>= (char->integer (string-ref str 0)) 128)
      (string-append "\x00" str)
      str))

(define (write-mpint/positive str)
  (write-buflen (string->mpint str)))

(define (write-payload/none ssh payload)
  (write-buflen (wots (payload-pad payload 8 4)) (ssh-op ssh)))

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
  (display "0123456789abcdef") ;; TODO: randomize

  (define (named-list l)
    (define s (string-join (intersperse l ",") ""))
    (display "\x00\x00\x00") ;; TODO proper u32
    (write-byte (string-length s))
    (display s))

  (named-list '("curve25519-sha256@libssh.org")) ;; kex_algorithms
  (named-list '("ssh-ed25519")) ;; server_host_key_algorithms
  (named-list '("chacha20-poly1305@openssh.com")) ;; encryption_algorithms_c->s
  (named-list '("chacha20-poly1305@openssh.com")) ;; encryption_algorithms_s->c
  (named-list '()) ;; mac_algorithms_client_to_server
  (named-list '()) ;; mac_algorithms_server_to_client
  (named-list '("none")) ;; compression_algorithms_client_to_server
  (named-list '("none")) ;; compression_algorithms_server_to_client
  (named-list '()) ;; languages_client_to_server
  (named-list '()) ;; languages_server_to_client
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

(define (read-buflen #!optional (ip (current-input-port)))
  (define packet_length (s2u (read-string/check 4 ip)))
  (read-string/check packet_length ip))

(define (read-u32 #!optional (ip (current-input-port)))
  (s2u (read-string/check 4 ip)))

(define (read-payload-type #!key expect (ip (current-input-port)))
  (let ((result (payload-type (read-string/check 1 ip))))
    (unless (eq? (or expect result) result)
      (error "payload-type mismatch" result expect))
    result))

(define (read-payload/none ssh)
  (packet-payload (read-buflen (ssh-ip ssh))))


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

(define (read-payload ssh)

  (let ((payload ((ssh-payload-reader ssh) ssh)))
    (with-output-to-port (current-error-port)
      (lambda ()
        (print "==== RECV #" (ssh-seqnum/read ssh)
               " " (wots (write (payload-parse payload))) " ;; "
               (wots (write (substring/shared
                             payload
                             0 (min 123 (string-length payload))))))))
    (%ssh-seqnum/read-set! ssh (+ 1 (ssh-seqnum/read ssh)))
    payload))

(define (read-payload/expect ssh expected-payload-type)
  (let ((payload (read-payload ssh)))
    (unless (eq? (payload-type payload) expected-payload-type)
      (error (conc "expected " expected-payload-type  " got")
             (payload-type payload) payload))
    payload))

(define (make-curve25519-keypair)

  (define scalarmult-base #${09000000 00000000    00000000 00000000
                             00000000 00000000    00000000 00000000})

  (let* ((sk (read-string asymmetric-box-secretkeybytes
                          (current-entropy-port)))
         (pk (blob->string (scalarmult (string->blob sk)
                                       scalarmult-base))))
    (values sk pk)))

(define (curve25519-dh server-sk client-pk)
  (blob->string (scalarmult (string->blob server-sk)
                            (string->blob client-pk))))

(define (write-signpk pk)
  (define type "ssh-ed25519")
  ;;(assert (= (string-length pk) 32))
  (write-buflen
   (conc (u2s (string-length type)) type
         (u2s (string-length pk))   pk)))

;; produce hash H according to https://tools.ietf.org/html/rfc4253#section-8
(define (exchange-hash hellorecv hellosend
                     kexrecv kexsend
                     server-sign-pk
                     clientpk serverpk
                     sharedsecret)

  ;; (print "hellorecv: " (string->blob hellorecv))
  ;; (print "hellosend: " (string->blob hellosend))
  ;; (print "kexrecv: " (string->blob kexrecv))
  ;; (print "kexsend: " (string->blob kexsend))
  ;; (print "server-sign-pk: " (string->blob server-sign-pk))
  ;; (print "clientpk: " (string->blob clientpk))
  ;; (print "serverpk: " (string->blob serverpk))
  ;; (print "sharedsecret: " (string->blob sharedsecret))

  (let ((content (wots (write-buflen hellorecv)
                   (write-buflen hellosend)
                   (write-buflen kexrecv)
                   (write-buflen kexsend)
                   (write-signpk server-sign-pk)
                   (write-buflen clientpk)
                   (write-buflen serverpk)
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


;; kex/read is an optional string representing the received KEXINIT
;; payload (reads next packet if not specified).
(define (run-kex ssh server-sign-sk server-sign-pk #!optional kex/read)

  (unless (and (ssh-hello/read ssh)
               (ssh-hello/write ssh))
    (error "run-protocol-exchange not run"))

  (define kex/write (wots (kx-payload)))
  (write-payload ssh kex/write)

  (print "EXPETCING KEX READ")
  (unless kex/read
    (set! kex/read (read-payload/expect ssh 'kexinit)))
  (print "GOT IT")

  (define kexdh-init (read-payload/expect ssh 'kexdh-init))
  (define clientpk (wifs kexdh-init
                         (read-byte) ;; ignore payload type
                         (read-buflen)))

  ;; generate temporary keypair for session
  (define-values (serversk serverpk)
    (make-curve25519-keypair))

  (define sharedsecret (string->mpint (curve25519-dh serversk clientpk)))

  (define hash
    (exchange-hash (ssh-hello/read ssh)
                   (ssh-hello/write ssh)
                   kex/read kex/write
                   server-sign-pk
                   clientpk serverpk
                   sharedsecret))

  ;; first exchange has = session id (unchanged, even after rekeying)
  (unless (ssh-sid ssh)
    (%ssh-sid-set! ssh hash))

  (define signature (substring ((asymmetric-sign (string->blob server-sign-sk)) hash) 0 64))

  (write-payload ssh
                 (wots (write-byte (payload-type->int 'kexdh-reply))
                       (write-signpk server-sign-pk)
                       (write-buflen serverpk)
                       (write-signpk signature)))

  (write-payload ssh
                 (wots (write-byte (payload-type->int 'newkeys))))

  (read-payload/expect ssh 'newkeys)

  (define (kex-derive-key id)
    (string->blob (kex-derive-keys64 id sharedsecret hash (ssh-sid ssh))))

  ;;(print "derived key A" (kex-derive-key "A"))
  ;;(print "derived key B" (kex-derive-key "B"))
  (define key-c2s (kex-derive-key "C"))
  (define key-s2c (kex-derive-key "D"))
  ;;(print "derived key E" (kex-derive-key "E"))
  ;;(print "derived key F" (kex-derive-key "F"))

  (define key-c2s-main   (string->blob (substring (blob->string key-c2s) 0 32)))
  (define key-c2s-header (string->blob (substring (blob->string key-c2s) 32 64)))

  (define key-s2c-main   (string->blob (substring (blob->string key-s2c) 0 32)))
  (define key-s2c-header (string->blob (substring (blob->string key-s2c) 32 64)))

  ;; TODO: add a handler for rekeying here

  (%ssh-payload-reader-set! ssh (make-payload-reader/chacha20 key-c2s-main key-c2s-header))
  (%ssh-payload-writer-set! ssh (make-payload-writer/chacha20 key-s2c-main key-s2c-header)))

(include "parsing.scm")

(define (handle-channel-open ssh type cid ws-remote max)

  (define ws-local #x000010)

  (write-payload ssh
                 (wots
                  (write-byte (payload-type->int 'channel-open-confirmation))
                  (write-u32 cid)            ;; client cid
                  (write-u32 cid)            ;; server cid (same)
                  (display (u2s ws-local))   ;; window size
                  (display (u2s #x008000)))) ;; max packet size

  (set! (ssh-channel ssh cid)
        (make-ssh-channel ssh type cid
                          ws-local
                          ws-remote)))

(define (handle-channel-close ssh cid)
  (hash-table-delete! (ssh-channels ssh) cid))

(define (handle-channel-data ssh cid str #!optional (increment #x8000))

  (define ch (ssh-channel ssh cid))
  (%ssh-channel-bytes/read-set!
   ch (- (ssh-channel-bytes/read ch) (string-length str)))

  (when (<= (ssh-channel-bytes/read ch) 0)
    (%ssh-channel-bytes/read-set!
     ch (+ (ssh-channel-bytes/read ch) increment))
    (write-payload
     ssh
     (wots (write-payload-type 'channel-window-adjust)
           (write-u32 cid)
           (write-u32 increment)))))

(define (handle-channel-eof ssh cid)
  ;; TODO: mark channel as "closed"?
  (void))

(define (handle-channel-request ssh cid type want-reply? . rest)
  (write-payload ssh
                 (wots (write-byte (payload-type->int 'channel-success))
                       (write-u32 cid))))

(define (ssh-channel-write ch str)
  (assert (string? str))
  (define len (string-length str))
  (when (< (ssh-channel-bytes/write ch) len)
    (print "TODO: handle wait for window adjust"))
  (write-payload (ssh-channel-ssh ch)
                 (wots (write-byte (payload-type->int 'channel-data))
                       (write-u32 (ssh-channel-cid ch))
                       (write-buflen str)))
  (%ssh-channel-bytes/write-set!
   ch (- (ssh-channel-bytes/write ch) len)))

(define (ssh-channel-close ch)
  (write-payload (ssh-channel-ssh ch)
                 (wots (write-payload-type 'channel-close)
                       (write-u32 (ssh-channel-cid ch)))))

(define (ssh-setup-channel-handlers! ssh)
  ;; it's probably important to not allow this too early:
  (assert (ssh-hello/write ssh))
  (assert (ssh-hello/read ssh))
  ;; TODO: check for user too
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
         (define ssh (make-ssh ip op))
         (run-protocol-exchange ssh)
         (run-kex ssh
                  server-host-key-secret
                  server-host-key-public)
         (handler ssh))))
    (loop)))

