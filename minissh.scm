(use tcp srfi-18 srfi-69 srfi-13 ports
     (only tweetnacl asymmetric-box-secretkeybytes current-entropy-port
           asymmetric-sign asymmetric-verify
           symmetric-verify symmetric-sign scalarmult*)
     (only sha2 sha256-primitive)
     (only message-digest message-digest-string)
     (only matchable match)
     (only data-structures conc intersperse rassoc string-split
           make-queue queue-add! queue-remove! queue-empty?)
     (only extras read-string read-line read-byte write-byte))

(define-syntax wots
  (syntax-rules ()
    ((_ body ...)
     (with-output-to-string (lambda () body ...)))))

(define-syntax wifs
  (syntax-rules ()
    ((_ str body ...)
     (with-input-from-string str (lambda () body ...)))))

;; grab hold of current-error-port now so we don't log into channels
;; (and send it across the ssh session).
(define ssh-log
  (let ((cep (current-error-port)))
   (lambda args
     (with-output-to-port cep
       (lambda () (apply print (cons (thread-name (current-thread))
                                (cons " " args))))))))

;; overrride with shorter version
(define (ssh-log-recv ssh payload)
  (ssh-log "ssh recv #" (ssh-seqnum/read ssh) ": " (payload-type payload)
           " (" (string-length payload) " bytes)"
           ;; " " (wots (write (payload-parse payload))) ;; uncomment for more juice
           ))

(define (ssh-log-send ssh payload)
  (ssh-log "ssh send #" (ssh-seqnum/write ssh) ": " (payload-type payload)
           " (" (string-length payload) " bytes)"
           ;; " " (wots (write (payload-parse payload))) ;; uncomment for more juice
           ))

(define (ssh-log-ignore/parsed ssh parsed)
  (ssh-log "ssh ignr #" (ssh-seqnum/write ssh) ": " (car parsed)
           " " (wots (write parsed))))

(define-record-type ssh
  (%make-ssh server?
             ip op
             host-pk hostkey-signer hostkey-verifier ;; blob, procedure, procedure
             sid user user-pk
             hello/server   hello/client
             seqnum/read    seqnum/write
             payload-reader payload-writer
             queue
             read-mutex write-mutex read-cv
             kexinit/sent
             specific
             channels)
  ssh?
  (server?        ssh-server?        %ssh-server-set!)
  (ip             ssh-ip)
  (op             ssh-op)
  (host-pk        ssh-host-pk        %ssh-host-pk-set!)
  (hostkey-signer ssh-hostkey-signer)
  (hostkey-verifier ssh-hostkey-verifier)
  (sid            ssh-sid            %ssh-sid-set!)
  (user           ssh-user           %ssh-user-set!)
  (user-pk        ssh-user-pk        %ssh-user-pk-set!)
  (hello/server   ssh-hello/server   %ssh-hello/server-set!)
  (hello/client   ssh-hello/client   %ssh-hello/client-set!)
  (seqnum/read    ssh-seqnum/read    %ssh-seqnum/read-set!)
  (seqnum/write   ssh-seqnum/write   %ssh-seqnum/write-set!)
  (payload-reader ssh-payload-reader %ssh-payload-reader-set!)
  (payload-writer ssh-payload-writer %ssh-payload-writer-set!)
  (queue          ssh-queue)
  (read-mutex     ssh-read-mutex)
  (write-mutex    ssh-write-mutex)
  (read-cv        ssh-read-cv)
  (kexinit/sent   ssh-kexinit/sent   %ssh-kexinit/sent-set!)
  (specific       ssh-specific       ssh-specific-set!)
  (channels       ssh-channels))

(define-record-printer ssh
  (lambda (ssh p)
    (display "#<ssh " p)
    (display (ssh-user ssh) p)
    (when (port? (ssh-ip ssh))
      (display "@" p)
      (receive (local remote) (tcp-addresses (ssh-ip ssh))
        (display remote p)))
    (display " (" p)
    (display (hash-table-size (ssh-channels ssh)) p)
    (display ")" p)
    (display ">" p)))

(define (make-ssh server? ip op host-pk signer verifier)
  (assert (input-port? ip))
  (assert (output-port? op))
  (if server?
      (begin
        (assert (blob? host-pk))
        (assert (procedure? signer)))
      (begin
        (assert (procedure? verifier))))
  (%make-ssh server?
             ip op
             host-pk signer verifier
             #f #f #f ;; sid user user-pk
             #f #f ;; hellos
             0 0   ;; sequence numbers
             read-payload/none
             write-payload/none
             (make-queue)
             (make-mutex) (make-mutex) ;; read write
             (make-condition-variable) ;; ssh-read-cv
             #f
             #f ;; specific
             (make-hash-table)))

;; ssh-kex-mutex is used to block others to send ssh-packets in the
;; middle of a kex session. write-payload is therefore protected by
;; ssh-kex-mutex. but since write-payload is used inside the kex
;; process itself, we need temporarily skip mutex protection inside
;; the kex session.
(define currently-kexing? (make-parameter #f))

(define ssh-channel
  (getter-with-setter
   (lambda (ssh cid)     (hash-table-ref  (ssh-channels ssh) cid))
   (lambda (ssh cid val)
     (if val
         (hash-table-set! (ssh-channels ssh) cid val)
         (hash-table-remove! (ssh-channels ssh) cid)))))



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

(define (ssh-write-blob16 blob #!optional (op (current-output-port)))
  (display (blob->string blob) op))

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
;; and implemented in openssh's sshbuf_put_bignum2_bytes
(define (string->mpint str)
  (let loop ((start 0))
    (if (eq? #\null (string-ref str start))
        (loop (+ 1 start))
        (if (>= (char->integer (string-ref str start)) 128)
            (string-append "\x00" (substring str start))
            (substring str start)))))

(define (write-mpint/positive str)
  (ssh-write-string (string->mpint str)))

(define (write-payload/none ssh payload)
  (ssh-write-string (wots (payload-pad payload 8 4)) (ssh-op ssh)))


;; read-payload and write-payload API (hopefully thread safe)

(define (%kexinit? payload)
  (eq? 'kexinit (payload-type payload)))

(define (write-payload/mutexless ssh payload)
  (ssh-log-send ssh payload)
  ((ssh-payload-writer ssh) ssh payload)
  (%ssh-seqnum/write-set! ssh (+ 1 (ssh-seqnum/write ssh))))

;; like read-payload, but without kexinit handler
(define (read-payload/mutexless ssh)
  (let ((payload ((ssh-payload-reader ssh) ssh)))
    (ssh-log-recv ssh payload)
    (%ssh-seqnum/read-set! ssh (+ 1 (ssh-seqnum/read ssh)))
    payload))

(define (read-payload/mutex ssh)
  (mutex-lock! (ssh-read-mutex ssh))
  (if (queue-empty? (ssh-queue ssh))
      ;; read from network
      (let ((p (read-payload/mutexless ssh)))
        (if (%kexinit? p)
            (begin
              (kexinit-respond ssh p)
              (mutex-unlock! (ssh-read-mutex ssh))
              (read-payload/mutex ssh))
            (begin
              (mutex-unlock! (ssh-read-mutex ssh))
              p)))
      ;; get packet from queue (some sender was looking for a kexinit)
      (let ((r (queue-remove! (ssh-queue ssh))))
        (mutex-unlock! (ssh-read-mutex ssh))
        r)))

(define (write-payload/mutex ssh p)
  (mutex-lock! (ssh-write-mutex ssh))
  (if (ssh-kexinit/sent ssh)
      ;; kexing, we'll need to halt everything and wait for a kexinit
      ;; response. we can't send non-kex packets until this is all
      ;; over.
      (begin
        ;; TODO: internal error when timeout is 0. core bug?
        (if (mutex-lock! (ssh-read-mutex ssh) 0.01)
            ;; noone else is reading, we'll have to do the dirty work
            ;; ourselves.
            (begin (mutex-unlock! (ssh-write-mutex ssh))
                   (let ((incoming (read-payload/mutexless ssh)))
                     (if (%kexinit? incoming)
                         (begin ;; all according to plan
                           (kexinit-respond ssh incoming)
                           ;; kexinit/sent should be #f now
                           (mutex-unlock! (ssh-read-mutex ssh))
                           (write-payload/mutex ssh p))
                         (begin ;; obs, didn't intend to get this one
                           (queue-add! (ssh-queue ssh) incoming)
                           (mutex-unlock! (ssh-read-mutex ssh))
                           (write-payload/mutex ssh p)))))
            ;; we didn't get the read lock - someone else is reading
            ;; and they'll do the work for us. wait for them to
            ;; finish.
            (begin (mutex-unlock! (ssh-write-mutex ssh) (ssh-read-cv ssh))
                   (write-payload/mutex ssh p))))
      (begin
        (when (%kexinit? p)
          (%ssh-kexinit/sent-set! ssh p))
        (write-payload/mutexless ssh p)
        (mutex-unlock! (ssh-write-mutex ssh)))))

(define (read-payload ssh)
  (if (currently-kexing?)
      (read-payload/mutexless ssh)
      (read-payload/mutex ssh)))

(define (write-payload ssh payload)
  (if (currently-kexing?)
      (write-payload/mutexless ssh payload)
      (write-payload/mutex ssh payload)))

;; like read-payload, but error on unexpected payload type
(define (read-payload/expect ssh expected-payload-type)
  (let ((payload (read-payload ssh)))
    (unless (eq? (payload-type payload) expected-payload-type)
      (error (conc "expected " expected-payload-type  " got")
             (payload-type payload) payload))
    payload))

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

;; in SSH2 packets of the form:
;;     length padding-length payload padding
;; extract payload
(define (packet-payload packet)
  (define padding_length (s2u (substring packet 0 1)))
  
  (define payload_end (- (string-length packet) padding_length))
  (substring packet 1 payload_end))

;; look at one-byte header that determines payload time. this should
;; be present in _all_ SSH packets.
;; (payload-type "\x06")
;; (payload-type "\xff")
(define (payload-type payload)
  (let* ((t (char->integer (string-ref payload 0)))
         (pair (rassoc t *payload-types*)))
    (and pair (car pair))))

(define (ssh-read-string #!optional (ip (current-input-port)))
  (define packet_length (s2u (read-string/check 4 ip)))
  (read-string/check packet_length ip))

(define (ssh-read-symbol #!optional (ip (current-input-port)))
  (string->symbol (ssh-read-string ip)))

(define (ssh-read-uint32 #!optional (ip (current-input-port)))
  (s2u (read-string/check 4 ip)))

(define (ssh-read-boolean #!optional (ip (current-input-port)))
  (if (= 0 (read-byte)) #f #t))

(define (ssh-read-blob16 #!optional (ip (current-input-port)))
  (string->blob (read-string 16 ip)))

(define (ssh-read-signpk #!optional (ip (current-input-port)))
  (define type "ssh-ed25519")

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

    (define pak* (read-string/check paklen ip))
    (define mac  (read-string/check 16 ip))
    
    (define poly-key (string->blob (chacha-decrypt ssh chacha-main #${00000000 00000000} (make-string 32 #\null))))

    (unless ((symmetric-verify poly-key) mac (conc paklen* pak*))
      (error "poly1305 signature failed (key,mac,content)"
             poly-key
             (string->blob mac)
             (string->blob (conc paklen* pak*))))
    
    (define pak (chacha-decrypt ssh chacha-main #${01000000 00000000} pak*))

    (packet-payload pak))
  
  read-payload/chacha20)


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
  (let ((pk (if (blob? pk) (blob->string pk) pk)))
    (ssh-write-string
     (conc (u2s (string-length type)) type
           (u2s (string-length pk))   pk))))

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
  (assert (= (string-length H) 32))
  (assert (= (string-length session-id) 32))
  (assert (= (string-length c) 1)) ;; make sure we're doing one of A B C D E F.
  (assert (memq (string-ref c 0) '(#\A #\B #\C #\D #\E #\F)))
  (define K1 (sha256 (string-append (u2s (string-length K)) K H c session-id)))
  (define K2 (sha256 (string-append (u2s (string-length K)) K H K1)))
  (string-append K1 K2))


;; ==================== parsing

;; because these
(define (unparse-kexinit*)
  (unparse-kexinit
   #f
   (string->blob (read-string 16 (current-entropy-port)))
   '("curve25519-sha256@libssh.org")  ;; kex_algorithms
   '("ssh-ed25519")                   ;; server_host_key_algorithms
   '("chacha20-poly1305@openssh.com") ;; encryption_algorithms_c->s
   '("chacha20-poly1305@openssh.com") ;; encryption_algorithms_s->c
   '()       ;; mac_algorithms_client_to_server
   '()       ;; mac_algorithms_server_to_client
   '("none") ;; compression_algorithms_client_to_server
   '("none") ;; compression_algorithms_server_to_client
   '()       ;; languages_client_to_server
   '()       ;; languages_server_to_client
   #f        ;; first_kex_packet_follows
   0))       ;; reserved00


;; process the incoming kexinit payload (kex/read). this must be done
;; in lockstep per SSH protocol: so no other threads must send ssh
;; packets while this procedure is running.
(define (kexinit-respond/mutexless ssh kex/read)

  (unless (and (ssh-hello/server ssh)
               (ssh-hello/client ssh))
    (error "run-protocol-exchange not run"))

  (define (xhash! remote-pk local-pk sharedsecret host-pk)
    (define hash
      (exchange-hash ssh
                     kex/read (ssh-kexinit/sent ssh)
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
    (define hash (xhash! client-pk server-pk sharedsecret (ssh-host-pk ssh)))
    (define signature (substring ((ssh-hostkey-signer ssh) hash) 0 64))

    (unparse-kexdh-reply ssh (ssh-host-pk ssh) server-pk signature)
    (values sharedsecret hash))

  (define (init-client)
    (define-values (client-sk client-pk)
      (make-curve25519-keypair))

    (unparse-kexdh-init ssh client-pk)

    (define kexdh-reply (payload-parse (read-payload/expect ssh 'kexdh-reply)))
    (match kexdh-reply
      (('kexdh-reply host-pk server-pk signature)
       (define sharedsecret (string->mpint (curve25519-dh client-sk server-pk)))
       (define hash (xhash! server-pk client-pk sharedsecret host-pk))

       (let ((pkb (string->blob host-pk))
             (handler (ssh-hostkey-verifier ssh)))

         (if ((asymmetric-verify pkb) (conc signature hash))
             (if (handler pkb)
                 (begin
                   (%ssh-host-pk-set! ssh pkb)
                   (values sharedsecret hash))
                 (begin
                   (error "server hostkey not accepted")))
             (error "server hostkey signature mismatch"))))))

  (define-values (sharedsecret hash)
    (if (ssh-server? ssh)
        (init-server)
        (init-client)))

  (unparse-newkeys ssh)
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

;; must be called while holding _both_ ssh-read-mutex and ssh-write-mutex!
(define (kexinit-respond ssh kexinit-payload/read)

  (mutex-lock! (ssh-write-mutex ssh))

  (unless (ssh-kexinit/sent ssh)
    (let ((kexinit-packet (unparse-kexinit*)))
      (%ssh-kexinit/sent-set! ssh kexinit-packet)
      (write-payload/mutexless ssh kexinit-packet)))

  (parameterize ((currently-kexing? #t))
    (kexinit-respond/mutexless ssh kexinit-payload/read)
    (%ssh-kexinit/sent-set! ssh #f))

  ;; release any blocked writers
  (condition-variable-broadcast! (ssh-read-cv ssh))

  (mutex-unlock! (ssh-write-mutex ssh)))

;; initiate a key regotiation. the subsequent incoming packet may not
;; immeditatly be the kexinit reply!
(define (kexinit-start ssh)
  (let ((kexinit-packet (unparse-kexinit*)))
    (write-payload ssh kexinit-packet)))

(include "minissh-parsing.scm")

(define (payload-parse payload)
  (cond ((hash-table-ref *payload-parsers* (payload-type payload) (lambda () #f)) =>
         (lambda (parser) (parser payload)))
        (else (list (payload-type payload) 'unparsed payload))))

;; TODO: find a good (but shorter) name for parsed-payload
(define (next-payload ssh)
  (payload-parse (read-payload ssh)))

(define (ssh-server-start server-host-key-public
                          server-host-key-secret
                          handler
                          #!key
                          (port 22022)
                          (listener (tcp-listen port))
                          (accept tcp-accept)
                          (spawn thread-start!))
  (let ((server-host-key-public (if (string? server-host-key-public)
                                    (string->blob server-host-key-public)
                                    server-host-key-public))
        (server-host-key-secret (if (string? server-host-key-secret)
                                    (string->blob server-host-key-secret)
                                    server-host-key-secret)))
    (let loop ()
      (receive (ip op) (accept listener)
        (spawn
         (lambda ()
           (handle-exceptions
               e (begin
                   (close-input-port ip)
                   (close-output-port op)
                   ((current-exception-handler) e))

               (define ssh
                 (make-ssh #t
                           ip op
                           server-host-key-public
                           (asymmetric-sign server-host-key-secret) ;; ssh-hostkey-signer
                           #f)) ;; ssh-hostkey-verifier
               (run-protocol-exchange ssh)
               (kexinit-start ssh)
               (handler ssh)
               (close-input-port ip)
               (close-output-port op)))))
      (loop))))


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

;; ==================== userauth ====================

(define (pk->pkblob pk)
  (wifs pk
        (assert (equal? "ssh-ed25519" (ssh-read-string)))
        (ssh-read-string)))

(define (sign->signblob sign)
  (wifs sign
        (assert (equal? "ssh-ed25519" (ssh-read-string)))
        (ssh-read-string)))

;; return the string/blob used by the client to sign
(define (userauth-publickey-signature-blob ssh user pk)
  ;; unparse-userauth-request does not work here beacuse this blob is
  ;; special. see https://tools.ietf.org/html/rfc4252 page 10
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


(define (signblob->sign signblob)
  (wots
   (ssh-write-string "ssh-ed25519")
   (ssh-write-string signblob)))

;; publickey must return true if a (user pk) login would be ok (can be called multiple times)
;; password must return true if (user password) loging would be ok
;; banner gets called after successful authenticaion, but before sending 'userauth-success
(define (run-userauth ssh
                      #!key publickey password banner
                      (unhandled
                       (lambda (x continue)
                         (ssh-log-ignore/parsed ssh x)
                         (continue))))

  (define (fail! #!optional partial?)
    (define auths
      (append (if publickey '("publickey") '())
              (if password  '("password")  '())))
    (unparse-userauth-failure ssh auths partial?))

  (let loop ()

    (match (next-payload ssh)

      (('service-request "ssh-userauth")
       (unparse-service-accept ssh "ssh-userauth")
       (loop))

      ;; client asks if pk would be ok (since the actual signing is expensive)
      (('userauth-request user "ssh-connection" 'publickey #f 'ssh-ed25519 pk)
       (cond ((and publickey (publickey user 'ssh-ed25519 pk #f))
              ;; tell client pk will be accepted if upcoming signature verifies
              (unparse-userauth-pk-ok ssh "ssh-ed25519" pk)
              (loop))
             (else
              (fail!)
              (loop))))
      ;; login with pk and signature
      (('userauth-request user "ssh-connection" 'publickey #t 'ssh-ed25519 pk sign)
       (cond ((and publickey
                   (or (userauth-publickey-verify ssh user pk sign)
                       (begin
                         (unparse-userauth-banner
                          ssh (conc "signature verification failed. this is"
                                    " most likely a bug in chicken-minissh.\n") "")
                         #f))
                   (publickey user 'ssh-ed25519 pk #t))
              (if banner (banner user))
              (%ssh-user-set! ssh user)
              (%ssh-user-pk-set! ssh (string->blob pk))
              (unparse-userauth-success ssh))
             ;; success, no loop ^
             (else
              (fail!)
              (loop))))
      ;; password login
      (('userauth-request user "ssh-connection" 'password #f plaintext-password)
       (cond ((and password (password user plaintext-password))
              (if banner (banner user))
              (%ssh-user-set! ssh user)
              (unparse-userauth-success ssh))
             ;; success, no loop ^
             (else
              (fail!)
              (loop))))
      ;; invalid log                             ,-- eg. 'none
      (('userauth-request user "ssh-connection" type . whatever)
       (fail!)
       (loop))

      (otherwise (unhandled otherwise loop)))))

(include "minissh-client.scm")
(include "minissh-channels.scm")
