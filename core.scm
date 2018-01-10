(use tcp base64 tweetnacl sha2 message-digest)
(use chacha)

(define-record-type ssh
  (%make-ssh ip op sid seqnum/read seqnum/write payload-reader payload-writer)
  ssh?
  (ip ssh-ip %ssh-ip-set!)
  (op ssh-op %ssh-op-set!)
  (sid ssh-sid %ssh-sid-set!)
  (seqnum/read  ssh-seqnum/read  %ssh-seqnum/read-set!)
  (seqnum/write ssh-seqnum/write %ssh-seqnum/write-set!)
  (payload-reader ssh-payload-reader %ssh-payload-reader-set!)
  (payload-writer ssh-payload-writer %ssh-payload-writer-set!))

(define (make-ssh ip op)
  (assert (input-port? ip))
  (assert (output-port? op))
  (let ((ssh (%make-ssh ip op
                        #f 0 0
                        read-payload/none
                        write-payload/none)))
    (warning "outpit? " (ssh-op ssh) op)
    ssh))

(begin ;; from https://tools.ietf.org/html/rfc4253#section-12
  (define SSH_MSG_DISCONNECT             1)
  (define SSH_MSG_IGNORE                 2)
  (define SSH_MSG_UNIMPLEMENTED          3)
  (define SSH_MSG_DEBUG                  4)
  (define SSH_MSG_SERVICE_REQUEST        5)
  (define SSH_MSG_SERVICE_ACCEPT         6)
  (define SSH_MSG_KEXINIT                20)
  (define SSH_MSG_NEWKEYS                21))

(begin ;; from https://tools.ietf.org/html/rfc4252#section-6
  (define SSH_MSG_USERAUTH_REQUEST            50)
  (define SSH_MSG_USERAUTH_FAILURE            51)
  (define SSH_MSG_USERAUTH_SUCCESS            52)
  (define SSH_MSG_USERAUTH_BANNER             53))

(begin ;; from https://tools.ietf.org/html/rfc4254#section-9
  (define SSH_MSG_GLOBAL_REQUEST                  80)
  (define SSH_MSG_REQUEST_SUCCESS                 81)
  (define SSH_MSG_REQUEST_FAILURE                 82)
  (define SSH_MSG_CHANNEL_OPEN                    90)
  (define SSH_MSG_CHANNEL_OPEN_CONFIRMATION       91)
  (define SSH_MSG_CHANNEL_OPEN_FAILURE            92)
  (define SSH_MSG_CHANNEL_WINDOW_ADJUST           93)
  (define SSH_MSG_CHANNEL_DATA                    94)
  (define SSH_MSG_CHANNEL_EXTENDED_DATA           95)
  (define SSH_MSG_CHANNEL_EOF                     96)
  (define SSH_MSG_CHANNEL_CLOSE                   97)
  (define SSH_MSG_CHANNEL_REQUEST                 98)
  (define SSH_MSG_CHANNEL_SUCCESS                 99)
  (define SSH_MSG_CHANNEL_FAILURE                100))

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
    (lambda () (print "==== SENDING #" (ssh-seqnum/write ssh) " " (wots (write payload)))))
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

(define (read-buflen #!optional (ip (current-input-port)))
  (define packet_length (s2u (read-string/check 4 ip)))
  (read-string/check packet_length ip))

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
        (print "==== RECV #" (ssh-seqnum/read ssh) " " (wots (write payload)))))
    (%ssh-seqnum/read-set! ssh (+ 1 (ssh-seqnum/read ssh)))
    payload))

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
