(use tcp base64 tweetnacl sha2 message-digest)
(use chacha)

(begin
  (define SSH_MSG_USERAUTH_REQUEST            50)
  (define SSH_MSG_USERAUTH_FAILURE            51)
  (define SSH_MSG_USERAUTH_SUCCESS            52)
  (define SSH_MSG_USERAUTH_BANNER             53))

(begin
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

(define (write-buflen packet #!optional (op (current-output-port)))
  (display (u2s (string-length packet)) op)
  (display packet op))

(define (write-payload/none payload op)
  (write-buflen (wots (payload-pad payload 8 4)) op))

;; parameterizing payload writers, not packet writers because ciphers
;; differ in padding schemes (chacha20 pads excluding packet_length,
;; others include those 4 bytes). including padding handling inside
;; writers means they can customize their padding as needed.
(define current-payload-writer      (make-parameter write-payload/none))
(define current-packet-seqnum/write (make-parameter 0))

(define (write-payload payload op)
  (with-output-to-port (current-error-port)
    (lambda () (print "====== SENDING (" (string-length payload) ") " (wots (write payload)))))
  ((current-payload-writer) payload op)
  (current-packet-seqnum/write (+ 1 (current-packet-seqnum/write))))

(define (make-payload-writer/chacha20 key-main key-header)
  
  (define chacha-s-main (make-chacha key-main))
  (define chacha-s-header (make-chacha key-header))

  (define (chacha-encrypt chacha counter str)
    (chacha-iv! chacha
                (string->blob (conc "\x00\x00\x00\x00" (u2s (current-packet-seqnum/write))))
                counter)
    (chacha-encrypt! chacha str))
  
  (define (write-payload/chacha20 payload op)
  
    (define pak (wots (payload-pad payload 8 0)))
    (print "SENDING: " (wots (write pak)))
 
    (define pak* (chacha-encrypt chacha-s-main #${01000000 00000000} pak))
    (define paklen (u2s (string-length pak)))
    (define paklen* (chacha-encrypt chacha-s-header #${00000000 00000000} paklen))
  
    (define poly (string->blob (chacha-encrypt chacha-s-main #${00000000 00000000} (make-string 32 #\null))))
    (define auth ((symmetric-sign poly) (conc paklen* pak*) tag-only?: #t))
    (assert (= 16 (string-length auth)))

    (display paklen* op)
    (display pak* op)
    (display auth op))

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
  (named-list '("hmac-sha2-256")) ;; mac_algorithms_client_to_server
  (named-list '("hmac-sha2-256")) ;; mac_algorithms_server_to_client
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
  (define packet_length (s2u (read-string 4 ip)))
  (let ((result (read-string packet_length ip)))
    (assert (= (string-length result) packet_length))
    result))

(define (read-payload/none ip)
  (packet-payload (read-buflen ip)))

(define current-packet-seqnum/read  (make-parameter 0))
(define current-payload-reader      (make-parameter read-payload/none))


(define (make-payload-reader/chacha20 key-main key-header)
  (define chacha-header (make-chacha key-header))
  (define chacha-main   (make-chacha key-main))

  (define (chacha-decrypt chacha counter ciphertext)
    (chacha-iv! chacha ;; TODO support 8-byte sequence numbers:
                (string->blob (conc "\x00\x00\x00\x00" (u2s (current-packet-seqnum/read))))
                counter)
    (chacha-encrypt! chacha ciphertext))
  
  (define (read-payload/chacha20 ip)

    (define paklen* (read-string 4 ip))
    (define paklen (s2u (chacha-decrypt chacha-header #${00000000 00000000} paklen*)))
    ;;(print "paklen " paklen)
    (unless (< paklen 100) (error "paklen too big?" paklen))
    (define pak* (read-string paklen ip))
    (define mac  (read-string 16 ip))
    
    (define poly-key (string->blob (chacha-decrypt chacha-main #${00000000 00000000} (make-string 32 #\null))))
    ;; (print "poly-key " poly-key)
    (unless ((symmetric-verify poly-key) mac (conc paklen* pak*))
      (error "poly1305 signature failed (key,mac,content)"
             poly-key
             (string->blob mac)
             (string->blob (conc paklen* pak*))))
    
    (define pak (chacha-decrypt chacha-main #${01000000 00000000} pak*))
    ;;(print "pak: " (wots (write pak)))

    (packet-payload pak))
  
  read-payload/chacha20)

(define (read-payload ip)

  (let ((payload ((current-payload-reader) ip)))
    (with-output-to-port (current-error-port)
      (lambda ()
        (print "==== RECV #" (current-packet-seqnum/read) " " (wots (write payload)))))
    (current-packet-seqnum/read (+ 1 (current-packet-seqnum/read)))
    payload))


;; derive a 64 byte key from curve25519 shared secret and exchange
;; hash. see https://tools.ietf.org/html/rfc4253#section-7.2
(define (kex-derive-keys64 c K H session-id)
  (assert (= 32 (string-length K)))
  (assert (= 32 (string-length H)))
  (assert (= 32 (string-length session-id)))
  (assert (= 1 (string-length c))) ;; make sure we're doing one of A B C D E F.
  (assert (memq (string-ref c 0) '(#\A #\B #\C #\D #\E #\F)))
  (define K1 (sha256 (string-append (u2s (string-length K)) K H c session-id)))
  (define K2 (sha256 (string-append (u2s (string-length K)) K H K1)))
  (string-append K1 K2))
