;; include me from within minissh.scm

;; for consistency:
;; TODO: rename read-buflen -> ssh-read-string
;; TODO: rename read-u32 -> ssh-read-uint32
;; TODO: rename read-bool -> ssh-read-boolean

;; ==================== parse syntax ====================

;; (syntax-prefix "foo-" test) => unbound variable foo-test (yey!)
(define-syntax syntax-prefix
  (er-macro-transformer
   (lambda (x r t)
     (let ((prefix (cadr x))
           (symbol (caddr x)))
       (string->symbol (string-append prefix (symbol->string symbol)))))))

(define-syntax parse-match
  (syntax-rules ()
    ((_ ) (error "parse fail: cond exhausted"))
    ((_ (match body ...) matches ...)
     (if match
         (parse (body ...))
         (parse-match matches ...)))))

;; (wifs "\x01\x00\x00\x00\x03foo" (parse ((bool bar) (bufsym test))))
;; (wifs "\x00\x00\x00\x01a" (parse ((bufsym test) (cond [(eq? test 'a)]))))
(define-syntax parse
  (syntax-rules (cond)
    ((_ ()) '())

    ((_ ((cond matches ...)))
     (parse-match matches ...))

    ((_ ((type name) rest ...))
     (let ((name ((syntax-prefix "read-" type))))
       (cons name (parse (rest ...)))))))

;; ==================== unparse syntax ====================

(define-syntax unparse-match
  (syntax-rules ()
    ((_ x) (error "unparse fail: cond exhausted"))
    ((_ x (match body ...) matches ...)
     (let ((datum x))
       (if match
           (unparse datum (body ...))
           (unparse-match datum matches ...))))))

;; (wots (unparse '(#t) ((bool foo))))
;; (wots (unparse '("guest" publickey) ((buflen username) (bufsym authtype))))
(define-syntax unparse
  (syntax-rules (cond)
    ((_ x ()) (begin))

    ((_ x ((cond matches ...)))
     (unparse-match x matches ...))

    ((_ x ((type name) rest ...))
     (let ((datum x))
       (let ((name (car datum)))
         ((syntax-prefix "write-" type) name)
         (unparse (cdr datum) (rest ...)))))))

;; make two definitions in one go
;; (expand '(define-parsepair* foo x y))
(define-syntax define-parsepair*
  (er-macro-transformer
   (lambda (x r t)

     (define (prefix str sym)
       (string->symbol (string-append str (symbol->string sym))))

     (let* ((type (cadr x))
            (parser-name   (prefix "parse-"   type))
            (unparser-name (prefix "unparse-" type))
            (parser (caddr x))
            (unparser (cadddr x)))

       `(,(r 'begin)
         (,(r 'define) ,parser-name   ,parser)
         (,(r 'define) ,unparser-name ,unparser))))))

;; define parser and unparser and include payload-type
(define-syntax define-parsepair
  (syntax-rules ()
    ((_ type pspec)
     (define-parsepair*
       type
       (lambda (payload)
         (wifs payload
               (cons (read-payload-type (quote type))
                     (parse pspec))))
       (lambda (msg)
         (unless (eq? 'type (car msg))
           (error "unparsing: tag mismatch (expected, actual)"
                  'type (car msg)))
         (wots
          (write-payload-type (quote type))
          (unparse (cdr msg) pspec)))))))

;; ====================

(define-parsepair kexdh-reply
  ((signpk ssh-hostkey-pk)
   (buflen       serverpk)
   (signpk      signature)))

(define-parsepair disconnect
  ((u32    reason-code)
   (buflen description)
   (buflen language)))

(define-parsepair service-request
  ((buflen name)))

(define-parsepair channel-open
  ((buflen channel-type)
   (u32    sender-channel)
   (u32    window-size)
   (u32    max-packet-size)))

;; see https://tools.ietf.org/html/rfc4254#section-6.2
(define-parsepair channel-request
  ((u32 cid)
   (bufsym request-type)
   (bool want-reply?)
   (cond [(eq? request-type 'pty-req)
          (buflen term)
          (u32    width/characters)
          (u32    height/rows)
          (u32    width/pixels)
          (u32    height/pixels)
          (buflen modes)]

         ;; TODO: x11-req
         [(eq? request-type 'env)
          (buflen name)
          (buflen value)]

         [(eq? request-type 'shell)]

         [(eq? request-type 'exec)
          (buflen command)]

         [(eq? request-type 'subsystem)
          (buflen name)]

         [(eq? request-type 'window-change)
          (u32    width)
          (u32    height)
          (u32    width/pixels)
          (u32    height/pixels)]

         [(eq? request-type 'xon-xoff)
          (bool      client-can-do)]

         [(eq? request-type 'signal)
          (bufsym name)] ;; without "SIG" prefix

         [(eq? request-type 'exit-status)
          (u32 status)]

         [(eq? request-type 'exit-signal)
          ;; valid signal names: ABRT ALRM FPE HUP ILL
          ;; INT KILL PIPE QUIT SEGV TERM USR1 USR2
          ;; + local ones with an @-sign
          (bufsym name) ;; without the "SIG" prefix
          (bool core-dumped?)
          (buflen  error-message) ;; ISO-10646 UTF-8 encoding
          (buflen  language)]     ;; RFC3066

         [(eq? request-type 'tcpip-forward)
          (buflen address) ;; (e.g., "0.0.0.0")
          (u32    port)]

         [#t ;; OBS: any guarantees that we can read until eof?
          ;;(string anything)
          ])))

;; https://tools.ietf.org/html/rfc4252#section-7
(define-parsepair userauth-request
  ((buflen user)
   (buflen service)
   (bufsym method)
   (cond [(eq? method 'publickey)
          (bool signature?)
          (cond [(eq? signature? #f)
                 (bufsym algorithm)
                 (buflen pk)]
                [(eq? signature? #t)
                 (bufsym algorithm)
                 (buflen pk)
                 (buflen signature)])]
         [(eq? method 'password)
          (bool renew?)
          (cond [(eq? renew? #f)
                 (buflen plaintext-password)]
                [(eq? renew? #t)
                 (buflen old-password)
                 (buflen new-password)])]
         [(eq? method 'none)])))


(define-parsepair channel-data
  ((u32    cid)
   (buflen data)))

(define-parsepair channel-eof
  ((u32 cid)))

(define-parsepair channel-close
  ((u32 cid)))

;; (parse-channel-eof "`\x00\x00\x00\x01")
;; (parse-channel-close "a\x00\x00\x00\x01")
;; (parse-channel-data "^\x00\x00\x00\x01\x00\x00\x00\rawdofihawofh\n")

;; TODO: derive this automatically
(define *payload-parsers*
  `((kexdh-reply      .  ,parse-kexdh-reply)
    (disconnect       .  ,parse-disconnect)
    (service-request  .  ,parse-service-request)
    (userauth-request .  ,parse-userauth-request)
    (channel-open     .  ,parse-channel-open)
    (channel-request  .  ,parse-channel-request)
    (channel-data     .  ,parse-channel-data)
    (channel-eof      .  ,parse-channel-eof)
    (channel-close    .  ,parse-channel-close)))
