;; include me from within minissh.scm

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

;; (wifs "\x01\x00\x00\x00\x03foo" (parse ((boolean bar) (symbol test))))
;; (wifs "\x00\x00\x00\x01a" (parse ((symbol test) (cond [(eq? test 'a)]))))
(define-syntax parse
  (syntax-rules (cond)
    ((_ ()) '())

    ((_ ((cond matches ...)))
     (parse-match matches ...))

    ((_ ((type name) rest ...))
     (let ((name ((syntax-prefix "ssh-read-" type))))
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

;; (wots (unparse '(#t) ((boolean foo))))
;; (wots (unparse '("guest" publickey) ((string username) (symbol authtype))))
(define-syntax unparse
  (syntax-rules (cond)
    ((_ x ())
     (unless (null? x)
       (error "unparsing: too many arguments")))

    ((_ x ((cond matches ...)))
     (unparse-match x matches ...))

    ((_ x ((type name) rest ...))
     (let ((datum x))
       (unless (pair? datum)
         (error "unparsing: too few arguments" 'name))
       (let ((name (car datum)))
         ((syntax-prefix "ssh-write-" type) name)
         (unparse (cdr datum) (rest ...)))))))

(define *payload-parsers* (make-hash-table))
(define (payload-parser payload-type)
  (hash-table-ref *payload-parsers* payload-type))

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
         (,(r 'define) ,unparser-name ,unparser)
         (,(r 'hash-table-set!)
          *payload-parsers* (quote ,type) ,parser-name))))))

;; (parse-spec->argumentnames '((string name) (cond [#t])))
(define (parse-spec->argumentnames pspec)
  (let loop ((pspec pspec)
             (res '()))
    (if (pair? pspec)
        (let ((spec (car pspec)))
          (if (eq? (car spec) 'cond)
              (append (reverse res) 'rest)
              (loop (cdr pspec) (cons (cadr (car pspec)) res))))
        (reverse res))))

;; produce informative procedure descriptions.
;; try this:
;; (procedure-decorate (lambda () #f) '(foo bar . rest))
;; => #<procedure (unparse-x bar . rest)>
(define (procedure-decorate proc lst)
  (##sys#decorate-lambda
   proc ##sys#lambda-info?
   (lambda (proc i)
     (##sys#setslot proc i (##sys#make-lambda-info (wots (write lst))))
     proc)))

;; define parser and unparser and include payload-type
(define-syntax define-parsepair
  (syntax-rules ()
    ((_ type pspec)
     (define-parsepair*
       type
       (lambda (payload)
         (wifs payload
               (cons (ssh-read-msgno (quote type))
                     (parse pspec))))

       (procedure-decorate
        (lambda (ssh . arguments)
          (let ((payload (wots
                          (ssh-write-msgno (quote type))
                          (unparse arguments pspec))))
            (if ssh (write-payload ssh payload) payload)))
        (cons (string->symbol (conc "unparse-" 'type))
              (cons 'ssh
                    (parse-spec->argumentnames 'pspec))))))))

;; ====================

(define-parsepair disconnect
  ((uint32 reason-code)
   (string description)
   (string language)))

;; TODO: ignore
;; TODO: unimplemented
;; TODO: debug


(define-parsepair service-request
  ((string name)))

(define-parsepair service-accept
  ((string name)))

(define-parsepair kexinit
  ((blob16 cookie)
   (list kex_algorithms)
   (list server_host_key_algorithms)
   (list encryption_algorithms_c->s)
   (list encryption_algorithms_s->c)
   (list mac_algorithms_client_to_server)
   (list mac_algorithms_server_to_client)
   (list compression_algorithms_client_to_server)
   (list compression_algorithms_server_to_client)
   (list languages_client_to_server)
   (list languages_server_to_client)
   (boolean first_kex_packet_follows)
   (uint32 reserved00)))

(define-parsepair newkeys ())

(define-parsepair kexdh-init
  ((string client-pk)))

(define-parsepair kexdh-reply
  ((signpk ssh-host-pk)
   (string serverpk)
   (signpk signature)))

;; https://tools.ietf.org/html/rfc4252#section-7
(define-parsepair userauth-request
  ((string user)
   (string service)
   (symbol method)
   (cond [(eq? method 'publickey)
          (boolean signature?)
          (cond [(eq? signature? #f)
                 (symbol algorithm)
                 (string pk)]
                [(eq? signature? #t)
                 (symbol algorithm)
                 (string pk)
                 (string signature)])]
         [(eq? method 'password)
          (boolean renew?)
          (cond [(eq? renew? #f)
                 (string plaintext-password)]
                [(eq? renew? #t)
                 (string old-password)
                 (string new-password)])]
         [(eq? method 'none)])))

(define-parsepair userauth-failure
  ((list auths)
   (boolean partial?)))

(define-parsepair userauth-success ())

(define-parsepair userauth-banner
  ((string msg)
   (string language)))

(define-parsepair userauth-pk-ok
  ((string algorithm)
   (string pk)))

;; TODO: global-request
;; TODO: request-success
;; TODO: request-failure

(define-parsepair channel-open
  ((string channel-type)
   (uint32 sender-channel)
   (uint32 window-size)
   (uint32 max-packet-size)))

(define-parsepair channel-open-confirmation
  ((uint32 channel-recipient)
   (uint32 channel-sender)
   (uint32 ws)
   (uint32 max-packet-size)))

(define-parsepair channel-open-failure
  ((uint32 cid)
   (uint32 reason)
   (string description) ;; ISO-10646 UTF-8 [RFC3629]
   (string language)))  ;; RFC3066

(define-parsepair channel-window-adjust
  ((uint32 cid)
   (uint32 increment))) ;; bytes to add

(define-parsepair channel-data
  ((uint32 cid)
   (string data)))

(define-parsepair channel-extended-data
  ((uint32 cid)
   (uint32 data-type) ;; 1 for stderr
   (string data)))

(define-parsepair channel-eof
  ((uint32 cid)))

(define-parsepair channel-close
  ((uint32 cid)))

;; see https://tools.ietf.org/html/rfc4254#section-6.2
(define-parsepair channel-request
  ((uint32 cid)
   (symbol request-type)
   (boolean want-reply?)
   (cond [(eq? request-type 'pty-req)
          (string term)
          (uint32 width/characters)
          (uint32 height/rows)
          (uint32 width/pixels)
          (uint32 height/pixels)
          (string modes)]

         ;; TODO: x11-req
         [(eq? request-type 'env)
          (string name)
          (string value)]

         [(eq? request-type 'shell)]

         [(eq? request-type 'exec)
          (string command)]

         [(eq? request-type 'subsystem)
          (string name)]

         [(eq? request-type 'window-change)
          (uint32 width)
          (uint32 height)
          (uint32 width/pixels)
          (uint32 height/pixels)]

         [(eq? request-type 'xon-xoff)
          (boolean client-can-do)]

         [(eq? request-type 'signal)
          (symbol name)] ;; without "SIG" prefix

         [(eq? request-type 'exit-status)
          (uint32 status)]

         [(eq? request-type 'exit-signal)
          ;; valid signal names: ABRT ALRM FPE HUP ILL
          ;; INT KILL PIPE QUIT SEGV TERM USR1 USR2
          ;; + local ones with an @-sign
          (symbol name) ;; without the "SIG" prefix
          (boolean core-dumped?)
          (string  error-message) ;; ISO-10646 UTF-8 encoding
          (string  language)]     ;; RFC3066

         [(eq? request-type 'tcpip-forward)
          (string address) ;; (e.g., "0.0.0.0")
          (uint32 port)]

         [#t ;; OBS: any guarantees that we can read until eof?
          ;;(string anything)
          ])))

(define-parsepair channel-success
  ((uint32 cid)))

(define-parsepair channel-failure
  ((uint32 cid)))

;; (parse-channel-eof "`\x00\x00\x00\x01")
;; (parse-channel-close "a\x00\x00\x00\x01")
;; (parse-channel-data "^\x00\x00\x00\x01\x00\x00\x00\rawdofihawofh\n")


