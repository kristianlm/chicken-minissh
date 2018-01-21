;; include me from within ssh.scm

(define (parse/check byte expected)
  (assert (symbol? expected))
  (unless (eq? expected (payload-type->int 'channel-open))
    (error (conc "expected " payload-type ", got ") expected)))

(define-syntax make-parser/values
  (syntax-rules ()
    ((_ ) '())
    ((_ (name exp) rest ...)
     (let ((value exp))
       (cons value (make-parser/values rest ...))))))
;; (make-parser/values (a (begin (print 1) 1)) (b (begin (print 2) 2)))

(define (parse-kexdh-reply payload)
  (wifs
   payload
   (make-parser/values
    (payload-type (read-payload-type expect: 'kexdh-reply))
    (ssh-hostkey-pk (read-signpk))
    (serverpk       (read-buflen))
    (signature      (read-signpk)))))

(define (parse-disconnect payload)
  (wifs
   payload
   (make-parser/values
    (payload-type (read-payload-type expect: 'disconnect))
    (reason-code (read-u32))
    (description (read-buflen))
    (language (read-buflen)))))

(define (parse-service-request payload)
  (wifs
   payload
   (make-parser/values
    (payload-type (read-payload-type expect: 'service-request))
    (name (read-buflen)))))

(define (parse-channel-open payload)
  (wifs
   payload
   (make-parser/values
    (payload-type (read-payload-type expect: 'channel-open))
    (channel-type (read-buflen))
    (sender-channel (read-u32))
    (window-size (read-u32))
    (max-packet-size (read-u32)))))

;; see https://tools.ietf.org/html/rfc4254#section-6.5
(define (parse-channel-request payload)
  (wifs
   payload
   (let* ((payload-type (read-payload-type expect: 'channel-request))
          (cid (read-u32))
          (request-type (string->symbol (read-buflen)))
          (want-reply (if (= 0 (read-byte)) #f #t)))
     `(,payload-type
       ,cid ,request-type ,want-reply
       ,@(case request-type
           ((shell) '())
           ((exec)
            (make-parser/values
             (command (read-buflen))))
           ((subsystem) (make-parser/values (name (read-buflen))))
           ((env)
            (make-parser/values
             (name (read-buflen))
             (value (read-buflen))))
           ((pty-req)
            (make-parser/values
             (term             (read-buflen))
             (width/characters (read-u32))
             (height/rows      (read-u32))
             (width/pixels     (read-u32))
             (height/pixels    (read-u32))
             (modes            (read-buflen))))
           (else (list (read-string #f))))))))

(define (parse-userauth-request payload)
  (wifs
   payload
   (let* ((payload-type (read-payload-type expect: 'userauth-request))
          (user    (read-buflen))
          (service (read-buflen))
          (method  (string->symbol (read-buflen))))
     `(,payload-type
       ,user ,service ,method
       ,@(case method
           ((none) '())
           ((publickey)
            (let ((signature? (if (= 0 (read-byte)) #f #t)))
              `(,signature?
                ,@(make-parser/values
                   (algorithm (string->symbol (read-buflen)))
                   (blob (read-buflen)))
                ,@(if signature?
                      (make-parser/values
                       (signature (read-buflen)))
                      '()))))
           ((password)
            (let ((changereq? (if (= 0 (read-byte)) #f #t)))
              `(,changereq?
                ,@(if changereq?
                      (make-parser/values
                       (password-old (read-buflen))
                       (password-new (read-buflen)))
                      (make-parser/values
                       (password (read-buflen)))))))
           (else (list (read-string #f))))))))

(define (parse-channel-data payload)
  (wifs
   payload
   (make-parser/values
    (payload-type (read-payload-type expect: 'channel-data))
    (cid (read-u32))
    (data (read-buflen)))))

(define (parse-channel-eof payload)
  (wifs
   payload
   (make-parser/values
    (payload-type (read-payload-type expect: 'channel-eof))
    (cid (read-u32)))))

(define (parse-channel-close payload)
  (wifs
   payload
   (make-parser/values
    (payload-type (read-payload-type expect: 'channel-close))
    (cid (read-u32)))))

;; (parse-channel-eof "`\x00\x00\x00\x01")
;; (parse-channel-close "a\x00\x00\x00\x01")
;; (parse-channel-data "^\x00\x00\x00\x01\x00\x00\x00\rawdofihawofh\n")


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
