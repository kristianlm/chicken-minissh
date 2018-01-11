;; included from core.scm

(define (parse/check byte expected)
  (assert (symbol? expected))
  (unless (eq? expected (payload-type->int 'channel-open))
    (error (conc "expected " payload-type ", got ") expected)))

(define-syntax make-parser/values
  (syntax-rules ()
    ((_ ) '())
    ((_ (name exp) rest ...)
     (let ((name exp))
       (cons name (make-parser/values rest ...))))))
;; (make-parser/values (a (begin (print 1) 1)) (b (begin (print 2) 2)))

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

(define (parse-channel-request payload)
  (wifs
   payload
   (make-parser/values
    (payload-type (read-payload-type expect: 'channel-request))
    (cid (read-u32))
    (request-type (read-buflen))
    (want-reply (read-byte))
    (rest (read-string #f)))))

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
