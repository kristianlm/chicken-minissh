(cond-expand
 (chicken-5
  (import (only srfi-18 make-condition-variable condition-variable-broadcast!
                mutex-unlock! mutex-lock!)))
 (else
  (use (only srfi-18 make-condition-variable condition-variable-broadcast!
             mutex-unlock! mutex-lock!))))
;;; one at a time
;;; included by channels-gochan.scm
;;;
;;; allows processing of a "next" item from multiple threads. only one
;;; thread will execute thunk at a time, but all threads will wait for
;;; thunk to complete. this is useful to handle the next incoming
;;; packet: only one thread does the read while the others wait for
;;; handlers to complete.
;;;
;;; sorry about the name...

(define-record-type <oaat>
  (%make-oaat working? mutex cv)
  oaat?
  (working? %oaat-working? %oaat-working?-set!)
  (mutex    %oaat-mutex)
  (cv       %oaat-cv))

(define (make-oaat) (%make-oaat #f (make-mutex) (make-condition-variable)))

(define (oaat ot thunk)
  (mutex-lock! (%oaat-mutex ot))
  (if (%oaat-working? ot)
      (begin ;; they're doing the work, wait for their signal
        (mutex-unlock! (%oaat-mutex ot) (%oaat-cv ot)))
      (begin ;; we're doing the work, signal others
        (%oaat-working?-set! ot #t)
        (mutex-unlock! (%oaat-mutex ot))
        (let ((r (thunk)))
          (mutex-lock! (%oaat-mutex ot))
          (%oaat-working?-set! ot #f)
          (condition-variable-broadcast! (%oaat-cv ot))
          (mutex-unlock! (%oaat-mutex ot))
          r))))

