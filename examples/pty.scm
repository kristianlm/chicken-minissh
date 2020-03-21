;;;
;;; this implements ansi escape sequences. you know what means? it
;;; means it is wrong. everything is wrong. this is the kind of thing
;;; that never works well everywhere, there's reason GNU readline and
;;; friends are so big. this particular implementation was born out of
;;; me pressing keys in my terminal and seeing which bytes come out on
;;; the other end. there's surprisingly little documentation on this
;;; online. I don't even know the name of the standard I'm trying to
;;; implement (VT100 or something?). Btw, it's hard to use GNU
;;; readline and friend because (I think) they need a pseudo terminal
;;; to do their work. we just want bytes to and from our ssh client
;;; (which does the pseudo-terminal part ... I think). anyway, it
;;; works for demonstration purposes it seems.
;;;
;;; oh, and it isn't really a readline implementation: I cheated and
;;; made support for editing one-liners only.
;;;
;;; this file is included from the other examples.

(import (prefix utf8 utf8.))

(define (edit-render e width #!key (op (current-output-port)) (prefix "> ") (clear "\r\x1b[K"))
  (let* ((pos (edit-pos e))
         (buf (edit-buf e))
         (len (edit-len e))
         (w (- width 1))
         (trimlen (min w len))
         (start (max 0 (min (- pos (quotient w 2))
                            (- len w))))
         (end (+ start trimlen)))
    (display (utf8.conc clear prefix
                        (utf8.substring buf start end) ;; move cursor back into position
                        (if (eq? pos len) ""
                            (utf8.conc "\x1b[" (- end (edit-pos e)) "D")))
             op)))

(define (read-keystroke #!optional (ip (current-input-port)))

  (let ((c (utf8.read-char ip)))
    (define (is? x) (eq? x c))
    (cond ((is? #\x00) 'C-space) ;;  ^A aka C-`
          ((is? #\x01) 'home) ;;  ^A
          ((is? #\x02) 'left) ;;  ^B
          ((is? #\x03) 'C-c)
          ((is? #\x04) 'delete) ;;  ?
          ((is? #\x05) 'end)    ;;  ^E
          ((is? #\x06) 'right)  ;;  ^F
          ((is? #\x07) 'alarm)
          ((is? #\x08) 'backspace)   ;;  ^H
          ((is? #\x09) 'tab)         ;;  ^H
          ((is? #\x0a) 'newline)     ;;  ^H
          ((is? #\x0b) 'deleteline)  ;;  ^K
          ((is? #\x0c) 'clearscreen) ;;  ^L
          ((is? #\x0d) 'enter) ;; aka C-m
          ((is? #\x0e) 'down) ;; C-n ^N
          ((is? #\x0f) 'C-o)
          ((is? #\x10) 'C-p)        ;; ?
          ((is? #\x11) 'C-q)        ;; ?
          ((is? #\x12) 'C-r)        ;; ?
          ((is? #\x13) 'C-s)        ;; ?
          ((is? #\x14) 'C-t)        ;; ?
          ((is? #\x15) 'C-u)        ;; ?
          ((is? #\x16) 'C-v)        ;;  ^P
          ((is? #\x17) 'deleteword) ;;  ^W
          ((is? #\x18) 'C-x)        ;;  ^W
          ((is? #\x19) 'C-y)        ;;  ^W
          ((is? #\x1a) 'C-z)        ;;  ^W
          ;; 1b escape
          ((is? #\x1c) 'C-backslash)
          ((is? #\x1d) 'C-square-bracket)
          ((is? #\x1e) '??1e)
          ((is? #\x1f) 'C-/)

          ((is? #\x1b) ;; Esc:
           (let ((seq (let loop ((c (utf8.read-char ip)))
                        ;;                ,-- combos that terminate an escape sequence
                        (cond ((or (and (char>=? c #\a)
                                        (char<=? c #\z))
                                   (and (char>=? c #\A)
                                        (char<=? c #\Z))
                                   (char=? c #\~)
                                   (char=? c #\x7f)
                                   (char=? c #\space))
                               (list c))
                              (else ;; continue escape
                               (append (list c) (loop (utf8.read-char ip))))))))
             (cond ((equal? seq '(#\f))      'forward-word)
                   ((equal? seq '(#\b))      'backward-word)
                   ((equal? seq '(#\delete)) 'backspace-word)
                   ((equal? seq '(#\d))      'delete-word)
                   ((equal? seq '(#\space))  'just-one-space)

                   ((equal? seq '(#\[ #\A)) 'up)
                   ((equal? seq '(#\[ #\B)) 'down)
                   ((equal? seq '(#\[ #\C)) 'right)
                   ((equal? seq '(#\[ #\D)) 'left)
                   ((equal? seq '(#\[ #\H)) 'home)
                   ((equal? seq '(#\[ #\F)) 'end)

                   ((equal? seq '(#\[ #\2 #\~)) 'insert)
                   ((equal? seq '(#\[ #\3 #\~)) 'delete)
                   ((equal? seq '(#\[ #\5 #\~)) 'page-up)
                   ((equal? seq '(#\[ #\6 #\~)) 'page-down)
                   (else seq))))
          (else c))))


(begin
  (define (make-edit) (vector "" 0))
  (define edit-buf (getter-with-setter (lambda (e) (vector-ref e 0))
                                       (lambda (e v) (vector-set! e 0 v) v)))
  (define edit-pos (getter-with-setter (lambda (e) (vector-ref e 1))
                                       (lambda (e v) (if (number? v) (vector-set! e 1 v) (error "bad pos" v)))))
  (define (edit-len e) (utf8.string-length (edit-buf e)))

  (define (edit-update! e proc)
    (receive (buf pos) (proc (edit-buf e) (edit-pos e))
      (when (< pos 0) (set! pos 0))
      (when (> pos (utf8.string-length buf)) (set! pos (utf8.string-length buf)))
      (set! (edit-buf e) buf)
      (set! (edit-pos e) pos)))

  (define (edit-input! e . cmds)
    (for-each
     (lambda (cmd)
       (cond ((string? cmd) (for-each (lambda (c) (edit-input! e c)) (string->list cmd)))

             ((eq? cmd #\delete) ;; aka backspace
              (edit-update! e (lambda (buf pos)
                                (values (utf8.conc (utf8.substring buf 0 (max 0 (- pos 1)))
                                                   (utf8.substring buf pos (utf8.string-length buf)))
                                        (- pos 1)))))
             ((eq? cmd 'delete) ;; as in insert, delete
              (edit-update! e (lambda (buf pos)
                                (values (utf8.conc (utf8.substring buf 0 pos)
                                                   (utf8.substring buf
                                                                   (min (utf8.string-length buf)
                                                                        (+ pos 1))
                                                                   (utf8.string-length buf)))
                                        pos))))
             ((eq? cmd #\newline)) ;; TODO
             ((eq? cmd #\return))  ;; TODO
             ((eq? cmd 'deleteline)
              (edit-update! e (lambda (buf pos) (values (utf8.substring buf 0 pos) pos))))

             ((char? cmd)
              (edit-update! e (lambda (buf pos)
                                (values (utf8.conc (utf8.substring buf 0 pos) cmd
                                                   (utf8.substring buf pos (utf8.string-length buf)))
                                        (+ pos 1)))))
             ((eq? cmd 'left ) (edit-update! e (lambda (buf x) (values buf (max 0 (- x 1))))))
             ((eq? cmd 'right) (edit-update! e (lambda (buf x) (values buf (min (edit-len e) (+ x 1))))))
             ((eq? cmd 'home)  (edit-update! e (lambda (buf x) (values buf 0))))
             ((eq? cmd 'end)   (edit-update! e (lambda (buf x) (values buf (utf8.string-length buf)))))

             ((eq? cmd 'forward-word)
              (edit-update!
               e (lambda (buf pos)
                   (values buf (or (edit-find e (lambda (b p c) (eq? c #\space)) #t)
                                   (edit-len e))))))
             ((eq? cmd 'backward-word)
              (edit-update!
               e (lambda (buf pos)
                   (values buf (or (edit-find e (lambda (b p c) (eq? c #\space)) #f)
                                   0)))))

             ((eq? cmd 'backspace-word)
              (edit-update!
               e (lambda (buf pos)
                   (let* ((eow (or (edit-find e (lambda (b p c) (eq? c #\space)) #f)
                                   (edit-len e)))
                          (wordlength (abs (- eow pos))))
                     (if (> eow pos)
                         (values (utf8.conc (utf8.substring buf 0 pos)
                                            (utf8.substring buf eow (utf8.string-length buf)))
                                 pos)
                         (values (utf8.conc (utf8.substring buf 0 eow)
                                            (utf8.substring buf pos (utf8.string-length buf)))
                                 (- pos wordlength)))))))

             ((eq? cmd 'delete-word)
              (edit-update!
               e (lambda (buf pos)
                   (let* ((eow (or (edit-find e (lambda (b p c) (eq? c #\space)) #t)
                                   (edit-len e)))
                          (wordlength (abs (- eow pos))))
                     (if (> eow pos)
                         (values (utf8.conc (utf8.substring buf 0 pos)
                                            (utf8.substring buf eow (utf8.string-length buf)))
                                 pos)
                         (values (utf8.conc (utf8.substring buf 0 eow)
                                            (utf8.substring buf pos (utf8.string-length buf)))
                                 (- pos wordlength)))))))))
     cmds)
    e)

  (define (edit-print e)
    (let ((buf (edit-buf e))
          (len (edit-len e)))
      (let loop ((pos 0))
        (when (< pos len)
          (when (= pos (edit-pos e)) (display "\x1b[45m")) ;; bg @ cursor
          (display (utf8.string-ref buf pos))
          (when (= pos (edit-pos e)) (display "\x1b[0m"))
          (loop (+ pos 1))))
      (if (= (edit-pos e) len) (display "\x1b[45m \x1b[0m"))
      (print "   ;; pos=" (edit-pos e))))

  (define e (make-edit))
  (edit-input! e "1111111111 2222222222 3333333333 4444444444 5555555555 6666666666 7777777777 8888888888")
  ;;(edit-input! e 'left 'left 'left 'left 'left 'left 'left 'left 'left)
  ;;(edit-print e)
  ;;(edit-input! e 'delete-word)
  ;;(edit-print e)

  ;; TODO: make this not completely messy
  (define (edit-find e pred right?)
    (let* ((buf (edit-buf e))
           (len (edit-len e))
           (∂   (if right? 1 -1)))

      (define (termination) (if right? len 0))

      ;; `next` char when going backwards is at (- pos 1))
      (define (traverse start proc eof)
        (let loop ((pos start))
          (let ((spot (if right? pos (- pos 1))))
            (if (and (< spot len) (>= spot 0))
                (if (proc buf spot)
                    pos
                    (loop (+ pos ∂)))
                (eof)))))

      (let* ((pos (edit-pos e))
             (start (traverse pos (lambda (buf pos) (not (pred buf pos (utf8.string-ref buf pos))))
                              termination)))
        (traverse start (lambda (buf pos) (pred buf pos (utf8.string-ref buf pos))) termination))))

  (edit-find e (lambda (b p c) (eq? c #\space)) #f))

;; handle edits, refresh to output port when needed
(define (make-pty-readline-port #!key
                                (ip (current-input-port))
                                (op (current-output-port))
                                (edit (make-edit))
                                (prefix "> ")
                                (width (lambda () 60))
                                (done (lambda (e) (display "\r\n" op)))
                                (update (lambda (e) (edit-render e (width) op: op prefix: prefix)))
                                (handle (lambda (e cmd) #f)))
  (define line "")
  (define (read-line)
    (let loop ()
      (let ((cmd (read-keystroke ip)))
        (if (eof-object? cmd)
            (done edit)
            (let ((body (edit-buf edit)))
              (if (handle e cmd)
                  (loop)
                  (if (eq? cmd 'enter)
                      (begin (set! (edit-buf edit) "")
                             (set! (edit-pos edit) 0)
                             (done edit)
                             (utf8.conc body "\n"))
                      (begin (edit-input! edit cmd)
                             (update edit)
                             (loop)))))))))

  (let ((buffer "") (pos 0)) ;; buffer is #f for #!eof
    (make-input-port
     (lambda () ;; read
       (let loop ()
         (if (>= pos (string-length buffer))
             (let ((line (read-line)))
               (if (eof-object? line)
                   line
                   (begin
                     (set! buffer line)
                     (set! pos 0)
                     (loop))))
             (let ((c (string-ref buffer pos)))
               (set! pos (+ 1 pos))
               c))))
     (lambda () (char-ready? ip))         ;; ready?
     (lambda () (close-input-port ip))))) ;; close

(import (only chicken.irregex irregex-replace/all))
;;(irregex-replace/all `(: ($ (~ "b")) "b") "ababab abba" "" "B")
(define (make-pty-output-port #!optional (op (current-output-port)))
  (make-output-port
   (lambda (str) ;; display
     (display (irregex-replace/all "\n" str "\r\n") op))
   (lambda () (close-output-port op))))
