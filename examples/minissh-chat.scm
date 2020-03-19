;;; this example tries to demonstrate a chat over SSH. much like the
;;; ssh.chat project.
;;;
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
;;; made support for editing one-liners.
(import minissh (chicken io) gochan chicken.string srfi-18 (chicken time posix)
        chicken.file
        minissh.core chicken.condition
        matchable
        srfi-69 ;; hash-tables
        (prefix utf8 utf8.)
        )

(ssh-log-payload? #t)

(define host-pk
  "AAAAC3NzaC1lZDI1NTE5AAAAIIfd+rbtTF2hJJbnnbQxtp2UVrUWkQtnsT8CL9iLpZBZ")
(define host-sk ;; the secret key would normally be kept safe
  #${ba72291c15494ee02003b3c0bb0f8507a6a803850aa811d015b141a193e2447d
     87ddfab6ed4c5da12496e79db431b69d9456b516910b67b13f022fd88ba59059})

(define (C-c)
  (print "commands:\r
 /exit\r
 /users"))

(define (greeting)
  (print ";; Welcome to secure CHICKEN chat\r
;; Or, it might have been secure if the secret key\r
;; wasn't committed in the official repo. Everything\r
;; you send is broadcast to everyone.\r
;; Problems? <enter>`.<enter> forces ssh disconnect\r"))

(if (file-exists? ".minissh-chat.scm")
    (load         ".minissh-chat.scm"))

(print "test with: ssh localhost -p 22022 chat")

(define chan #f)
(define (width) (or (current-terminal-width) 80))

(define (edit-render e width)
  (let* ((pos (edit-pos e))
         (buf (edit-buf e))
         (len (edit-len e))
         (w (- width 1))
         (trimlen (min w len))
         (start (max 0 (min (- pos (quotient w 2))
                            (- len w))))
         (end (+ start trimlen)))
    (display (utf8.substring buf start end))
    (unless (eq? pos len) ;; move cursor back into position
      (display (utf8.conc "\x1b[" (- end (edit-pos e)) "D")))))

(define (read-cmd)

  (let ((c (utf8.read-char)))
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
           (let ((seq (let loop ((c (utf8.read-char)))
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
                               (append (list c) (loop (utf8.read-char))))))))
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
                                 (- pos wordlength)))))))

             (else (warning "unknown command" cmd))))
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

  (newline)
  (define e (make-edit))
  (edit-input! e "1111111111 2222222222 3333333333 4444444444 5555555555 6666666666 7777777777 8888888888")
  ;;(edit-input! e 'left 'left 'left 'left 'left 'left 'left 'left 'left)
  (edit-print e)
  ;;(edit-input! e 'delete-word)
  (edit-print e)

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

(define _userpks (make-hash-table))
(define userpk
  (getter-with-setter
   (lambda (user) (hash-table-ref _userpks user (lambda () #f)))
   (lambda (user pk) (hash-table-set! _userpks user pk) (userpk user))))
(define (userpks) (hash-table-keys _userpks))

(define (print-users)
  (hash-table-for-each
   _userpks
   (lambda (user pk) (print pk " " user "\r"))))

(define bc (gochan 0))
(define msgs (gochan 0))

;; this is a publish-subscribe pattern of some sort. we chain the
;; gocha's together, starting with the top-level bc (later
;; replaced). when the gochan is closed, it points to the gochan that
;; will get the next message (in the close flag). this ensures that no
;; messages get lost, and nobody misses a gochan instance in the
;; middle of the chain. GC should pick up unreferenced gochan's
;; backwards in the chain.
(define (broadcast! msg)
  (let ((chan-next (gochan 0)))
    (gochan-close bc (list chan-next msg))
    (set! bc chan-next)))

(define (print-msg user msg self?)
  (let ((color (if self? 33 34)))
    (display (conc "\r\x1b[K\x1b[32m" (time->string (seconds->local-time) "%H:%M")
                   " \x1b[" color "m" user "\x1b[0m")))
  (print " " msg))

;; keep last line (editing) nice and tidy
(define (refresh e user)
  (display "\r\x1b[K") ;; goto column 0 and clear line
  (let ((prefix (conc "[\x1b[33m" user "\x1b[0m] ")))
    (display prefix)
    (edit-render e (max 0 (- (width) (utf8.string-length prefix) -9)))))

(define (handle-chat user pk)
  (greeting)

  (define alive (gochan 0))
  (define e (make-edit))
  (define (prompt) (conc "[" user "]"))

  (thread-start!
   (lambda ()
     (let ((ceh (current-exception-handler)))
       (current-exception-handler (lambda (e) (gochan-close alive) (ceh e))))
     (call/cc
      (lambda (quit)
        (let loop ()
          (let ((cmd (read-cmd)))
            (let ((body (edit-buf e)))
              (case cmd
                ((enter)
                 (cond ((equal? body ""))
                       ((equal? body "/users")
                        (display "\r\x1b[K")
                        (print-users))
                       ((equal? body "/exit")
                        (quit #f))
                       (else
                        (broadcast! (list user body))))
                 (set! (edit-buf e) "")
                 (set! (edit-pos e) 0))
                ((C-c)
                 (print "\r\x1b[K")
                 (C-c))
                (else (edit-input! e cmd))))
            (gochan-send alive #f) ;; <-- refresh, but avoid likely print race-conditions
            (loop)))))
     (gochan-close alive)))

  (refresh e user)
  (let loop ((bc bc))
    (gochan-select
     ((bc -> _ msg)
      (match msg
        ((bc (from msg))
         (print-msg from msg (equal? user from))
         (refresh e user)
         (loop bc))))
     ((alive -> request closed?)
      ;;(if request (display))
      (refresh e user)
      (if closed?
          (broadcast! (list user 'eof))
          (loop bc))))))

(import srfi-18) (thread-start! (lambda () (import nrepl) (nrepl 1234)))
(ssh-server-start
 host-pk host-sk
 (lambda (ssh)
   (set! _ssh ssh)
   (userauth-accept ssh
                    publickey:
                    (lambda (user type pk signed?)
                      (if signed?
                          (equal? pk (or (userpk user)
                                         (set! (userpk user) pk)))
                          #t)))
   (channels-accept
    ssh (lambda ()
          ;;(error "TESTING TESTING")
          (handle-chat (ssh-user ssh) (ssh-user-pk ssh))))))
