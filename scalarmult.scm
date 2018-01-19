(import foreign)
(foreign-declare "#include \"scalarmult-impl.c\"")

(define scalarmult-primitive   "curve25519")
(define scalarmult-bytes       32)
(define scalarmult-scalarbytes 32)

(define (scalarmult* n p)
  (unless (eqv? scalarmult-scalarbytes (blob-size n))
    (error 'scalarmult "invalid length" n))
  (unless (eqv? scalarmult-scalarbytes (blob-size p))
    (error 'scalarmult "invalid length" p))
  (let ((q (make-blob scalarmult-bytes)))
    ((foreign-lambda int "crypto_scalarmult"
                     nonnull-scheme-pointer
                     nonnull-scheme-pointer
                     nonnull-scheme-pointer)
     q n p)
    q))
