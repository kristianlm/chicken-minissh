(import srfi-4
        (only (chicken blob) blob-size))

(foreign-declare "#include \"chacha20-impl.c\"")

(define-foreign-type chacha_ctx u32vector)

;;(define chacha (make-chacha-context))
(define (make-chacha key)
  (chacha-key! (u32vector 0 0 0 0 0 0 0 0
                          0 0 0 0 0 0 0 0
                          0 0 0 0 0 0 0 0
                          0 0 0 0 0 0 0 0)
               key))

(define (chacha-key! chacha key #!optional (bits 256))
  
  (assert (= 32 (u32vector-length chacha)))
  (assert (= 32 (blob-size key)))
  ((foreign-lambda* void
                    ((chacha_ctx chacha)
                     (nonnull-scheme-pointer k)
                     (int bits))
                    "chacha_keysetup((struct chacha_ctx*)chacha, k, bits);")
   chacha key bits)
  chacha)

(define (chacha-iv! chacha iv counter)
  (assert (= 32 (u32vector-length chacha)))
  (assert (= 8 (blob-size iv)))
  (assert (= 8 (blob-size counter)))
  ((foreign-lambda* void
                    ((chacha_ctx chacha)
                     (nonnull-scheme-pointer iv)
                     (nonnull-scheme-pointer counter))
                    "chacha_ivsetup((struct chacha_ctx*)chacha, iv, counter);")
   chacha iv counter)
  chacha)

;; TODO: export chacha-counter! setter too

(define (chacha-encrypt! chacha source)
  (assert (= 32 (u32vector-length chacha)))
  (let ((dest (make-string (string-length source))))
    ((foreign-lambda* void
                      ((chacha_ctx chacha)
                       (nonnull-scheme-pointer m)
                       (nonnull-scheme-pointer c)
                       (int len))
                      "chacha_encrypt_bytes((struct chacha_ctx*)chacha, m, c, len);")
     chacha source dest (string-length source))
    dest))
