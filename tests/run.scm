(use test ssh base64)

(test `(channel-open "session" 1 2 3)
      (parse-channel-open "Z\x00\x00\x00\asession\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00\x00\x03"))

(test `(channel-request 1 exec #t "test")
      (parse-channel-request "b\x00\x00\x00\x01\x00\x00\x00\x04exec\x01\x00\x00\x00\x04test"))

(test `(userauth-request "tst" "ssh-connection" none)
      (parse-userauth-request "2\x00\x00\x00\x03tst\x00\x00\x00\x0essh-connection\x00\x00\x00\x04none"))
(test
 "publickey (no signature)"
 `(userauth-request "tst" "ssh-connection" publickey #f ssh-ed25519
                    ,(blob->string #${0000000b7373682d656432353531390000002087c22ef3cd
                                      43b130429c2f30d364338257ee2c8a152ae4116d2fae3c16
                                      53adc8}))
 (parse-userauth-request
  "2\x00\x00\x00\x03tst\x00\x00\x00\x0essh-connection\x00\x00\x00\tpublickey\x00\x00\x00\x00\vssh-ed25519\x00\x00\x003\x00\x00\x00\vssh-ed25519\x00\x00\x00 \207\302.\363\315C\2610B\234/0\323d3\202W\356,\212\x15*\344\x11m/\256<\x16S\255\310"))

(test
 "publickey (with signature)"
 `(userauth-request "heisann" "ssh-connection" publickey #t ssh-ed25519
                    "\x00\x00\x00\vssh-ed25519\x00\x00\x00 \207\302.\363\315C\2610B\234/0\323d3\202W\356,\212\x15*\344\x11m/\256<\x16S\255\310"
                    "\x00\x00\x00\vssh-ed25519\x00\x00\x00@\3009\200i\x1a\244\271?J\372\346\"NB\217\242\265\254\232\257\360R\374B\x1a\356d\230\236\x19\2469~Y\x0e\315e\353\321\357\376|\354\x0f\354\331q\353Kz\327 64\265m\245\230\363=?\352\304\x00")

 (parse-userauth-request
  (blob->string #${320000000768656973616e6e0000000e7373682d636f6e6e656374696f6e0000
                   00097075626c69636b6579010000000b7373682d656432353531390000003300
                   00000b7373682d656432353531390000002087c22ef3cd43b130429c2f30d364
                   338257ee2c8a152ae4116d2fae3c1653adc8000000530000000b7373682d6564
                   323535313900000040c03980691aa4b93f4afae6224e428fa2b5ac9aaff052fc
                   421aee64989e19a6397e590ecd65ebd1effe7cec0fecd971eb4b7ad7203634b5
                   6da598f33d3feac400})))

(test
 "userauth-request password"
 `(userauth-request "tst" "ssh-connection" password #f "3777")
 (parse-userauth-request "2\x00\x00\x00\x03tst\x00\x00\x00\x0essh-connection\x00\x00\x00\bpassword\x00\x00\x00\x00\x043777"))


