(module minissh *
(import scheme
        (chicken base)
        (chicken foreign))
(include "chacha20.scm")
(include "minissh.scm"))
