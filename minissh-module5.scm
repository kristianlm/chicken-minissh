(module minissh *
(import scheme
        (chicken base)
        (chicken foreign))
(import minissh.core)
(include "minissh-channels.scm"))
