;; many re-exports from minissh.core
(module minissh (ssh-keygen ;; util
                 ;; server
                 ssh-server-start userauth-accept channel-accept
                 ;; client
                 ssh-connect userauth-password userauth-publickey
                 channel-open channel-exec
                 ;; channel properties
                 channel-command channel-terminal channel-terminal-width channel-terminal-height
                 ;; channel io
                 channel-read channel-write channel-eof channel-close
                 channel-input-port channel-output-port channel-error-port
                 with-channel-ports with-channel-ports*
                 ;; kex
                 kexinit-start
                 ;; accessors
                 ssh-ip ssh-op ssh-user ssh-user-pk
                 ;; log
                 ssh-log ssh-log? ssh-log-payload?)
(import scheme
        (chicken base)
        (chicken foreign))
(import minissh.core)
(include "minissh-channels.scm"))
