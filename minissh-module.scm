(module minissh (channels-accept
                 ;; plus some from core:
                 ssh-log? ssh-log-payload?
                 ssh-server-start
                 channels-accept ;; <-- could use a better name
                 userauth-accept userauth-publickey userauth-password
                 ssh-keygen ssh-connect

                 ssh-user ssh-user-pk ;; just for convenience

                 current-ssh-watermark/minimum current-ssh-watermark/increment
                 current-terminal-width current-terminal-height current-terminal-modes
                 current-ssh-command)

(import scheme (chicken base) (chicken foreign))
(import minissh.core)

(include "minissh-channels.scm")
)
