
# SSH for CHICKEN 

This is very much work in progress.

## Supported standards

### [SSH Transport Layer](https://tools.ietf.org/html/rfc4253)

- kex algorithms:                  curve25519-sha256@libssh.org
- server host key algorithms:      ssh-ed25519
- encryption algorithms:           chacha20-poly1305@openssh.com
- mac algorithms:                  hmac-sha2-256
- compression:                     none

This is the bulk of the hard work. The result of this is an encrypted
channel where you can send and receive SSH packets. These packets are
then used by the other protocols.

## [SSH Authentication Protocol](https://tools.ietf.org/html/rfc4252)

You probably have to do most of this yourself, but it's not that hard.

## [SSH Connection Protocol](https://tools.ietf.org/html/rfc4254)

You have to do this youself.


# TODO

- everywhere: nice API
- tweetnacl: what to do with `scalarmult`?
- make a ssh client too
- transport: implement rekeying
- transport: allow querying current encryption level
- channels: respect window limits
- channels: turn into input/output ports?
- channels: pty handling?
