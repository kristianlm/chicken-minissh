
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

## fix known bug: `expected kexinit, got : "(channel-window-adjust 1 98310)"`

Caused by us not following
[this](https://tools.ietf.org/html/rfc4253#section-7.1) part of the
RFC4253 spec:

> Note, however, that during a key re-exchange, after sending a
> SSH_MSG_KEXINIT message, each party MUST be prepared to process an
> arbitrary number of messages that may be in-flight before receiving
> a SSH_MSG_KEXINIT message from the other party.

this bug only happens when minissh initiates the first kexinit (which
it never does unless you do `run-kex` manually).

- everywhere: nice API
- make a ssh client too
- transport: allow querying current encryption level
- channels: respect window limits
- channels: pty handling?
- find a faster current-entropy-port
