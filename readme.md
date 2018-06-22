  [CHICKEN]: http://call-cc.org
  [OpenSSH]: https://www.openssh.com/
  [curve25519-sha256@libssh.org]: https://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/PROTOCOL.chacha20poly1305?annotate=HEAD
  [ssh-ed25519]: https://tools.ietf.org/html/draft-ietf-curdle-ssh-ed25519-ed448-00
  [chacha20-poly1305@openssh.com]: https://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/PROTOCOL.chacha20poly1305?annotate=HEAD

# SSH for CHICKEN

A SSH-2 server and client implementation for [CHICKEN] Scheme. It
supports a limited suite of ciphers. Not enough to be standards
compliant, but enough to work with [OpenSSH] versions [6.5 and
above](https://www.openssh.com/txt/release-6.5) from 2013.

`minissh` is intended to be compliant with [OpenSSH] and itself.

## Compatibility

`minissh` servers will only accept [ssh-ed25519] user keys, so
[OpenSSH] clients will have to do `ssh-keygen -t ed25519`.

`minissh` clients will only work with servers which have [ssh-ed25519]
host-keys. These are generated on recent versions of [OpenSSH] by
default. If you run into trouble, check for something like
`/etc/ssh/ssh_host_ed25519_key.pub`.

### [SSH Transport Layer](https://tools.ietf.org/html/rfc4253)

The SSH-2 transport layer provides a packet-based channel over which
packets (and their length) is encrypted and where the server
(accepting tcp connections) is authenticated. Clients (initiating tcp
connections) are authenticated in a separate layer
(`userauth-publickey` and `userauth-password`). The other SSH layers
sit on top of the transport layer.

The SSH-2 procotol supports a negotiating a large veriety of
ciphers. `minissh` only supports a single selection of these:

- kex algorithms:                  [curve25519-sha256@libssh.org]
- user authentication:             [ssh-ed25519]
- server host key algorithms:      [ssh-ed25519]
- encryption algorithms:           [chacha20-poly1305@openssh.com]
- mac algorithms:                  only implicitly through chacha20-poly1305
- compression:                     none

Note that `minissh` is missing support for a lot of "REQUIRED" ciphers
and may not work on many SSH implementations.

# API

All calls uses blocking semantics and should be thread-safe.

## Key API

    [procedure] (ssh-keygen type)

Mimics OpenSSH's `ssh-keygen -t ed25519`. `type` must be
`'ed25519`. Returns two values: public key as a base64 encoded string
and a secret key as a blob. Users of this egg is responsible for
handling the secret key with the right amount of precaution.

The public key is encoded the same way as [OpenSSH]'s public
keys. This should make it simple to move things around between
`minissh`, `~/.ssh/known_hosts` and `~/.ssh/authorized_keys`. See
`examples/client-publickey.scm`.

## Client API

    [procedure] (ssh-connect host port verifier)

Connects to a SSH server on `host:port`. `verifier` is called with the
the server's public key and must return `#f` if the host is not
recognized.

`ssh-connect` returns an `ssh` client session which provides an
encrypted, packet-based transport layer to an authenticated server.

Following SSH-2 procedures, the client must initiate user
authentication next using the procedures below.

    [procedure] (userauth-publickey ssh user pk sk)

Tries to log in to `ssh` using the public key (base64 string) and
secret key (blob) provided. Returns `#t` on successful login, `#f`
otherwise.

It is an error to call this when `(ssh-user ssh)` is already set.

    [procedure] (userauth-password ssh user password)

Tries to log in to `ssh` using the username and password provided. The
password is not sent in cleartext. It is the user's responsibility to
treat `password` with the right amount of precaution.

It is an error to call this when `(ssh-user ssh)` is already set.

## Server API

    [procedure] (ssh-server public-key secret-key handler #!key (port 22022))

Listens on tcp port `port` and, for each incoming connection,
establishes an SSH session by authenticating itself using `public-key`
(blob) and `secret-key` (blob) then calls `(handler ssh)` in a new
srfi-18 thread, where `ssh` is an encrypted SSH server session.

Following SSH-2 procedures, the server awaits user
authentication. Therefore, the first thing `handler` does is typically
to call `userauth-accept`.

    [procedure] (userauth-accept ssh #!key publickey password banner)

Authenticate the user incoming authentication request. The callbacks
are as follows.

- `publickey: (lambda (user type pk signed?) ...)` Allow public key
  logins and deny access to users where this procedure returns
  `#f`. Grant access otherwise. To save CPU power, servers may ask if
  `pk` would be allowed before generating the actual signature. So
  this procedure may be called where `signed?` is `#f` before being
  called again where `signed?` is `#t`.
- `password: (lambda (user password) ...)` Allow password login and
  deny access to users where this procedure returns `#f`. Grant access
  otherwise. `users` is string. `password` is the plaintext password
  string.
- `banner: (lambda (user granted? pk) ...)` Called when granting or
  denying `user` access as `granted?` indicates with `#t` or
  `#f`. Must returns a string or `#f` for no banner. Note that clients
  may not display banners in the terminal. `pk` is the public key of
  the user for publickey login attempts or `#f` for password login
  attempts. The banner string should return a trailing newline.

Each callback may be called multiple times. Either `publickey`,
`password` or both must be supplied.

## Channel API

### Creating channels

    [procedure] (channel-accept ssh)

Typically run by SSH servers. Blocks until the remote side requests to
open a session channel to run a command. Returns a ssh channel object
for the new channel.

    [procedure] (channel-exec ssh cmd)

Typically run by SSH clients. Requests to open a session channel and
run command `cmd`. If remote side replies with success, returns a ssh
`channel` object. If remote side replies with failure, throws an
error.

### Working with channels

    [procedure] (channel-command channel)

Return the command string for `channel`. As in `ssh -p 22022 localhost
"command string"` or `(channel-exec ssh "command string")`. For
interactive shell sessions, this returns `#f`.

    [procedure] (channel-read channel)

Read the next data packet from `channel`. Returns two values:

- the data as a string
- the [data type code](https://tools.ietf.org/html/rfc4254#section-5.2)
  which is `#f` for normal data and a fixnum for extended data packets
  where 1 represents stderr.

The remote window size size is adjusted to stay between 1-2 MiB.

    [procedure] (channel-write channel str #!optional extended)

Sends a SSH data packet with `str` to `channel`. This respects the
SSH-2 channel window size limitations and may therefore block waiting
for window size adjustments. `extended` may be supplied as `'stderr`
or a fixnum for extended data packets.

    [procedure] (channel-eof channel)

Sends an SSH eof packet to `channel`. This indicates that no more data
will be sent, often resulting in the remote end initiating to
close. Incoming data is unaffected.

    [procedure] (channel-close channel)

Closes `channel` and also sends an SSH close packet unless `channel`
is already closed. It is an error to call `channel-write` on a channel
which is closed.

    [procedure] (channel-input-port channel)
    [procedure] (channel-output-port channel)
    [procedure] (channel-error-port channel)
    [procedure] (with-channel-ports channel thunk)
    [procedure] (with-channel-ports* channel thunk)

Wrap channel calls into ports. `channel-input-port` does
`(channel-read channel)` and ignores the extended data index, so it
cannot distinguish between `stdout` and
`stderr`. `channel-output-port` does `(channel-write channel str)` and
`channel-error-port` does `(channel-write ch 'stderr)`.

`with-channel-ports` calls `thunk` with `current-input-port` and
`current-output-port` bound to `channels`'s
ports. `with-channel-ports*` also wraps `current-error-port`. This may
sometimes cause problems as runtime errors are printed onto
`channels`'s stderr.

## Key exchange API

    [procedure] (kexinit-start ssh)
    
Explicitly demand renegotiation of keys. This blocks other senders
until the key exchange process is complete. [OpenSSH] clients will
initiate this after 1GiB of data.

## Logging API

    [parameter] (ssh-log? #t)
    [parameter] (ssh-log-payload? #f)

Tune logging verbosity with these parameters. Default values are shown
above. `(ssh-log? #f)` shuts off logging completely.
`(ssh-log-payload? #t)` turns on logging on parsed packet content
which may be useful during SSH debugging.

# Notes

## Configuring [OpenSSH] with `ControlMaster`

The SSH-2 protocol allows multiplexing multiple channels over a single
TCP connection. This means multiple programs may be started with a
single login. See the
[`ControlMaster`](https://man.openbsd.org/ssh_config#ControlMaster)
ssh config option for how to apply this in your OpenSSH client.

## Server vs Client channels

The SSH-2 protocol does not dictate that only servers should accept
new channels. However,
[RFC4254](https://tools.ietf.org/html/rfc4254#section-6.1) says:

> Client implementations SHOULD reject any session channel open
> requests to make it more difficult for a corrupt server to attack
> the client.

`minissh` supports client that call `channel-accept` and servers that
call `channel-exec`, though this is unconventional.

# TODO

## fix known bug: will never initiate key negitiation

[RFC4253s9](https://tools.ietf.org/html/rfc4253#section-9) says:

> It is RECOMMENDED that the keys be changed after each gigabyte of
> transmitted data or after each hour of connection time, whichever
> comes sooner.  However, since the re-exchange is a public key
> operation, it requires a fair amount of processing power and should
> not be performed too often.

minissh will currently never initiate a key exchange (but will respond
correctly to when the remote side initiates). You can call
`kexinit-start` to explicitly renegotiate keys.

## plus these things

- benchmark: faster read-string! based channel-input-port
- transport: allow querying current encryption level
- channels: pty handling?
- channels: do some buffering (don't send 1-byte SSH packets)
- find a faster current-entropy-port
- reply with unimplemented when receiving unhandled messages
