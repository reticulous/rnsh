# rnsh — Reticulum remote shell (client + server)

**rnsh** is a remote shell over [Reticulum](https://reticulum.network), in one
straddle with two halves. The **server** advertises an `rnsh` destination on the
mesh, accepts an incoming reliable **Channel**, and bridges it to the device's
`cli` behind the **admin-password login gate**. The **client** — the
`rnsh <dest_hash>` CLI command — dials a remote node's `rnsh` destination and
relays an interactive terminal session over the same Channel.

It is the mesh-native analogue of [sshd](../sshd): where sshd carries the CLI
over TCP+SSH, rnsh carries it over a Reticulum Link. Because the Link is already
end-to-end encrypted and cryptographically authenticated by Reticulum, rnsh
implements **no crypto of its own** — its only security job is deciding who is
admitted. The remote's `stdout` and `stderr` arrive **collapsed into one
stream**, because the device `cli` is a single output channel to begin with.

A device can run either half, both, or neither. The server is off by default
(`s.rnsh.server.enabled` — it exposes the device CLI to the mesh). The client
costs nothing until the first outbound `rnsh`.

## Who gets in

Admission is decided once per session, from the Reticulum identity the peer
identified with — Reticulum itself proves that identity, so the check is a hash
comparison and nothing more:

| the peer's identity | `s.rnsh.server.password` on (default) | off |
| --- | --- | --- |
| listed in `s.rnsh.server.allowed` | in, no password | in, no password |
| anything else, or unidentified | admin-password prompt | refused at connect |

So the list is the *bypass*, not the gate: `rnshd allow <32-hex identity>` is how
a node you own stops having to type the password, and `rnshd password off` is
how a node stops accepting passwords at all — after which the list is the only
way in, and an empty list means nobody. A peer that never identified is never on
the list, whatever it claims in-band.

## Origins

rnsh rides entirely on the Channel primitive that [rns](../rns) added to its
microReticulum fork (`rnsdChannelOpen` / `rnsdDestListenChannels`, see
[rns/INTERNALS.md §5.6](../rns/INTERNALS.md)) and the `cli` login gate that
[spangap-core](../spangap-core) added (`cli_connect_t.login`). This straddle is
the wiring that connects the two: a session pump between an accepted Channel and
a login-gated `cli` backend, plus the client relay command. On the wire it
speaks the **upstream (acehoss) rnsh protocol** (version 1), so both halves
interoperate with the stock `rnsh` tool in both directions — our server accepts
a stock client, and our client drives a stock listener.

---

# The rnsh server

When enabled, the server:

1. loads/creates its identity (`secrets.rnsh.identity`) and hosts a
   `Destination(IN, SINGLE, "rnsh")`, announcing it periodically;
2. registers for inbound Channels on that destination
   (`rnsdDestListenChannels`);
3. runs the upstream listener handshake per Channel (version exchange, then an
   `ExecuteCommand`) and opens a `cli` backend, relaying the remote's `stdin`
   stream to it and the cli's output back as `stdout`. The `ExecuteCommand` is
   where admission is settled (see "Who gets in"): a listed identity gets the
   backend with `cli_connect_t.login = 0`, anyone else with `login = 1` — or an
   `ErrorMessage` and a closed Channel, where password login is off.

The login gate is enforced entirely inside `cli` (server-side): the remote sees
`Enter admin password:` and every byte it sends is consumed by the password
check — echoed as `*` — until `authLogin(pw, "admin")` succeeds. **No command
runs before then**, and three wrong tries drop the session. A client that
reaches the Channel cannot bypass it. After a successful login the session is an
ordinary interactive device CLI.

Who the peer is comes from Reticulum, not from anything the session says: the
initiator identifies over the Link and microReticulum verifies the signature, so
rnsh only ever compares the resulting 16-byte identity hash against the list.

### Colour

The server does not have to guess whether colour is welcome — the peer says so.
`ExecuteCommand` carries the client's own view of its end of the session, and
upstream fills it from real file descriptors rather than from config:
`pipe_stdout` is `not os.isatty(1)`, `term` is its `$TERM`, and `cmdline` is
whatever was typed after `--`. So:

**colour = `s.rnsh.server.color` is on, AND no command was named, AND `stdout`
is a terminal, AND `$TERM` is neither empty, `dumb`, nor `-mono`.**

Turning the switch on therefore cannot spray escapes into
`rnsh <hash> -- some-command > log.txt`; the switch says what you would like, and
the session says what is possible. A payload we cannot parse counts as the least
capable peer. Our own client declares itself the same way: it sends
`term=xterm` only when the local CLI slot is an interactive colour terminal, and
`term=xterm-mono` otherwise — which withdraws colour without pretending to be no
terminal at all, so a stock listener still gives you a working PTY.

Up to **two** sessions run concurrently. The server hosts exactly one
destination and one small session pump — it is not a general service host.

### Storage (server)

`s.rnsh.server.*` is user/browser-writable configuration; `secrets.rnsh.identity`
is device-local and never synced. The admin password is **not** an rnsh secret —
it lives in spangap-core's `auth` `admin` realm (shared with the web and ssh
login flows).

| Key | Default | Purpose |
| --- | --- | --- |
| `s.rnsh.server.enabled` | `0` | Master switch. Live (no reboot) — the server task reconciles within ~1 s, opening/closing the hosted destination. Owned by this straddle's `settings:` block. |
| `s.rnsh.server.color` | `0` | Show ANSI colors. A preference, not a decision: colour is sent only if this is on **and** the peer's `ExecuteCommand` says it is an interactive colour terminal (see "Colour"). |
| `s.rnsh.server.password` | `1` | Whether an unlisted peer may log in with the admin password. `0` refuses one at `ExecuteCommand`, so `s.rnsh.server.allowed` becomes the only way in. |
| `s.rnsh.server.allowed[]` | `[]` | One object per passwordless identity: `{ id, hash, label }`. `hash` is the 32-hex identity hash; `label` is the finished row text (the comment, or the hash). |
| `secrets.rnsh.identity` | (generated when first enabled) | 128-hex private key of the server's `rnsh` destination identity — and the identity our client identifies with. |
| `rnsh.server.dest` | (published) | Runtime: the server's 16-byte destination hash (hex) — hand this to a client. Empty when the server is off. |
| `rnsh.identity` | (published) | Runtime: our own 16-byte identity hash (hex) — hand this to a remote node's `rnshd allow`. |

### Setup

Include the straddle in a build (it requires [rns](../rns)):

```
spangap build reticulous/reticulous --with spangap/hw-lilygo-tdeck --with reticulous/rnsh
```

Then, on the device CLI (`spangap cli "…"` or the serial monitor):

```
auth passwd admin <password>     # set the admin password (once) — shared with ssh/web
rnshd enable                      # turn the server on
rnshd                             # status → 'enabled: <hash>' (the client address)
```

`rnshd` is the operator front-end. No argument prints the status block — the
server address, our own identity hash, the password policy and how many
identities are allowed:

```
rnshd                             show status
rnshd enable | disable            shortcuts for `set s.rnsh.server.enabled=…`
rnshd a[nnounce]                  re-announce the destination now
rnshd allowed                     list the identities that skip the password
rnshd allow <32-hex> [label]      let one in without a password
rnshd deny <id>                   drop one (id from `rnshd allowed`)
rnshd password [on|off]           admit unlisted peers by admin password
```

`announce` matters only for a re-announce: the destination announces once when
the server opens, and each interface decides how often that goes back on the air
— see [rns/README.md](../rns/README.md), "The announce tick".

A remote node then runs `rnsh <that_hash>`, is prompted for the admin password,
and gets an interactive device CLI. To skip that prompt, read the remote's own
identity off its `rnshd` status and allow it here:

```
rnshd allow 4e1f…c7  tdeck        # the hash `rnshd` printed as `identity:`
rnshd password off                # optional: now only allowed identities get in
```

Note that an allowed identity gets in whether or not an admin password has ever
been set — the list is checked first and the password is never consulted.

---

# The rnsh client

The client is a CLI command that opens an outbound Channel and relays your
terminal to the remote device CLI.

```
rnsh <dest_hash> [aspect]    open a remote CLI over Reticulum
                             dest_hash = 32 hex chars; aspect defaults to "rnsh"
                             type '..!' on a new line to disconnect
```

`rnsh <hash>` requests a path if needed, establishes the Channel, does the
version handshake and sends an `ExecuteCommand`, then relays: your keystrokes go
out as the `stdin` stream, the remote's `stdout`/`stderr` streams (including its
`Enter admin password:` prompt) come back and are written to your terminal. It
identifies with the device's rnsh identity, so a listener that gates on allowed
identities — a stock one's `-a <hash>`, or another spangap node's `rnshd allow`
— can admit it. Type **`..!`** at the start of a line to disconnect (the same
escape as the ssh client). It runs as a normal CLI command, so it works over
serial, the browser terminal, or a nested `spangap cli` session.

There is no client-side configuration — the remote decides whether it wants a
password from you. The one thing the client contributes is its identity hash
(`rnshd` prints it as `identity:`, and it is published at `rnsh.identity`),
which is what the far end allows to let this device in without one.

---

## Interop with the stock rnsh

Because rnsh is wire-compatible with the upstream (acehoss) `rnsh` tool, either
half can be exercised against a reference Reticulum stack (install one so `rnsh`
and `rnsd` are on PATH):

- **Reference client → device server:** `rnshd enable` on the device, note the
  hash, then `rnsh <device_hash>` on the reference host — you get the admin
  password prompt and an interactive device CLI.
- **Device client → reference listener:** run `rnsh -l -A -- /bin/bash` on the
  reference host (it prints its destination), then `rnsh <that_hash>` on the
  device.

Both directions also work device-to-device. The codec is verified byte-exact
against the reference; see [INTERNALS.md §7](INTERNALS.md) for the full test
matrix and status.

---

## Browser

The server contributes a generated settings pane (Settings → Reticulum Mesh →
Remote shell) from this straddle's `settings:` block — the enable switch, server
color, the password-login switch, the read-only server address and our own
identity, and the editor for the passwordless-identity list. The list's adds and
removes arrive as `rnsh.peer.*` command keys that `rnsh.cpp` validates and applies,
so a malformed hash comes back as a sentence, not as a UI rule. There is no
hand-written Vue panel and no browser UI for the client.

## Dependencies

- [rns](../rns) — the Channel API (`rnsdChannelOpen`,
  `rnsdDestListenChannels`, `rnsdDestOpen`) and the identity/destination
  helpers. Brings `rnsd` up first via the dependency order.
- [spangap-core](../spangap-core) (transitively) — ITS, storage, the `cli`
  service and its `login` gate, and the `auth` `admin` realm.

## What this straddle does NOT own

- The Channel primitive and the rnsd bridge — [rns](../rns).
- The `cli` service, the login gate, and the `auth` realm store —
  [spangap-core](../spangap-core).
- TCP/SSH remote shell — [sshd](../sshd).

## Read next

- [INTERNALS.md](INTERNALS.md) — the session pump, the login handoff, the
  client relay, the upstream wire protocol, and the pitfalls.
