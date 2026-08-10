# rnsh — Reticulum remote shell (client + server)

**rnsh** is a remote shell over [Reticulum](https://reticulum.network), in one
straddle with two halves. The **server** advertises an `rnsh` destination on the
mesh, accepts an incoming reliable **Channel**, and bridges it to the device's
`cli` with the **admin-password login gate forced on**. The **client** — the
`rnsh <dest_hash>` CLI command — dials a remote node's `rnsh` destination and
relays an interactive terminal session over the same Channel.

It is the mesh-native analogue of [sshd](../sshd): where sshd carries the CLI
over TCP+SSH, rnsh carries it over a Reticulum Link. Because the Link is already
end-to-end encrypted and cryptographically authenticated by Reticulum, rnsh
implements **no crypto of its own** — its only security job is the
application-level admin-password gate. The remote's `stdout` and `stderr` arrive
**collapsed into one stream**, because the device `cli` is a single output
channel to begin with.

A device can run either half, both, or neither. The server admits no one until
an admin password is set and `s.rnsh.server.enabled` is on (default **off** — it
exposes the device CLI to the mesh). The client costs nothing until the first
outbound `rnsh`.

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
   `ExecuteCommand`) and opens a `cli` backend **with `cli_connect_t.login = 1`**,
   relaying the remote's `stdin` stream to it and the cli's output back as
   `stdout`. Identity is accepted from anyone (the password gate is the auth), so
   a stock client's identify is honoured but never required.

The login gate is enforced entirely inside `cli` (server-side): the remote sees
`Enter admin password:` and every byte it sends is consumed by the password
check — echoed as `*` — until `authLogin(pw, "admin")` succeeds. **No command
runs before then**, and three wrong tries drop the session. A client that
reaches the Channel cannot bypass it. After a successful login the session is an
ordinary interactive device CLI.

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
| `s.rnsh.server.color` | `0` | Pass `CLI_COLOR`/`CLI_NO_COLOR` to the cli backend (off → clean text for a scripted client). |
| `s.rnsh.server.announce_interval` | `1800` | Seconds between destination announces (`0` treated as default). |
| `secrets.rnsh.identity` | (generated when first enabled) | 128-hex private key of the server's `rnsh` destination identity. |
| `rnsh.server.dest` | (published) | Runtime: the server's 16-byte destination hash (hex) — hand this to a client. Empty when the server is off. |

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

`rnshd [enable|disable|a[nnounce]]` is the operator front-end: no argument prints
`disabled` or `enabled: <hash>`; `enable`/`disable` are shortcuts for
`set s.rnsh.server.enabled=…`; `announce` re-announces the destination now
(otherwise it announces every `s.rnsh.server.announce_interval` seconds).

A remote node then runs `rnsh <that_hash>`, is prompted for the admin password,
and gets an interactive device CLI.

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
identifies with the device's rnsh identity, so a stock listener that gates on
allowed identities (`-a <hash>`) can admit it. Type **`..!`** at the start of a
line to disconnect (the same escape as the ssh client). It runs as a normal CLI
command, so it works over serial, the browser terminal, or a nested `spangap
cli` session.

There is no client-side configuration or key — the remote authenticates you via
its own admin-password gate.

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

The server contributes a generated settings pane (Settings → Remote shell) from
this straddle's `settings:` block — the enable switch, server color, announce
interval, and the read-only server address. There is no hand-written Vue panel
and no browser UI for the client.

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
