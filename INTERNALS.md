# rnsh — internals

The user/operator guide is [README.md](README.md). This file covers the wiring:
the server session pump, the login handoff, the client relay, and the pitfalls.

rnsh is deliberately thin. Everything hard — reliable delivery, encryption,
authentication of the transport — is done by the Channel + Link layers in
[rns](../rns). rnsh is one file (`src/rnsh.cpp`) that (a) registers the `rnsh`
client CLI command and (b) runs a server task that splices an inbound Channel to
a login-gated `cli` backend. On top of that transport it speaks the upstream
rnsh message protocol (§6) so both halves interoperate with the stock tool.

## 1. Bring-up

`RnshService::onInit()` (registered in the generated service registry) runs on
the main task after rns is up. It:

- writes storage defaults once, gated on `s.rnsh.version`;
- generates the rnsh identity (`RNSH_IDENTITY_KEY`, idempotent) so the client
  can identify and the server host under it, whichever runs first;
- registers the `rnsh` client command and the `rnshd` server-control command
  (`cliRegisterCmd`);
- spawns `rnshServerTask` (8 KB PSRAM stack, prio 3).

`rnshd [enable|disable|announce]` is a thin operator front-end on the cli task:
no arg prints `disabled` or `enabled: <hash>` (the destination hash, computed
from the rnsh identity); `enable`/`disable` just write `s.rnsh.server.enabled`
(the server task reconciles within ~1 s); `announce` sets a `volatile` request
flag the server task serves on its next loop.

The server task always exists; it stays idle until `s.rnsh.server.enabled` is
on. It is both an ITS **server** (its inbox port for forwarded Channels) and an
ITS **client** (it dials the `cli` backend).

## 2. The server session pump

The server hosts a `Destination(IN, SINGLE, "rnsh")` via `rnsdDestOpen` and
registers for inbound Channels with `rnsdDestListenChannels(dest,
RNSH_INBOX_PORT)` (port **130** — distinct from lxmf's 100/101 and clink's 120).
When a remote establishes a Link+Channel to the destination, rnsd forwards it as
a fresh ITS connection to `RNSH_INBOX_PORT` carrying an `rnsd_link_incoming_t`.

Each session is a slot in a fixed `s_sessions[RNSH_MAX_SESSIONS]` (2) array
holding `{state, inboxHandle, backendHandle}`. It runs the upstream listener
state machine (session.py's `LSState`): **WAIT_VERS → WAIT_CMD → RUNNING**. We
skip WAIT_IDENT — identity is accepted from anyone (allow-all); the password
gate (§3) is the authentication — so a client's identify is honoured but never
required.

- **`onInboxConnect`** — a Channel arrived. Allocate a slot in `WAIT_VERS`. The
  CLI backend is **not** opened yet.
- **`onInboxRecv`** (remote → session): drain framed messages and dispatch on
  the envelope msgtype (see §6):
  - `WAIT_VERS`: on `VersionInfo` reply with our own `VersionInfo`, advance to
    `WAIT_CMD`.
  - `WAIT_CMD`: on `ExecuteCommand` open the CLI backend **with the login gate
    forced on** (the payload is ignored — the device runs its one "command", the
    cli), advance to `RUNNING`:

    ```c
    cli_connect_t cc = { CLI_ANSI, /*from_usb_serial*/0, color, /*no_prompt*/0, /*login*/1 };
    itsConnect("cli", CLI_PORT_TCP, &cc, sizeof(cc), …, /*ref*/i, onBackendRecv, onBackendDisc);
    ```

    That `login = 1` is the entire authentication story — see §3.
  - `RUNNING`: a `StreamData(stdin)` frame → decompress if flagged → `itsSend`
    its bytes to the backend (the remote's password, then its keystrokes). A
    frame with the **stdin-EOF** flag (a stock client whose stdin pipe closed —
    our interactive client never sends it) closes the session: send
    `CommandExited(0)` and tear down, so a client waiting on the exit unblocks.
    `WindowSize`/`Noop` are ignored.
- **`onBackendRecv`** (CLI → remote): accumulate backend output into the
  session's `outbuf` and emit it as `StreamData(stdout)` frames — **coalesced**
  like the client's stdin but snappier (so remote echo stays responsive): a full
  chunk goes out immediately (so a big dump isn't delayed), a partial tail is
  flushed by the task loop once output goes idle for **250 ms** or **1.5 s**
  after the first pending byte, or **immediately when the buffer ends with the
  cli prompt** (`" $ "`) — a completed command's prompt appears without the idle
  delay (a false match mid-output merely sends a slightly smaller packet). This
  carries the `Enter admin password:` prompt, the `*` echoes, and all command
  output. It is **one stream**: the cli never emits a separate stderr, so
  stdout+stderr are collapsed by construction (same as sshd, which never sends
  `EXTENDED_DATA`). Pending output is flushed before `CommandExited` on teardown.
- **Teardown** — either side closing tears down the other. On backend close the
  server sends `CommandExited(0)` first. `sessClose` disconnects both handles and
  clears the slot; a re-entrant disconnect callback no-ops because the slot's
  `used` flag is already false.

The bytes are copied through PSRAM statics on the 8 KB server task (`bbuf`,
`frame`, `rxbuf`, plus a 16 KB `decomp` bound by `RawChannelWriter.MAX_CHUNK_LEN`
for compressed inbound chunks). The task loop polls at 1 Hz when idle, but drops
to 50 ms whenever a session has stdout pending, so the coalescing flush timer
fires on schedule; it also serves the `rnshd announce` request flag there.

## 3. Login handoff

rnsh does **not** call `authLogin` itself. It sets `cli_connect_t.login = 1` and
lets `cli` enforce the gate server-side (spangap-core `cli.cpp`): on a
login-required slot the CLI prints `Enter admin password:`, routes every
received byte into a masked password accumulator, verifies each completed line
against `authLogin(pw, "admin")`, and **dispatches no command until it
succeeds** (three failures drop the slot). Because enforcement lives in the cli
task and only the *result* (authed / not) gates command processing, a remote
that controls the Channel bytes cannot pipeline a command past the prompt — the
first line is always consumed as a password guess.

Centralising the gate in `cli` (rather than duplicating an `authLogin` call in
rnsh, as sshd does at its protocol layer) means there is provably no path from
an accepted Channel to a running command that skips the password.

## 4. The client relay (`cliRnsh`)

`rnsh <dest_hash> [aspect]` runs on the cli task. It:

1. parses the 32-hex destination and optional aspect (default `"rnsh"`);
2. `rnsdChannelOpen(dh, aspect, RNSH_IDENTITY_KEY, tag, …)` — the outbound
   Channel. Passing the identity key makes rnsd identify the link to the remote
   once active, so a listener gating on allowed initiator identities (upstream
   `-a <hash>`) admits us;
3. polls `rnsd.chan.<tag>.state` until `active` (up to ~70 s: a path request
   plus establishment) or `failed` (prints `last_error`); Ctrl-C aborts;
4. **handshake:** sends `VersionInfo`, waits (~15 s) for the server's
   `VersionInfo` reply, then sends one `ExecuteCommand` (default shell,
   interactive PTY — `pipe_*` false; our server ignores the payload, a stock
   server sizes its PTY from it);
5. enters the relay loop: drains inbound frames — `StreamData(stdout/stderr)` →
   decompress if flagged → `cliWrite`; `CommandExited`/`Error` end the session —
   and reads `cliReadRaw` operator keystrokes, **coalescing** them into one
   `StreamData(stdin)` that is flushed once typing goes idle for **500 ms**, or
   **3 s** after the first unsent byte (whichever first), when the pending buffer
   would exceed one chunk, or immediately when the operator presses **Enter** (a
   newline submits the line without waiting). This turns a burst of typing into a
   single
   reliable Channel message instead of one per keystroke — a large win over the
   mesh, at the cost of ~½ s of local echo latency. Typing **`..!`** at the start
   of a line disconnects — the same line-start escape the ssh client uses (a
   single control byte like Ctrl-] is a poor fit; the T-Deck keyboard has no
   `]`). Ctrl-D is *not* special: like the stock client it is forwarded as a
   plain stdin byte, and the remote decides. A partial `..` match not completed
   is forwarded verbatim.

Session end is detected three ways, because the ITS handle only drops after
rnsd reclaims its slot (~3 s after a link teardown): an in-band
`CommandExited`/`Error`; `itsConnected(ch)` going false; and a ~1 Hz poll of
`rnsd.chan.<tag>.state` for `closed`/`failed`, which flips the instant the link
tears down — the prompt signal when the remote disconnects.

The relay drains the Channel handle itself with `itsRecv` rather than relying on
the `rnsdChannelOpen` recv callback, because while the command runs the cli task
is parked inside it and its poll loop can't dispatch the callback (same reason
`cliReadLine` reads the handle directly). ITS recv is a copy out of the
connection's ring, so it works without the owning task polling.

## 5. Pitfalls

- **The cli task stack is small (6 KB); keep the relay's frame off it.**
  `cliRnsh`'s relay buffers (`in`, `fwd`, `rx`, `tx`, `sframe`, and the 16 KB
  `decomp`) are `PSRAM_BSS static`, not automatic. `itsRecv`/`cliReadRaw` are
  copy-based APIs so scratch buffers are unavoidable, but ~900 B of them on the
  stack overflowed the cli task the first time (`help`, which calls every
  command's help handler one frame deeper, tipped it). CLI commands are
  serialized on the cli task, so the statics are safe. Don't reintroduce large
  automatic buffers here.
- **Outbound establishment needs a *path*, not just a recalled identity.** This
  is enforced in rns (`onChannelConnect` gates on `has_path() && recall()` and
  `channelTick` re-requests the path) — see [rns/INTERNALS.md §5.6](../rns/INTERNALS.md).
  A cached identity with no path-table entry sends a Link request into the void
  and fails with `establish_timeout`; on a busy public mesh (churning 100-entry
  path table) that is a live case, not a corner one.
- **`login` only travels on `cli_connect_t`.** The browser DataChannel and any
  net-forwarded raw-TCP cli path don't carry it and default to `login = 0`;
  rnsh (and sshd's password auth) are the callers that opt in. Don't assume a
  cli session is gated unless its connector set the bit.
- **A one-shot `spangap cli "rnsh <dest>"` ends when its stdin closes.** The
  relay's `cliReadRaw` returns < 0 when the operator session hangs up, ending
  the command. To drive it non-interactively, hold stdin open and feed input
  after the Channel is up (`( sleep 9; printf 'cmd\r'; sleep N ) | spangap cli
  "rnsh <dest>"`).
- **The device collapses stderr and ignores window size.** rnsh speaks the full
  upstream protocol on the wire, but the device cli is a single output stream
  with no terminal geometry: the server only ever emits `StreamData(stdout)`,
  and `WindowSize` frames are accepted and dropped. Peers see a valid session;
  they just never receive a separate `stderr` or act on a resize from us.
- **Our side never compresses; incoming compression is decompressed.** Upstream
  bz2-compresses stream chunks > 32 B when it shrinks them (common for a stock
  listener's larger output). We always send uncompressed (no MCU compress cost)
  but must decompress inbound frames with the `compressed` bit — via
  `rnsdBz2Decompress` (rns reuses the bzip2 already linked for Resources). A
  frame that fails to decompress is dropped, not fatal.

## 6. Wire

rnsh speaks the **upstream (acehoss) rnsh protocol, version 1**, byte-identical
to the stock `rnsh` tool, so our client and server interoperate with it in both
directions. Each Channel message is one upstream-typed envelope; magic `0xac`,
`MSGTYPE = 0xac00 | val`:

| val | message | payload |
|-----|---------|---------|
| 0 | `Noop` | empty |
| 2 | `WindowSize` | msgpack `(rows, cols, hpix, vpix)` |
| 3 | `ExecuteCommand` | msgpack `(cmdline, pipe_stdin, pipe_stdout, pipe_stderr, tcflags, term, rows, cols, hpix, vpix)` |
| 4 | `StreamData` | 2-byte big-endian header `(stream_id & 0x3fff) \| 0x8000 eof \| 0x4000 compressed`, then bytes (bz2 if compressed). Streams: stdin 0, stdout 1, stderr 2 |
| 5 | `VersionInfo` | msgpack `(sw_version, protocol_version = 1)` |
| 6 | `Error` | msgpack `(msg, fatal, data)` |
| 7 | `CommandExited` | msgpack `return_code` (a bare int) |

The 16-bit envelope msgtype is carried between rnsd and rnsh on the channel ITS
pipe framed as `[msgtype:2 BE][payload]` (see [rns/INTERNALS.md](../rns/INTERNALS.md)
and `rnsdChannelOpen`); the underlying `RNS::Channel` now sends and delivers an
arbitrary msgtype rather than a single `MSGTYPE_RAW`. rnsh builds/parses the
small tuples with an inline msgpack appender (`Buf` + `mp*`) and dispatches
purely on msgtype — only `StreamData` and the two `VersionInfo` fields need any
payload decoding. Session end is an in-band `CommandExited` (or `Error`), or
Channel/Link teardown (`itsConnected(ch)` going false).

Because the stock tool *is* the reference peer now, the raw-`0x0100` test peers
under `hw-lilygo-tdeck/tests/peers/` are obsolete — drive the device with
`rnsh -l …` (a listener) and `rnsh <hash>` (a client) from an installed
reference stack instead.

The typed-msgtype `Channel::send` in rns stays backward-compatible: the no-arg
`send()` still uses `MSGTYPE_RAW`, and lxmf/clink ride *links*, not Channels, so
they are unaffected — rnsh is the only channel consumer.

## 7. Testing & interop

The message codec is proven **byte-exact** against the reference `rnsh 0.1.7`
off-device: our packed `VersionInfo`, `ExecuteCommand`, `StreamData`,
`CommandExited` and `Error` all round-trip through upstream's own
`rnsh.protocol` message objects. The firmware builds for `hw-lilygo-tdeck`.
Full on-device interop against the stock tool still wants a live device.

Reference stack for testing: `install-reticulum` wires an `rns` uplink and puts
`rns 1.4.0` + `rnsh 0.1.7` on PATH (in `~/.reticulum-venv`); the wire is defined
by `.../site-packages/rnsh/{protocol,session,listener,initiator}.py`. With a
device online (`rnshd enable`, admin password set), exercise all four directions:

- **stock client → our server:** `rnsh <device_hash>` from the reference stack
  (get the hash from `rnshd`), enter the admin password.
- **our client → stock server:** `rnsh -l -A -- /bin/bash` on the reference host
  (it prints its destination), then `rnsh <that_hash>` on the device.
- **our client → our server** and **stock client → stock server** for symmetry.
