# rnsh — internals

The user/operator guide is [README.md](README.md). This file covers the wiring:
the server session pump, the login handoff, the client relay, and the pitfalls.

rnsh is deliberately thin. Everything hard — reliable delivery, encryption,
authentication of the transport — is done by the Channel + Link layers in
[rns](../rns). rnsh is one file (`src/rnsh.cpp`, ~350 lines) that (a) registers
the `rnsh` client CLI command and (b) runs a server task that splices an
inbound Channel to a login-gated `cli` backend.

## 1. Bring-up

`RnshService::onInit()` (registered in the generated service registry) runs on
the main task after rns is up. It:

- writes storage defaults once, gated on `s.rnsh.version`;
- registers the `rnsh` client command (`cliRegisterCmd("rnsh", cliRnsh)`);
- spawns `rnshServerTask` (8 KB PSRAM stack, prio 3).

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
holding `{inboxHandle, backendHandle}`:

- **`onInboxConnect`** — a Channel arrived. Allocate a slot and open the CLI
  backend **with the login gate forced on**:

  ```c
  cli_connect_t cc = { CLI_ANSI, /*from_usb_serial*/0, color, /*no_prompt*/0, /*login*/1 };
  itsConnect("cli", CLI_PORT_TCP, &cc, sizeof(cc), …, /*ref*/i, onBackendRecv, onBackendDisc);
  ```

  That `login = 1` is the entire authentication story — see §3.
- **`onInboxRecv`** (remote → CLI): drain the Channel message, `itsSend` it to
  the backend. This is where the remote's password (typed at the CLI's prompt)
  and, later, its commands flow in.
- **`onBackendRecv`** (CLI → remote): drain the backend, `itsSend` it to the
  inbox handle — rnsd wraps it as a Channel message. This carries the
  `Enter admin password:` prompt, the `*` echoes, and all command output. It is
  **one stream**: the cli never emits a separate stderr, so stdout+stderr are
  collapsed by construction (same as sshd, which never sends `EXTENDED_DATA`).
- **Teardown** — either side closing tears down the other. `sessClose`
  disconnects both handles and clears the slot; a re-entrant disconnect callback
  no-ops because the slot's `used` flag is already false.

The bytes are copied through modest stack buffers (`char buf[600]` on the 8 KB
server task) — fine here, unlike the client (§5).

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
2. `rnsdChannelOpen(dh, aspect, "", tag, …)` — the outbound Channel;
3. polls `rnsd.chan.<tag>.state` until `active` (up to ~70 s: a path request
   plus establishment) or `failed` (prints `last_error`); Ctrl-C aborts;
4. enters the relay loop: `cliReadRaw` operator keystrokes → `itsSend(ch)`;
   `itsRecv(ch)` remote output → `cliWrite`. Typing **`..!`** at the start of a
   line disconnects — the same line-start escape the ssh client uses (a single
   control byte like Ctrl-] is a poor fit; the T-Deck keyboard has no `]`). A
   partial match (`.`/`..`) not completed is forwarded verbatim.

The relay drains the Channel handle itself with `itsRecv` rather than relying on
the `rnsdChannelOpen` recv callback, because while the command runs the cli task
is parked inside it and its poll loop can't dispatch the callback (same reason
`cliReadLine` reads the handle directly). ITS recv is a copy out of the
connection's ring, so it works without the owning task polling.

## 5. Pitfalls

- **The cli task stack is small (6 KB); keep the relay's frame off it.**
  `cliRnsh`'s relay buffers (`in[256]`, `out[600]`) are `PSRAM_BSS static`, not
  automatic. `itsRecv`/`cliReadRaw` are copy-based APIs so a scratch buffer is
  unavoidable, but ~900 B of it on the stack overflowed the cli task the first
  time (`help`, which calls every command's help handler one frame deeper,
  tipped it). CLI commands are serialized on the cli task, so the statics are
  safe. Don't reintroduce large automatic buffers here.
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
- **No separate stderr, no PTY.** rnsh carries the single cli stream and nothing
  else — no window-resize, no `stderr` demux, no terminal modes. That is the
  intended minimal surface, matching the device cli's own model.

## 6. Wire

The application layer inside each Channel message is **raw terminal bytes** — no
opcode. Session end is signalled by Channel/Link teardown (the client's
`itsConnected(ch)` going false), not an in-band frame. The Channel itself is a
standard RNS Channel (envelope + `CONTEXT.CHANNEL` packets, msgtype `0x0100`
carrying the raw bytes), so a stock RNS `Channel` with a matching `MessageBase`
interoperates — which is how a reference Python client/server (a stock
`RNS.Channel` with a `MessageBase` whose `MSGTYPE = 0x0100` packs/unpacks the
raw bytes) can drive the device in testing, in the shape of the peers under
`hw-tdeck/tests/peers/`.
