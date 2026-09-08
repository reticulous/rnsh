/**
 * rnsh — Reticulum remote shell.
 *
 * Client half: the `rnsh <dest_hash> [aspect]` CLI command opens a reliable
 * Channel to a remote node's `rnsh` destination and relays the operator's
 * interactive terminal to/from the remote device CLI.
 *
 * Server half: a daemon that hosts the `rnsh` destination, accepts an incoming
 * Channel, and splices it to the local CLI behind the admin-password login
 * gate. Enabled by `s.rnsh.server.enabled` (default 0).
 *
 * Who gets in:
 *   s.rnsh.server.allowed[]   one object per identity: { id, hash, label } —
 *                             `hash` is the 32-hex Reticulum identity the peer
 *                             identifies with; a match skips the password
 *   s.rnsh.server.password    1 = unlisted peers may log in with the admin
 *                             password (default); 0 = they are refused outright
 *
 * `rnshd allowed|allow <hash> [label]|deny <id>|password [on|off]` is the
 * operator front-end; the settings pane edits the same store through the
 * rnsh.peer.* sentinels.
 *
 * Colour:
 *   s.rnsh.server.color       show ANSI colors (default 0). A preference, not a
 *                             decision — the session is coloured only if this is
 *                             on AND the peer's ExecuteCommand says it is an
 *                             interactive colour terminal (no cmdline, stdout is
 *                             a tty, $TERM is not empty/dumb/-mono).
 */
#pragma once

#include "service.h"

/** Bring up rnsh: register the `rnsh` client CLI command and spawn the server
 *  task (idle until s.rnsh.server.enabled). Called from the generated straddle
 *  init dispatcher, after rns (rnsd) is up. */
class RnshService : public Service {
public:
    void onInit() override;
};
