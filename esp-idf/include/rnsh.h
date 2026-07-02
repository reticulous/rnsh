/**
 * rnsh — Reticulum remote shell.
 *
 * Client half: the `rnsh <dest_hash> [aspect]` CLI command opens a reliable
 * Channel to a remote node's `rnsh` destination and relays the operator's
 * interactive terminal to/from the remote device CLI.
 *
 * Server half: a daemon that hosts the `rnsh` destination, accepts an incoming
 * Channel, and splices it to the local CLI with the admin-password login gate
 * forced on. Enabled by `s.rnsh.server.enabled` (default 0).
 */
#pragma once

/** Bring up rnsh: register the `rnsh` client CLI command and spawn the server
 *  task (idle until s.rnsh.server.enabled). Called from the generated straddle
 *  init dispatcher, after rns (rnsd) is up. */
void rnshInit(void);
