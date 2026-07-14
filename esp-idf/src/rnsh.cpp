/**
 * rnsh — Reticulum remote shell (client + server).
 *
 * Client: `rnsh <dest_hash> [aspect]` opens a reliable Channel (rnsdChannelOpen)
 * to a remote node's `rnsh` destination and relays the operator's interactive
 * terminal over it — keystrokes out, combined output in. Ctrl-] quits.
 *
 * Server: hosts the `rnsh` destination, listens for inbound Channels
 * (rnsdDestListenChannels), and for each one opens a CLI backend with the
 * admin-password login gate forced on (cli_connect_t.login = 1), then pumps
 * bytes between the Channel and the CLI. The CLI is a single output stream, so
 * the remote's stdout+stderr arrive collapsed by construction. Enabled by
 * s.rnsh.server.enabled (default 0).
 *
 * All transport encryption/authentication is Reticulum's; rnsh adds only the
 * application-level admin gate.
 */
#include "rnsh.h"
#include "rnsd.h"
#include "ports.h"
#include "cli.h"
#include "its.h"
#include "spangap.h"
#include "mem.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"

#include <cstring>
#include <cstdio>
#include <string>

static const char* TAG = "rnsh";

#define RNSH_VERSION        1
#define RNSH_INBOX_PORT     130     /* server's inbound-Channel forward port
                                       (distinct from lxmf 100/101, clink 120) */
#define RNSH_MAX_SESSIONS   2
#define RNSH_IDENTITY_KEY   "secrets.rnsh.identity"
/* Line-start disconnect escape — same as the ssh client (`..!`). A single
 * control byte like Ctrl-] is a poor fit: the T-Deck keyboard has no `]`. */
static const char RNSH_ESC[] = "..!";

/* ═══════════════════════════ client ═══════════════════════════ */

/* rnsdChannelOpen requires an on_recv callback, but the client drains the
 * handle itself inside the relay loop (the cli task is parked in the command,
 * so its poll loop can't dispatch the callback). No-op keeps the API happy. */
static void rnshClientRecvNoop(int /*handle*/, size_t /*avail*/) {}
static void rnshClientDiscNoop(int /*handle*/) {}

static bool hexToBytes(const char* hex, uint8_t* out, size_t outLen) {
    size_t n = strlen(hex);
    if (n != outLen * 2) return false;
    for (size_t i = 0; i < outLen; i++) {
        char b[3] = { hex[i * 2], hex[i * 2 + 1], 0 };
        char* end = nullptr;
        long v = strtol(b, &end, 16);
        if (end != b + 2) return false;
        out[i] = (uint8_t)v;
    }
    return true;
}

static void cliRnsh(const char* args) {
    if (cliWantsHelp(args)) {
        cliPrintf("rnsh <dest_hash> [aspect]   open a remote CLI over Reticulum\n");
        cliPrintf("                            dest_hash = 32-hex; aspect defaults to \"rnsh\"\n");
        cliPrintf("                            type '..!' on a new line to disconnect.\n");
        return;
    }
    /* Parse: <dest_hash> [aspect] */
    char hex[80] = {}, aspect[32] = {};
    int got = sscanf(args, "%79s %31s", hex, aspect);
    if (got < 1 || hex[0] == '\0') {
        cliPrintf("usage: rnsh <dest_hash> [aspect]\n");
        return;
    }
    if (aspect[0] == '\0') safeStrncpy(aspect, "rnsh", sizeof(aspect));

    uint8_t dh[RNSD_DEST_HASH_LEN];
    if (!hexToBytes(hex, dh, sizeof(dh))) {
        cliPrintf("rnsh: dest_hash must be %d hex chars\n", (int)(RNSD_DEST_HASH_LEN * 2));
        return;
    }

    static int s_seq = 0;
    char tag[24];
    snprintf(tag, sizeof(tag), "rnsh.c%d", s_seq++);

    int ch = rnsdChannelOpen(dh, aspect, "", tag,
                             /*path_timeout_ms*/0, /*link_timeout_ms*/30000,
                             /*ref*/0, rnshClientRecvNoop, rnshClientDiscNoop);
    if (ch < 0) {
        cliPrintf("rnsh: could not open channel (rnsd down?)\n");
        return;
    }

    cliPrintf("rnsh: connecting to %s (aspect %s)...\r\n", hex, aspect);

    /* Wait for the channel to go active (or fail), polling its state key. */
    char stateKey[64];
    snprintf(stateKey, sizeof(stateKey), "rnsd.chan.%s.state", tag);
    bool active = false;
    for (int i = 0; i < 700; i++) {          /* ~70 s cap (path req + establish) */
        char st[24] = {};
        storageGetStr(stateKey, st, sizeof(st), "");
        if (strcmp(st, "active") == 0) { active = true; break; }
        if (strcmp(st, "failed") == 0) {
            char errKey[64], errv[48] = {};
            snprintf(errKey, sizeof(errKey), "rnsd.chan.%s.last_error", tag);
            storageGetStr(errKey, errv, sizeof(errv), "?");
            cliPrintf("rnsh: connection failed (%s)\r\n", errv);
            itsDisconnect(ch);
            return;
        }
        /* Allow Ctrl-C to cancel while establishing. */
        char c;
        int r = cliReadRaw(&c, 1, 100);
        if (r > 0 && (c == 0x03)) { cliPrintf("\r\nrnsh: cancelled\r\n"); itsDisconnect(ch); return; }
        if (r < 0) { itsDisconnect(ch); return; }
    }
    if (!active) {
        cliPrintf("rnsh: timed out establishing channel\r\n");
        itsDisconnect(ch);
        return;
    }

    cliPrintf("rnsh: connected  ('..!' on a new line disconnects)\r\n");

    /* Relay buffers live in PSRAM statics, not on the stack: the cli task has a
     * modest 6 KB stack and this command's frame would otherwise spike it (and
     * the whole frame is reserved on entry even for the early-return help path).
     * CLI commands are serialized on the cli task, so statics are safe. `fwd`
     * holds the escape-filtered bytes (up to `in` plus a 2-char withheld
     * prefix flush). */
    PSRAM_BSS static char in[256];
    PSRAM_BSS static char out[600];
    PSRAM_BSS static char fwd[260];

    /* Interactive relay: operator keystrokes → channel; channel messages →
     * operator terminal. Everything from the remote is one collapsed stream.
     * `..!` at the start of a line disconnects (same escape as the ssh client);
     * a partial match (`.`/`..`) not completed is forwarded verbatim, so only a
     * literal `..!` line-start is ever eaten. */
    bool   atLineStart = true;
    size_t escMatch    = 0;   /* chars of RNSH_ESC withheld so far */
    for (;;) {
        if (!itsConnected(ch)) { cliPrintf("\r\nrnsh: session closed.\r\n"); break; }

        /* Remote output. */
        size_t m = itsRecv(ch, out, sizeof(out), 0);
        if (m > 0) cliWrite(out, m);

        /* Operator input (short block so output stays responsive). */
        int r = cliReadRaw(in, sizeof(in), 20);
        if (r < 0) break;                       /* operator session gone */
        if (r == 0) continue;

        int  fn = 0;
        bool quit = false;
        for (int i = 0; i < r; i++) {
            char c = in[i];
            if (escMatch) {
                if (c == RNSH_ESC[escMatch]) {
                    if (++escMatch == sizeof(RNSH_ESC) - 1) { quit = true; break; }
                    continue;                   /* keep withholding */
                }
                /* mismatch: flush the withheld prefix, then handle c below */
                for (size_t k = 0; k < escMatch; k++) fwd[fn++] = RNSH_ESC[k];
                escMatch = 0;
                atLineStart = false;
            }
            if (atLineStart && c == RNSH_ESC[0]) { escMatch = 1; continue; }
            fwd[fn++] = c;
            atLineStart = (c == '\r' || c == '\n');
        }
        if (fn > 0) itsSend(ch, fwd, fn, pdMS_TO_TICKS(1000));
        if (quit) { cliPrintf("\r\nrnsh: disconnected.\r\n"); break; }
    }
    itsDisconnect(ch);
}

/* ═══════════════════════════ server ═══════════════════════════ */

namespace {

struct rnsh_session_t {
    bool used;
    int  inboxHandle;     /* Channel forward from rnsd (RNSH_INBOX_PORT) */
    int  backendHandle;   /* CLI backend (CLI_PORT_TCP, login-gated) */
};

PSRAM_BSS rnsh_session_t s_sessions[RNSH_MAX_SESSIONS];

TaskHandle_t s_serverTask = nullptr;
int          s_destHandle  = -1;   /* hosted rnsh destination (rnsdDestOpen) */

rnsh_session_t* sessByInbox(int h) {
    for (auto& s : s_sessions) if (s.used && s.inboxHandle == h) return &s;
    return nullptr;
}
rnsh_session_t* sessByBackend(int h) {
    for (auto& s : s_sessions) if (s.used && s.backendHandle == h) return &s;
    return nullptr;
}
int sessAlloc() {
    for (int i = 0; i < RNSH_MAX_SESSIONS; i++) if (!s_sessions[i].used) return i;
    return -1;
}

void sessClose(rnsh_session_t& s) {
    if (s.backendHandle >= 0) itsDisconnect(s.backendHandle);
    if (s.inboxHandle   >= 0) itsDisconnect(s.inboxHandle);
    s = {};
    s.inboxHandle = s.backendHandle = -1;
}

/* CLI backend → remote: forward CLI output down the Channel. */
void onBackendRecv(int handle, size_t /*avail*/) {
    rnsh_session_t* s = sessByBackend(handle);
    if (!s) return;
    char buf[600];
    size_t n = itsRecv(handle, buf, sizeof(buf), 0);
    if (n == 0) return;
    itsSend(s->inboxHandle, buf, n, pdMS_TO_TICKS(200));
}

/* CLI backend closed (user exited, or login failed / dropped): tear the whole
 * session down so the remote's Channel closes. */
void onBackendDisc(int ref) {
    if (ref < 0 || ref >= RNSH_MAX_SESSIONS) return;
    if (s_sessions[ref].used) {
        ESP_LOGI(TAG, "session %d: CLI backend closed", ref);
        sessClose(s_sessions[ref]);
    }
}

/* Inbound Channel arrived (rnsd forwarded it here). Open a login-gated CLI
 * backend for it. The connect payload is rnsd_link_incoming_t; we only need to
 * know a session started. */
int onInboxConnect(int handle, const void* /*data*/, size_t /*len*/) {
    int i = sessAlloc();
    if (i < 0) { ESP_LOGW(TAG, "no free session slot — rejecting"); return -1; }
    s_sessions[i].used = true;
    s_sessions[i].inboxHandle = handle;
    s_sessions[i].backendHandle = -1;

    cli_color_t color = storageGetInt("s.rnsh.server.color", 0) ? CLI_COLOR : CLI_NO_COLOR;
    cli_connect_t cc = { CLI_ANSI, /*from_usb_serial*/0, color, /*no_prompt*/0, /*login*/1 };
    int b = itsConnect("cli", CLI_PORT_TCP, &cc, sizeof(cc), pdMS_TO_TICKS(500),
                       /*ref*/i, onBackendRecv, onBackendDisc);
    if (b < 0) {
        ESP_LOGW(TAG, "session %d: CLI backend connect failed (%d)", i, b);
        s_sessions[i] = {};
        return -1;
    }
    s_sessions[i].backendHandle = b;
    ESP_LOGI(TAG, "session %d: inbound rnsh channel → login-gated CLI", i);
    return i;
}

/* Remote → CLI backend: forward Channel messages to the CLI (this includes the
 * password the remote types at the "Enter admin password: " prompt). */
void onInboxRecv(int handle, size_t /*avail*/) {
    rnsh_session_t* s = sessByInbox(handle);
    if (!s || s->backendHandle < 0) return;
    char buf[600];
    size_t n = itsRecv(handle, buf, sizeof(buf), 0);
    if (n == 0) return;
    itsSend(s->backendHandle, buf, n, pdMS_TO_TICKS(200));
}

void onInboxDisconnect(int ref) {
    if (ref < 0 || ref >= RNSH_MAX_SESSIONS) return;
    if (s_sessions[ref].used) {
        ESP_LOGI(TAG, "session %d: remote channel closed", ref);
        sessClose(s_sessions[ref]);
    }
}

/* rnsdDestOpen callbacks — the hosted destination itself carries no app
 * packets (only Link/Channel establishment), so these are no-ops. */
void onDestRecv(int /*handle*/, size_t /*avail*/) {}
void onDestDisc(int /*handle*/) { s_destHandle = -1; }

/* Publish the server's destination hash so the operator can hand it to a
 * client. Best-effort — computed from our identity + the "rnsh" aspect. */
void publishServerDest() {
    uint8_t dh[RNSD_DEST_HASH_LEN];
    if (rnsdDestinationHash(RNSH_IDENTITY_KEY, "rnsh", "", dh)) {
        char hex[RNSD_DEST_HASH_LEN * 2 + 1];
        for (size_t i = 0; i < RNSD_DEST_HASH_LEN; i++) snprintf(hex + i * 2, 3, "%02x", dh[i]);
        storageSet("rnsh.server.dest", hex);
        ESP_LOGI(TAG, "server destination: %s", hex);
    }
}

void serverOpen() {
    rnsdIdentityGenerate(RNSH_IDENTITY_KEY);   /* idempotent */
    s_destHandle = rnsdDestOpen("rnsh", RNSH_IDENTITY_KEY, /*SINGLE*/0,
                                /*ref*/0, onDestRecv, onDestDisc);
    if (s_destHandle < 0) {
        ESP_LOGW(TAG, "server: rnsdDestOpen failed (%d)", s_destHandle);
        return;
    }
    if (!rnsdDestListenChannels(s_destHandle, RNSH_INBOX_PORT)) {
        ESP_LOGW(TAG, "server: rnsdDestListenChannels failed");
    }
    publishServerDest();
    ESP_LOGI(TAG, "server: hosting rnsh, listening for channels");
}

void serverClose() {
    if (s_destHandle >= 0) itsDisconnect(s_destHandle);
    s_destHandle = -1;
    for (auto& s : s_sessions) if (s.used) sessClose(s);
    storageSet("rnsh.server.dest", "");
    ESP_LOGI(TAG, "server: stopped");
}

void serverAnnounce() {
    if (s_destHandle < 0) return;
    uint8_t f[1] = { RNSD_DEST_ANNOUNCE };
    itsSend(s_destHandle, f, sizeof(f), pdMS_TO_TICKS(200));
}

void rnshServerTask(void*) {
    for (auto& s : s_sessions) { s = {}; s.inboxHandle = -1; s.backendHandle = -1; }
    itsServerInit();
    itsClientInit(RNSH_MAX_SESSIONS + 2);   /* CLI backends + dest handle */
    itsServerPortOpen(RNSH_INBOX_PORT, ITS_PACKET, RNSH_MAX_SESSIONS, 4096, 4096, 0, 4096);
    itsServerOnConnect(RNSH_INBOX_PORT, onInboxConnect);
    itsServerOnRecv(RNSH_INBOX_PORT, onInboxRecv);
    itsServerOnDisconnect(RNSH_INBOX_PORT, onInboxDisconnect);

    /* Wait for the RNS universe to come up before hosting a destination. */
    while (storageGetInt("rns.ready", 0) == 0) vTaskDelay(pdMS_TO_TICKS(500));

    TickType_t nextAnnounce = 0;
    for (;;) {
        itsPoll(pdMS_TO_TICKS(1000));

        bool en = storageGetInt("s.rnsh.server.enabled", 0) != 0;
        if (en && s_destHandle < 0) { serverOpen(); nextAnnounce = 0; }
        else if (!en && s_destHandle >= 0) { serverClose(); }

        if (s_destHandle >= 0) {
            TickType_t now = xTaskGetTickCount();
            if (nextAnnounce == 0 || (int32_t)(now - nextAnnounce) >= 0) {
                serverAnnounce();
                int iv = storageGetInt("s.rnsh.server.announce_interval", 1800);
                if (iv <= 0) iv = 1800;
                nextAnnounce = now + pdMS_TO_TICKS(iv * 1000);
            }
        }
    }
}

} // namespace

/* ═══════════════════════════ init ═══════════════════════════ */

void RnshService::onInit() {
    if (storageGetInt("s.rnsh.version", 0) < RNSH_VERSION) {
        storageBegin();
        storageDefault("s.rnsh.server.enabled", 0);
        storageDefault("s.rnsh.server.color", 0);
        storageDefault("s.rnsh.server.announce_interval", 1800);
        storageSet("s.rnsh.version", RNSH_VERSION);
        storageEnd();
    }

    cliRegisterCmd("rnsh", cliRnsh);

    s_serverTask = spawnTask(rnshServerTask, TAG, 8192, nullptr, 3, 0, STACK_PSRAM);
}
