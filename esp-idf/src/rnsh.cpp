/**
 * rnsh — Reticulum remote shell (client + server), speaking the upstream
 * (acehoss) rnsh wire protocol so our client and server interoperate with the
 * stock `rnsh` tool in both directions.
 *
 * Every Channel message is one upstream-typed envelope (magic 0xac): NoopMessage
 * (0xac00), WindowSizeMessage (0xac02), ExecuteCommandMessage (0xac03),
 * StreamDataMessage (0xac04), VersionInfoMessage (0xac05), ErrorMessage
 * (0xac06), CommandExitedMessage (0xac07). rnsd carries the envelope msgtype on
 * the channel ITS pipe framed as [msgtype:2 BE][payload], so this file chooses
 * the msgtype per send and dispatches on it per receive. Terminal bytes ride
 * StreamDataMessage streams (stdin=0, stdout=1, stderr=2).
 *
 * Client: `rnsh <dest_hash> [aspect]` opens a Channel to a remote rnsh
 * destination, does the Version handshake, sends one ExecuteCommand, then relays
 * the operator's terminal as stdin and prints the stdout/stderr streams.
 * Typing '..!' on a new line disconnects.
 *
 * Server: hosts the `rnsh` destination, accepts inbound Channels, and per
 * session runs the listener state machine WAIT_VERS → WAIT_CMD → RUNNING. On
 * ExecuteCommand it opens a CLI backend with the admin-password login gate
 * forced on (cli_connect_t.login = 1) — the device has one "command", its CLI —
 * and relays: stdin stream → CLI, CLI output → stdout stream. The CLI is a
 * single output stream, so stdout+stderr are collapsed by construction. The
 * password gate is our only authentication; identity is accepted from anyone
 * (allow-all), so a stock client's identify is honoured but never required.
 * Enabled by s.rnsh.server.enabled (default 0).
 *
 * All transport encryption/authentication is Reticulum's; upstream compresses
 * stream chunks > 32 B with bz2, so incoming compressed frames are decompressed
 * (rnsdBz2Decompress); our side always sends uncompressed.
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

/* ── upstream rnsh protocol (rnsh/protocol.py) ── */
#define MT_NOOP     0xac00
#define MT_WINSIZE  0xac02
#define MT_EXEC     0xac03
#define MT_STREAM   0xac04
#define MT_VERSION  0xac05
#define MT_ERROR    0xac06
#define MT_EXITED   0xac07

#define STREAM_STDIN   0
#define STREAM_STDOUT  1
#define STREAM_STDERR  2
#define STREAM_EOF        0x8000    /* StreamDataMessage header flag bits */
#define STREAM_COMPRESSED 0x4000
#define STREAM_ID_MASK    0x3fff

#define RNSH_MAX_CHUNK   16384      /* RawChannelWriter.MAX_CHUNK_LEN (decompress bound) */
#define RNSH_STREAM_CHUNK  384      /* max stdout bytes per StreamData (fits Link MDU) */
#define RNSH_SW_VERSION  "spangap-rnsh 1"
#define RNSH_PROTO_VER   1

/* Line-start disconnect escape — same as the ssh client (`..!`). A single
 * control byte like Ctrl-] is a poor fit: the T-Deck keyboard has no `]`. */
static const char RNSH_ESC[] = "..!";

/* ═══════════════════════════ msgpack + framing ═══════════════════════════ */

/* Minimal msgpack appender over a caller-owned buffer (upstream payloads are
 * tiny fixed tuples). Overflow is silently clamped; callers size for the max. */
namespace {
struct Buf {
    uint8_t* p; size_t cap; size_t n;
    void u8(uint8_t b)                   { if (n < cap) p[n] = b; n++; }
    void raw(const uint8_t* d, size_t l) { for (size_t i = 0; i < l; i++) u8(d[i]); }
};
void mpArray(Buf& b, size_t n) {
    if (n <= 15) b.u8((uint8_t)(0x90 | n));
    else { b.u8(0xdc); b.u8((uint8_t)(n >> 8)); b.u8((uint8_t)n); }
}
void mpUint(Buf& b, uint32_t v) {
    if (v <= 0x7f)        b.u8((uint8_t)v);
    else if (v <= 0xff)   { b.u8(0xcc); b.u8((uint8_t)v); }
    else if (v <= 0xffff) { b.u8(0xcd); b.u8((uint8_t)(v >> 8)); b.u8((uint8_t)v); }
    else { b.u8(0xce); b.u8((uint8_t)(v >> 24)); b.u8((uint8_t)(v >> 16));
           b.u8((uint8_t)(v >> 8)); b.u8((uint8_t)v); }
}
void mpStr(Buf& b, const char* s) {
    size_t l = strlen(s);
    if (l <= 31) b.u8((uint8_t)(0xa0 | l));
    else { b.u8(0xd9); b.u8((uint8_t)l); }
    b.raw((const uint8_t*)s, l);
}
void mpBool(Buf& b, bool v) { b.u8(v ? 0xc3 : 0xc2); }
void mpNil(Buf& b)          { b.u8(0xc0); }

/* Read one framed message from an ITS handle. Returns payload length (>=0) and
 * sets msgtype and payload, or -1 if nothing available / runt. */
int recvMsg(int handle, uint8_t* buf, size_t cap, uint16_t* msgtype, const uint8_t** payload) {
    size_t m = itsRecv(handle, buf, cap, 0);
    if (m < 2) return -1;
    *msgtype = (uint16_t)((buf[0] << 8) | buf[1]);
    *payload = buf + 2;
    return (int)(m - 2);
}
} // namespace

/* Frame [msgtype][payload] and send on an ITS handle. Each caller passes its own
 * scratch buffer (the cli task and the rnsh server task never share one). */
static void sendMsg(int handle, uint16_t msgtype, uint8_t* scratch, size_t cap,
                    const uint8_t* payload, size_t n, TickType_t to) {
    if (n + 2 > cap) return;
    scratch[0] = (uint8_t)(msgtype >> 8);
    scratch[1] = (uint8_t)(msgtype & 0xFF);
    if (n) memcpy(scratch + 2, payload, n);
    itsSend(handle, scratch, n + 2, to);
}

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

/* ═══════════════════════════ client ═══════════════════════════ */

/* rnsdChannelOpen requires an on_recv callback, but the client drains the
 * handle itself inside the relay loop (the cli task is parked in the command,
 * so its poll loop can't dispatch the callback). No-op keeps the API happy. */
static void rnshClientRecvNoop(int /*handle*/, size_t /*avail*/) {}
static void rnshClientDiscNoop(int /*handle*/) {}

/* Decode one StreamData payload into (stream_id, data). Decompresses into
 * `scratch` if the compressed bit is set. Returns data length and sets the
 * stream_id, data and eof out-params; -1 on error. */
static int decodeStream(const uint8_t* payload, size_t n, uint8_t* scratch, size_t scratchCap,
                        uint16_t* stream_id, const uint8_t** data, bool* eof) {
    if (n < 2) return -1;
    uint16_t hdr = (uint16_t)((payload[0] << 8) | payload[1]);
    *stream_id = hdr & STREAM_ID_MASK;
    *eof = (hdr & STREAM_EOF) != 0;
    const uint8_t* body = payload + 2;
    size_t blen = n - 2;
    if (hdr & STREAM_COMPRESSED) {
        size_t dn = rnsdBz2Decompress(body, blen, scratch, scratchCap);
        if (dn == 0 && blen != 0) return -1;   /* decompress failed */
        *data = scratch;
        return (int)dn;
    }
    *data = body;
    return (int)blen;
}

static void cliRnsh(const char* args) {
    if (cliWantsHelp(args)) {
        cliPrintf("rnsh <dest_hash> [aspect]   open a remote CLI over Reticulum\n");
        cliPrintf("                            dest_hash = 32-hex; aspect defaults to \"rnsh\"\n");
        cliPrintf("                            type '..!' on a new line to disconnect.\n");
        return;
    }
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

    /* Identify with our rnsh identity so a listener gating on allowed initiator
     * identities (upstream `-a <hash>`) admits us; harmless to allow-all peers. */
    int ch = rnsdChannelOpen(dh, aspect, RNSH_IDENTITY_KEY, tag,
                             /*path_timeout_ms*/0, /*link_timeout_ms*/30000,
                             /*ref*/0, rnshClientRecvNoop, rnshClientDiscNoop);
    if (ch < 0) {
        cliPrintf("rnsh: could not open channel (rnsd down?)\n");
        return;
    }

    cliPrintf("rnsh: connecting to %s (aspect %s)...\r\n", hex, aspect);

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

    /* Relay buffers in PSRAM statics, not on the cli task's modest stack (its
     * frame is reserved on entry, even for the early-return paths above). CLI
     * commands are serialized on the cli task, so statics are safe. */
    PSRAM_BSS static uint8_t rx[512];
    PSRAM_BSS static uint8_t decomp[RNSH_MAX_CHUNK];
    PSRAM_BSS static uint8_t tx[RNSH_STREAM_CHUNK + 8];
    PSRAM_BSS static uint8_t sframe[2 + RNSH_STREAM_CHUNK];  /* stdin: 2-byte header + coalesced bytes */
    PSRAM_BSS static char    in[256];
    PSRAM_BSS static char    fwd[260];

    /* Version handshake: send our VersionInfo, wait for the server's reply. */
    {
        uint8_t pl[64]; Buf b{pl, sizeof(pl), 0};
        mpArray(b, 2); mpStr(b, RNSH_SW_VERSION); mpUint(b, RNSH_PROTO_VER);
        sendMsg(ch, MT_VERSION, tx, sizeof(tx), pl, b.n, pdMS_TO_TICKS(1000));
    }
    bool gotVersion = false;
    for (int i = 0; i < 300 && !gotVersion; i++) {   /* ~15 s */
        if (!itsConnected(ch)) { cliPrintf("\r\nrnsh: session closed.\r\n"); itsDisconnect(ch); return; }
        uint16_t mt; const uint8_t* pl;
        int n = recvMsg(ch, rx, sizeof(rx), &mt, &pl);
        if (n >= 0) {
            if (mt == MT_VERSION) { gotVersion = true; break; }
            if (mt == MT_ERROR)   { cliPrintf("\r\nrnsh: remote error\r\n"); itsDisconnect(ch); return; }
            continue;   /* ignore anything else during handshake */
        }
        char c; int r = cliReadRaw(&c, 1, 50);
        if (r > 0 && c == 0x03) { cliPrintf("\r\nrnsh: cancelled\r\n"); itsDisconnect(ch); return; }
    }
    if (!gotVersion) {
        cliPrintf("rnsh: no version reply from remote\r\n");
        itsDisconnect(ch);
        return;
    }

    /* ExecuteCommand: default shell, interactive PTY (pipe_* false), no tcflags.
     * Our server ignores the payload; a stock server uses it to size the PTY. */
    {
        uint8_t pl[64]; Buf b{pl, sizeof(pl), 0};
        mpArray(b, 10);
        mpNil(b);                 /* cmdline → listener default */
        mpBool(b, false);         /* pipe_stdin  */
        mpBool(b, false);         /* pipe_stdout */
        mpBool(b, false);         /* pipe_stderr */
        mpNil(b);                 /* tcflags */
        mpStr(b, "xterm");        /* term */
        mpUint(b, 25);            /* rows */
        mpUint(b, 80);            /* cols */
        mpUint(b, 0);             /* hpix */
        mpUint(b, 0);             /* vpix */
        sendMsg(ch, MT_EXEC, tx, sizeof(tx), pl, b.n, pdMS_TO_TICKS(1000));
    }

    cliPrintf("rnsh: connected  ('..!' on a new line disconnects)\r\n");

    /* Outbound coalescing: accumulate typed bytes in `sframe` (after the 2-byte
     * stream header) and send one StreamData once typing goes idle for 500 ms,
     * or 3 s after the first unsent byte, whichever comes first — so a burst of
     * keystrokes is one reliable Channel message, not one per character. */
    size_t     pn = 0;                 /* pending stdin bytes buffered in sframe+2 */
    TickType_t firstKeyTick = 0, lastKeyTick = 0;
    auto flushStdin = [&]() {
        if (pn == 0) return;
        sframe[0] = (uint8_t)(STREAM_STDIN >> 8);
        sframe[1] = (uint8_t)(STREAM_STDIN & 0xFF);
        sendMsg(ch, MT_STREAM, tx, sizeof(tx), sframe, pn + 2, pdMS_TO_TICKS(1000));
        pn = 0;
    };

    bool   atLineStart = true;
    size_t escMatch    = 0;   /* chars of RNSH_ESC withheld so far */
    int    hangupPoll  = 0;
    for (;;) {
        if (!itsConnected(ch)) { cliPrintf("\r\nrnsh: session closed.\r\n"); break; }

        /* Remote hangup detection (~1 s cadence): the ITS handle only drops
         * after rnsd reclaims the slot (~3 s), but the channel state key flips
         * to closed/failed the instant the link tears down. */
        if (++hangupPoll >= 50) {
            hangupPoll = 0;
            char st[24] = {};
            storageGetStr(stateKey, st, sizeof(st), "");
            if (strcmp(st, "closed") == 0 || strcmp(st, "failed") == 0) {
                cliPrintf("\r\nrnsh: remote disconnected.\r\n"); break;
            }
        }

        /* Drain all pending remote output. */
        bool exited = false;
        for (;;) {
            uint16_t mt; const uint8_t* pl;
            int n = recvMsg(ch, rx, sizeof(rx), &mt, &pl);
            if (n < 0) break;
            if (mt == MT_STREAM) {
                uint16_t sid; const uint8_t* data; bool eof;
                int dn = decodeStream(pl, n, decomp, sizeof(decomp), &sid, &data, &eof);
                if (dn > 0 && (sid == STREAM_STDOUT || sid == STREAM_STDERR))
                    cliWrite((const char*)data, dn);
            } else if (mt == MT_EXITED) {
                exited = true; break;
            } else if (mt == MT_ERROR) {
                cliPrintf("\r\nrnsh: remote error\r\n"); exited = true; break;
            }
            /* NOOP / VERSION / WINSIZE ignored */
        }
        if (exited) { cliPrintf("\r\nrnsh: session ended.\r\n"); break; }

        /* Operator input (short block so output stays responsive). */
        int r = cliReadRaw(in, sizeof(in), 20);
        if (r < 0) break;                       /* operator session gone */
        TickType_t now = xTaskGetTickCount();

        int  fn = 0;
        bool quit = false, sawEnter = false;
        for (int i = 0; i < r; i++) {
            char c = in[i];
            if (escMatch) {
                if (c == RNSH_ESC[escMatch]) {
                    if (++escMatch == sizeof(RNSH_ESC) - 1) { quit = true; break; }
                    continue;                   /* keep withholding */
                }
                for (size_t k = 0; k < escMatch; k++) fwd[fn++] = RNSH_ESC[k];
                escMatch = 0;
                atLineStart = false;
            }
            if (atLineStart && c == RNSH_ESC[0]) { escMatch = 1; continue; }
            fwd[fn++] = c;
            atLineStart = (c == '\r' || c == '\n');
            if (atLineStart) sawEnter = true;   /* newline → submit the line now */
        }

        if (fn > 0) {
            if (pn + fn > RNSH_STREAM_CHUNK) flushStdin();  /* would overflow */
            if (pn == 0) firstKeyTick = now;
            memcpy(sframe + 2 + pn, fwd, fn);
            pn += fn;
            lastKeyTick = now;
        }

        /* Enter short-circuits coalescing; otherwise flush on 500 ms idle or 3 s
         * since the first pending byte. */
        if (sawEnter) flushStdin();
        else if (pn > 0 && ((now - lastKeyTick)  >= pdMS_TO_TICKS(500) ||
                            (now - firstKeyTick) >= pdMS_TO_TICKS(3000)))
            flushStdin();

        if (quit) { flushStdin(); cliPrintf("\r\nrnsh: disconnected.\r\n"); break; }
    }
    itsDisconnect(ch);
}

/* ═══════════════════════════ server ═══════════════════════════ */

namespace {

enum rnsh_state_t { SS_WAIT_VERS, SS_WAIT_CMD, SS_RUNNING };

struct rnsh_session_t {
    bool         used;
    rnsh_state_t state;
    int          inboxHandle;     /* Channel forward from rnsd (RNSH_INBOX_PORT) */
    int          backendHandle;   /* CLI backend (CLI_PORT_TCP, login-gated) */
    /* Outbound stdout coalescing (snappier than the client's stdin, so remote
     * echo stays responsive): accumulate CLI output and emit one StreamData once
     * it goes idle for 250 ms, 1.5 s after the first pending byte, or when a full
     * chunk is buffered. */
    uint8_t      outbuf[RNSH_STREAM_CHUNK];
    size_t       outn;
    TickType_t   firstByteTick, lastByteTick;
};

PSRAM_BSS rnsh_session_t s_sessions[RNSH_MAX_SESSIONS];

TaskHandle_t     s_serverTask = nullptr;
volatile bool    s_parked = false;     /* true while parked (stopped); rnshStop waits on it */
volatile bool    s_stop = false;       /* rns stop → break the work loop and park */
int              s_destHandle = -1;    /* hosted rnsh destination (rnsdDestOpen) */
volatile bool    s_announceRequest = false;   /* set by `rnshd announce`, served on the task */

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

/* Send an upstream-typed message down a session's Channel (inbox handle). One
 * server-task scratch buffer; the server task is single-threaded. */
void srvSend(rnsh_session_t& s, uint16_t msgtype, const uint8_t* payload, size_t n) {
    PSRAM_BSS static uint8_t scratch[RNSH_STREAM_CHUNK + 8];
    if (s.inboxHandle >= 0)
        sendMsg(s.inboxHandle, msgtype, scratch, sizeof(scratch), payload, n, pdMS_TO_TICKS(200));
}

/* Emit the coalesced stdout buffer as one StreamData, uncompressed (the peer
 * decompresses only when the bit is set). */
void flushStdout(rnsh_session_t& s) {
    if (s.outn == 0) return;
    PSRAM_BSS static uint8_t frame[2 + RNSH_STREAM_CHUNK];
    frame[0] = (uint8_t)(STREAM_STDOUT >> 8);
    frame[1] = (uint8_t)(STREAM_STDOUT & 0xFF);
    memcpy(frame + 2, s.outbuf, s.outn);
    srvSend(s, MT_STREAM, frame, s.outn + 2);
    s.outn = 0;
}

/* CLI backend → remote: accumulate CLI output into the session's stdout buffer.
 * A full chunk is sent immediately (bounds latency for big dumps); a partial
 * tail is flushed on the idle/max timer in rnshServerTask. */
void onBackendRecv(int handle, size_t /*avail*/) {
    rnsh_session_t* s = sessByBackend(handle);
    if (!s) return;
    PSRAM_BSS static uint8_t bbuf[RNSH_STREAM_CHUNK];
    for (;;) {
        size_t n = itsRecv(handle, bbuf, sizeof(bbuf), 0);
        if (n == 0) break;
        size_t off = 0;
        while (off < n) {
            if (s->outn == 0) s->firstByteTick = xTaskGetTickCount();
            size_t space = RNSH_STREAM_CHUNK - s->outn;
            size_t take  = (n - off < space) ? (n - off) : space;
            memcpy(s->outbuf + s->outn, bbuf + off, take);
            s->outn += take;
            off     += take;
            s->lastByteTick = xTaskGetTickCount();
            if (s->outn == RNSH_STREAM_CHUNK) flushStdout(*s);   /* full → send now */
        }
    }
    /* A prompt sitting idle at the tail (the cli emits "<host> $ ") means the
     * command finished — send it now instead of waiting out the idle timer. A
     * false match mid-output just sends a slightly smaller packet, which is fine. */
    if (s->outn >= 3 && memcmp(s->outbuf + s->outn - 3, " $ ", 3) == 0)
        flushStdout(*s);
}

/* CLI backend closed (user exited, or login failed / dropped): report the exit
 * to the remote, then tear the session down so its Channel closes. */
void onBackendDisc(int ref) {
    if (ref < 0 || ref >= RNSH_MAX_SESSIONS) return;
    if (s_sessions[ref].used) {
        ESP_LOGI(TAG, "session %d: CLI backend closed", ref);
        flushStdout(s_sessions[ref]);                           /* don't drop final output */
        uint8_t pl[2]; Buf b{pl, sizeof(pl), 0}; mpUint(b, 0);   /* CommandExited(0) */
        srvSend(s_sessions[ref], MT_EXITED, pl, b.n);
        sessClose(s_sessions[ref]);
    }
}

/* Open the login-gated CLI backend for a session (on ExecuteCommand). */
bool openBackend(rnsh_session_t& s, int ref) {
    cli_color_t color = storageGetInt("s.rnsh.server.color", 0) ? CLI_COLOR : CLI_NO_COLOR;
    cli_connect_t cc = { CLI_ANSI, /*from_usb_serial*/0, color, /*no_prompt*/0, /*login*/1 };
    int b = itsConnect("cli", CLI_PORT_TCP, &cc, sizeof(cc), pdMS_TO_TICKS(500),
                       /*ref*/ref, onBackendRecv, onBackendDisc);
    if (b < 0) { ESP_LOGW(TAG, "session %d: CLI backend connect failed (%d)", ref, b); return false; }
    s.backendHandle = b;
    return true;
}

/* Inbound Channel arrived (rnsd forwarded it). Start the session state machine;
 * the CLI backend is not opened until ExecuteCommand. */
int onInboxConnect(int handle, const void* /*data*/, size_t /*len*/) {
    int i = sessAlloc();
    if (i < 0) { ESP_LOGW(TAG, "no free session slot — rejecting"); return -1; }
    s_sessions[i].used = true;
    s_sessions[i].state = SS_WAIT_VERS;
    s_sessions[i].inboxHandle = handle;
    s_sessions[i].backendHandle = -1;
    ESP_LOGI(TAG, "session %d: inbound rnsh channel (awaiting version)", i);
    return i;
}

/* Remote → session: drive the listener state machine. */
void onInboxRecv(int handle, size_t /*avail*/) {
    rnsh_session_t* s = sessByInbox(handle);
    if (!s) return;
    int ref = (int)(s - s_sessions);

    PSRAM_BSS static uint8_t rxbuf[512];
    PSRAM_BSS static uint8_t decomp[RNSH_MAX_CHUNK];
    for (;;) {
        uint16_t mt; const uint8_t* pl;
        int n = recvMsg(handle, rxbuf, sizeof(rxbuf), &mt, &pl);
        if (n < 0) break;

        switch (s->state) {
            case SS_WAIT_VERS:
                if (mt == MT_VERSION) {
                    uint8_t rp[64]; Buf b{rp, sizeof(rp), 0};
                    mpArray(b, 2); mpStr(b, RNSH_SW_VERSION); mpUint(b, RNSH_PROTO_VER);
                    srvSend(*s, MT_VERSION, rp, b.n);
                    s->state = SS_WAIT_CMD;
                }
                break;

            case SS_WAIT_CMD:
                if (mt == MT_EXEC) {
                    if (!openBackend(*s, ref)) {
                        uint8_t ep[48]; Buf eb{ep, sizeof(ep), 0};
                        mpArray(eb, 3);                      /* ErrorMessage(msg, fatal, data) */
                        mpStr(eb, "backend unavailable");
                        mpBool(eb, true);
                        mpNil(eb);
                        srvSend(*s, MT_ERROR, ep, eb.n);
                        sessClose(*s);
                        return;
                    }
                    s->state = SS_RUNNING;
                    ESP_LOGI(TAG, "session %d: exec → login-gated CLI", ref);
                }
                break;

            case SS_RUNNING:
                if (mt == MT_STREAM && s->backendHandle >= 0) {
                    if (n < 2) break;
                    uint16_t hdr = (uint16_t)((pl[0] << 8) | pl[1]);
                    if ((hdr & STREAM_ID_MASK) != STREAM_STDIN) break;
                    const uint8_t* data = pl + 2;
                    size_t dlen = n - 2;
                    if (hdr & STREAM_COMPRESSED) {
                        size_t dn = rnsdBz2Decompress(data, dlen, decomp, sizeof(decomp));
                        if (dn == 0 && dlen != 0) break;   /* decompress failed */
                        data = decomp; dlen = dn;
                    }
                    if (dlen) itsSend(s->backendHandle, data, dlen, pdMS_TO_TICKS(200));
                    /* stdin EOF: the remote is done. Report the exit and close so
                     * both halves tear down (a stock client waits for this). */
                    if (hdr & STREAM_EOF) {
                        ESP_LOGI(TAG, "session %d: stdin eof — closing", ref);
                        flushStdout(*s);                         /* don't drop final output */
                        uint8_t pl2[2]; Buf b{pl2, sizeof(pl2), 0}; mpUint(b, 0);
                        srvSend(*s, MT_EXITED, pl2, b.n);
                        sessClose(*s);
                        return;
                    }
                }
                /* WINSIZE / NOOP ignored */
                break;
        }
    }
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

  for (;;) {   /* Park, don't delete: this task lives across rns stop/start, so its
                * ITS server ports + client slots are reused, not leaked. */
    TickType_t nextAnnounce = 0;
    /* (Re-)bring-up on entry and on resume: if server mode is enabled, re-host
     * the rnsh destination now. Teardown left s_destHandle == -1, so this re-opens
     * it (and re-listens for channels); the enable-reconcile in the loop then
     * handles any later toggle. */
    if (storageGetInt("s.rnsh.server.enabled", 0) != 0 && s_destHandle < 0)
        serverOpen();
    while (!s_stop) {
        /* Poll fast while any session has stdout pending, so the idle/max flush
         * timer fires on time; otherwise idle at 0.2 Hz. Inbound session bytes and
         * new-session connects are ITS notifies, so input latency is unaffected;
         * this only bounds housekeeping (announce scheduling is wall-clock). */
        bool pending = false;
        for (auto& s : s_sessions) if (s.used && s.outn > 0) { pending = true; break; }
        itsPoll(pdMS_TO_TICKS(pending ? 50 : 5000));

        /* Flush coalesced stdout: 250 ms idle, or 1.5 s since the first byte. */
        TickType_t now = xTaskGetTickCount();
        for (auto& s : s_sessions) {
            if (s.used && s.outn > 0 &&
                ((now - s.lastByteTick)  >= pdMS_TO_TICKS(250) ||
                 (now - s.firstByteTick) >= pdMS_TO_TICKS(1500)))
                flushStdout(s);
        }

        bool en = storageGetInt("s.rnsh.server.enabled", 0) != 0;
        if (en && s_destHandle < 0) { serverOpen(); nextAnnounce = 0; }
        else if (!en && s_destHandle >= 0) { serverClose(); }

        if (s_destHandle >= 0) {
            if (s_announceRequest) { s_announceRequest = false; serverAnnounce(); }
            now = xTaskGetTickCount();
            if (nextAnnounce == 0 || (int32_t)(now - nextAnnounce) >= 0) {
                serverAnnounce();
                int iv = storageGetInt("s.rnsh.server.announce_interval", 1800);
                if (iv <= 0) iv = 1800;
                nextAnnounce = now + pdMS_TO_TICKS(iv * 1000);
            }
        } else {
            s_announceRequest = false;   /* drop stale requests while disabled */
        }
    }   /* end while(!s_stop) */

    /* rns stop: TEARDOWN — close the hosted destination and any live session (each
     * holds a CLI-backend + inbox ITS handle). serverClose disconnects the dest ITS
     * handle so rnsd frees its RNSD_PORT_DEST slot, and tears down each session's
     * backend/inbox handles. Keep the ITS server ports for the next start. Then
     * PARK on the inbox until rnshStart() clears s_stop and notifies. */
    if (s_destHandle >= 0) serverClose();
    s_parked = true;
    info("[%s] stopped", TAG);
    while (s_stop) itsPoll(portMAX_DELAY);
    s_parked = false;
  }
}

} // namespace

/* ═══════════════════════════ rnshd control command ═══════════════════════════ */

/* `rnshd [enable|disable|announce]` — no arg shows status; enable/disable are
 * shortcuts for `set s.rnsh.server.enabled`; announce sends one now. */
static void cliRnshd(const char* args) {
    if (cliWantsHelp(args)) {
        cliPrintf("rnshd [enable|disable|a[nnounce]]  rnsh server control\n");
        cliPrintf("                                  (no arg) show status\n");
        cliPrintf("      enable     turn the server on  (s.rnsh.server.enabled=1)\n");
        cliPrintf("      disable    turn the server off (s.rnsh.server.enabled=0)\n");
        cliPrintf("      a[nnounce] send a destination announce now\n");
        return;
    }

    char sub[16] = {};
    sscanf(args, "%15s", sub);

    if (sub[0] == '\0') {                     /* status */
        if (storageGetInt("s.rnsh.server.enabled", 0) == 0) { cliPrintf("disabled\n"); return; }
        uint8_t dh[RNSD_DEST_HASH_LEN];
        if (rnsdDestinationHash(RNSH_IDENTITY_KEY, "rnsh", "", dh)) {
            char hex[RNSD_DEST_HASH_LEN * 2 + 1];
            for (size_t i = 0; i < RNSD_DEST_HASH_LEN; i++) snprintf(hex + i * 2, 3, "%02x", dh[i]);
            cliPrintf("enabled: %s\n", hex);
        } else {
            cliPrintf("enabled\n");
        }
        return;
    }

    if (strcmp(sub, "enable") == 0) {
        storageSet("s.rnsh.server.enabled", 1);   /* server task reconciles within ~1 s */
        cliPrintf("rnshd: enabled\n");
    } else if (strcmp(sub, "disable") == 0) {
        storageSet("s.rnsh.server.enabled", 0);
        cliPrintf("rnshd: disabled\n");
    } else if (cliVerbIs(sub, "announce", 1)) {
        if (storageGetInt("s.rnsh.server.enabled", 0) == 0) { cliPrintf("rnshd: server disabled\n"); return; }
        s_announceRequest = true;
        cliPrintf("rnshd: announce requested\n");
    } else {
        cliPrintf("usage: rnshd [enable|disable|announce]\n");
    }
}

/* ═══════════════════════════ init ═══════════════════════════ */

/* ── RNS lifecycle hooks (registered with the orchestrator; see rnsServiceRegister) ── */
static void rnshStart(void) {
    s_stop = false;
    if (!s_serverTask)
        s_serverTask = spawnTask(rnshServerTask, TAG, 8192, nullptr, 3, 0, STACK_PSRAM);
    else
        xTaskNotifyGive(s_serverTask);   /* un-park the resident task */
}

static void rnshStop(void) {
    if (!s_serverTask || s_stop) return;
    s_stop = true;
    xTaskNotifyGive(s_serverTask);   /* break the work loop; the task parks, not deleted */
    for (int i = 0; i < 300 && !s_parked; i++) delay(10);   /* await park */
    if (!s_parked) warn("[%s] stop timed out", TAG);
}

void RnshService::onInit() {
    if (storageGetInt("s.rnsh.version", 0) < RNSH_VERSION) {
        storageBegin();
        storageDefault("s.rnsh.server.enabled", 0);
        storageDefault("s.rnsh.server.color", 0);
        storageDefault("s.rnsh.server.announce_interval", 1800);
        storageSet("s.rnsh.version", RNSH_VERSION);
        storageEnd();
    }

    /* Ensure the rnsh identity exists so the client can identify (and the
     * server host under it) regardless of which half runs first. Idempotent. */
    rnsdIdentityGenerate(RNSH_IDENTITY_KEY);

    cliRegisterCmd("rnsh", cliRnsh);
    cliRegisterCmd("rnshd", cliRnshd);

    /* Register with the RNS orchestrator instead of self-spawning: rnsStart()
     * calls rnshStart() (which spawns rnshServerTask) once rnsd is up and past its
     * boot window, and rnsStop() calls rnshStop(). */
    rnsServiceRegister(TAG, rnshStart, rnshStop);
}
