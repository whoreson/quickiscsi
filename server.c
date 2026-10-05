/*
 * server.c -- main iSCSI daemon loop for quickiscsi
 *
 * - Binds TCP port 3260
 * - select() event loop: accepts new connections, drives sessions
 * - Handles SIGINT/SIGTERM for clean shutdown (POSIX)
 * - Windows: console ctrl handler
 *
 * Usage: quickiscsi [-c config_file] [-v]
 * Default config: ./quickiscsi.conf or /etc/quickiscsi.conf
 *
 * C89 clean.
 */

#include "compat.h"
#include "config.h"
#include "session.h"
#include "iscsi.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <poll.h>

#if !defined(_WIN32)
#   include <signal.h>
#endif

/* -------------------------------------------------------------------------
 * Signal / shutdown flag
 * ---------------------------------------------------------------------- */

#if defined(_WIN32)
static volatile int g_quit = 0;
#else
static volatile sig_atomic_t g_quit = 0;
#endif

#if defined(_WIN32)
#   include <windows.h>
    static BOOL WINAPI console_ctrl_handler(DWORD type)
    {
        QD_UNUSED(type);
        g_quit = 1;
        return TRUE;
    }
#else
#   include <signal.h>
    static void sig_handler(int sig)
    {
        (void)sig;
        g_quit = 1;
    }
#endif

/* -------------------------------------------------------------------------
 * Session pool
 * ---------------------------------------------------------------------- */

#define MAX_SESSIONS ISCSI_MAX_SESSIONS

static session_t *g_sessions[MAX_SESSIONS];
static int        g_num_sessions = 0;

/*
 * Global monotone StatSN seed.
 *
 * Every new session gets a unique starting StatSN drawn from this counter,
 * which is incremented on each accepted connection.  Seeding from time(NULL)
 * at startup means the baseline also advances across server restarts, so
 * open-iscsi (which keeps its own ExpStatSN state across TCP reconnects for
 * the entire daemon lifetime) never sees a StatSN it has previously
 * acknowledged -- not within a run, and not after a restart.
 *
 * Why this matters:
 *   open-iscsi maintains a per-portal ExpStatSN counter.  If a new session
 *   starts with a StatSN <= the last one open-iscsi acknowledged, it treats
 *   every Data-In and SCSI Response as a duplicate and drops them, which
 *   triggers another reconnect.  This produces the login->INQUIRY->close
 *   loop seen when a naive target always starts at StatSN=0 or StatSN=1.
 *
 *   FreeBSD iscontrol resynchronises its tracking from whatever StatSN it
 *   receives, so it is tolerant of repeated values.  open-iscsi is not.
 *
 * Every session starts at StatSN=1.  During the login handshake, session.c
 * may raise stat_sn to match the initiator's ExpStatSN (following the istgt
 * approach).  This handles both open-iscsi reconnects (high ExpStatSN) and
 * FreeBSD new sessions (ExpStatSN=0, kept at 1).
 */

static void session_add(session_t *s)
{
    int i;
    for (i = 0; i < MAX_SESSIONS; i++) {
        if (!g_sessions[i]) {
            g_sessions[i] = s;
            g_num_sessions++;
            return;
        }
    }
    /* No room: close immediately */
    fprintf(stderr, "server: session pool full, dropping connection\n");
    qd_close_sock(s->sock);
    session_free(s);
}

static void session_remove(int idx)
{
    session_t *s = g_sessions[idx];
    if (!s) return;
    qd_close_sock(s->sock);
    session_free(s);
    g_sessions[idx] = NULL;
    g_num_sessions--;
}

/* -------------------------------------------------------------------------
 * fd_set helpers (Windows SOCKET vs POSIX int)
 * ---------------------------------------------------------------------- */

static qd_sock_t fd_max(qd_sock_t listen_sock)
{
    qd_sock_t mx = listen_sock;
    int i;
    for (i = 0; i < MAX_SESSIONS; i++) {
        if (g_sessions[i]) {
#if defined(_WIN32)
            /* Winsock SOCKET is UINT_PTR; fd_set doesn't use max */
            QD_UNUSED(mx);
#else
            if (g_sessions[i]->sock > mx)
                mx = g_sessions[i]->sock;
#endif
        }
    }
    return mx;
}

/* -------------------------------------------------------------------------
 * print_usage
 * ---------------------------------------------------------------------- */

static void print_usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s [-c config] [-v]\n"
        "  -c config   Config file (default: quickiscsi.conf)\n"
        "  -v          Verbose: dump config at startup\n"
        "\n"
        "Example config (quickiscsi.conf):\n"
        "\n"
        "  [target \"data\"]\n"
        "  iqn     = iqn.homelab:data\n"
        "  backend = file\n"
        "  path    = /var/iscsi/data.img\n"
        "  size    = 20G\n"
        "\n"
        "  [target \"ram\"]\n"
        "  iqn     = iqn.homelab:ram\n"
        "  backend = ramdisk\n"
        "  size    = 512M\n"
        "\n"
        "  [target \"raw\"]\n"
        "  iqn     = iqn.homelab:raw\n"
        "  backend = block\n"
        "  path    = /dev/sdb\n",
        prog);
}

/* -------------------------------------------------------------------------
 * main
 * ---------------------------------------------------------------------- */

int main(int argc, char *argv[])
{
    const char  *config_path = NULL;
    int          verbose = 0;
    int          i;
    config_t     cfg;
    qd_sock_t    listen_sock;
    struct sockaddr_in  addr;
    int          opt;

    /* Parse arguments */
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-c") == 0 && i + 1 < argc) {
            config_path = argv[++i];
        } else if (strcmp(argv[i], "-v") == 0) {
            verbose = 1;
        } else if (strcmp(argv[i], "-h") == 0 ||
                   strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }

    /* Default config paths */
    if (!config_path) {
        FILE *f = fopen("quickiscsi.conf", "r");
        if (f) { fclose(f); config_path = "quickiscsi.conf"; }
        else   { config_path = "/etc/quickiscsi.conf"; }
    }

    printf("quickiscsi starting on platform: %s\n", QD_PLATFORM);

    /* Initialize sockets */
    QD_SOCK_INIT();

    /* Parse and open backends */
    if (config_parse(config_path, &cfg) != 0) {
        fprintf(stderr, "Fatal: config parse failed\n");
        QD_SOCK_CLEANUP();
        return 1;
    }

    {
        int opened = config_open_backends(&cfg);
        if (opened == 0 && cfg.num_targets > 0) {
            fprintf(stderr, "Fatal: no backends opened\n");
            config_free(&cfg);
            QD_SOCK_CLEANUP();
            return 1;
        }
    }

    if (verbose) config_dump(&cfg);

    /* Create listening socket */
    listen_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_sock == QD_INVALID_SOCK) {
        fprintf(stderr, "socket() failed: %d\n", qd_sock_errno());
        config_free(&cfg);
        QD_SOCK_CLEANUP();
        return 1;
    }

    opt = 1;
    setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR,
               (const char *)&opt, sizeof(opt));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port        = htons(ISCSI_PORT);

    if (bind(listen_sock, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        fprintf(stderr, "bind() on port %d failed: %d\n",
                ISCSI_PORT, qd_sock_errno());
        qd_close_sock(listen_sock);
        config_free(&cfg);
        QD_SOCK_CLEANUP();
        return 1;
    }

    if (listen(listen_sock, 8) != 0) {
        fprintf(stderr, "listen() failed: %d\n", qd_sock_errno());
        qd_close_sock(listen_sock);
        config_free(&cfg);
        QD_SOCK_CLEANUP();
        return 1;
    }

    printf("quickiscsi listening on port %d\n", ISCSI_PORT);
    printf("quickiscsi targets: %d configured\n", cfg.num_targets);

    /* Seed the StatSN counter.  Starts at 1; session.c may raise it
     * during login to match the initiator's ExpStatSN. */

    /* Install signal handlers */
#if defined(_WIN32)
    SetConsoleCtrlHandler(console_ctrl_handler, TRUE);
#else
    /* Use signal() -- it's C89 standard; sigaction would need _POSIX_C_SOURCE */
    signal(SIGINT,  sig_handler);
    signal(SIGTERM, sig_handler);
    /* SIGPIPE: ignore broken pipe errors on write */
    signal(SIGPIPE, SIG_IGN);
#endif

    /* Set listen socket non-blocking */
    QD_SET_NONBLOCK(listen_sock);

    memset(g_sessions, 0, sizeof(g_sessions));

    /* -----------------------------------------------------------------------
     * Main select() loop
     * -------------------------------------------------------------------- */
    while (!g_quit) {
        fd_set   readfds;
        struct timeval tv;
        int      nready;
        qd_sock_t maxfd;

        FD_ZERO(&readfds);
        FD_SET(listen_sock, &readfds);

        maxfd = fd_max(listen_sock);

        for (i = 0; i < MAX_SESSIONS; i++) {
            if (g_sessions[i])
                FD_SET(g_sessions[i]->sock, &readfds);
        }

        tv.tv_sec  = 5;
        tv.tv_usec = 0;

#if defined(_WIN32)
        nready = select(0, &readfds, NULL, NULL, &tv);
#else
        nready = select((int)(maxfd + 1), &readfds, NULL, NULL, &tv);
#endif

        if (nready < 0) {
            if (qd_would_block() || qd_sock_errno() == 4 /*EINTR*/)
                continue;
            fprintf(stderr, "select() error: %d\n", qd_sock_errno());
            break;
        }

        if (nready == 0) {
            /* Timeout: can send NOP-In pings here in future */
            continue;
        }

        /* New connection? */
        if (FD_ISSET(listen_sock, &readfds)) {
            struct sockaddr_in peer;
            qd_socklen_t plen = sizeof(peer);
            qd_sock_t    csock;

            csock = accept(listen_sock,
                           (struct sockaddr *)&peer, &plen);
            if (csock != QD_INVALID_SOCK) {
                session_t *ns;
                struct sockaddr_in local;
                qd_socklen_t local_len = sizeof(local);
                char addr_str[64] = "0.0.0.0";

                /* Get our local address for SendTargets */
                if (getsockname(csock, (struct sockaddr *)&local, &local_len) == 0) {
                    strncpy(addr_str, inet_ntoa(local.sin_addr), sizeof(addr_str) - 1);
                }

                /* Disable Nagle: iSCSI is latency-sensitive */
                {
                    int nodelay = 1;
                    setsockopt(csock, 6 /*IPPROTO_TCP*/, 1 /*TCP_NODELAY*/,
                               (const char *)&nodelay, sizeof(nodelay));
                }
                ns = session_new(csock, &cfg, 1, addr_str);
                if (ns) {
                    printf("server: new connection from %s\n",
                           inet_ntoa(peer.sin_addr));
                    session_add(ns);
                } else {
                    fprintf(stderr, "server: out of memory for session\n");
                    qd_close_sock(csock);
                }
            }
        }

        /* Drive existing sessions */
        for (i = 0; i < MAX_SESSIONS; i++) {
            session_t *s = g_sessions[i];
            if (!s) continue;

            /* Check if socket is readable using poll with a short timeout.
             * This avoids blocking in recv_exact when no data is available,
             * while still allowing rapid R2T/DATA-OUT processing. */
            {
                struct pollfd pfd;
                int prc;
                pfd.fd = (int)s->sock;
                pfd.events = POLLIN;
                pfd.revents = 0;
                prc = poll(&pfd, 1, 0);  /* non-blocking poll */
                if (prc <= 0 || !(pfd.revents & POLLIN)) continue;
            }

            {
                int rc = session_drive(s);
                if (rc == -1 || s->state == SESS_CLOSED) {
                    printf("server: session closed\n");
                    session_remove(i);
                }
            }
        }
    }

    /* Cleanup */
    printf("quickiscsi shutting down\n");
    for (i = 0; i < MAX_SESSIONS; i++) {
        if (g_sessions[i]) session_remove(i);
    }
    qd_close_sock(listen_sock);
    config_free(&cfg);
    QD_SOCK_CLEANUP();
    return 0;
}
