/*
 * Copyright (c) 2019 joshua stein <jcs@jcs.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <err.h>
#include <unistd.h>
#include <signal.h>
#include <endian.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/un.h>

#include <X11/Xlib.h>
#include <X11/Xutil.h>
#include <X11/Xatom.h>
#include <X11/Xft/Xft.h>

#define FONT		"monospace:size=24"
#define FONT_SMALL	"monospace:size=18"
#define DEFAULT_PROMPT	"Tap the security key to continue with signing request"

/* https://tools.ietf.org/html/draft-miller-ssh-agent-03 */
struct agent_msg_hdr {
	uint32_t	len;
	uint8_t		type;
#define SSH_AGENT_IDENTITIES_ANSWER	12
#define SSH_AGENTC_SIGN_REQUEST		13
} __packed;

uint32_t be32bytes(unsigned char *);
void	rollback(int);
int	forward_agent_message(ssize_t, void *, int, pid_t);
void	x11_init(void);
int	x11_prompt(pid_t);
int	procname(pid_t, char **);

static char *auth_sock = NULL, *upstream_auth_sock = NULL;
static char pkcs_key[1024];
static unsigned int pkcs_key_len = 0;
static Display *dpy = NULL;
static XVisualInfo vinfo;
static Colormap colormap;
static XftFont *font, *smallfont;
static XftColor white, gray;
static int upstreamfd = -1;
static int debug = 0;
static char *prompt;

#define DPRINTF(x) { if (debug) { printf x; } };

#ifndef explicit_bzero
#define explicit_bzero(p, s) memset(p, 0, s)
#endif

uint32_t
be32bytes(unsigned char *buf)
{
	return (buf[3] << 0) | (buf[2] << 8) | (buf[1] << 16) | (buf[0] << 24);
}

void
rollback(int sig)
{
	if (upstream_auth_sock != NULL && auth_sock != NULL) {
		DPRINTF(("rollback: %s -> %s\n", upstream_auth_sock,
		    auth_sock));
		if (rename(upstream_auth_sock, auth_sock) == -1)
			warn("rollback rename failed");
	}

	if (sig)
		_exit(0);
}

int
main(int argc, char *argv[])
{
	struct sockaddr_un sunaddr;
	struct sockpeercred peercred;
	struct pollfd pfd[2];
	ssize_t len;
	socklen_t slen;
	unsigned char buf[4096];
	uid_t euid;
	gid_t egid;
	int ch, sock, clientfd = -1;

	prompt = strdup(DEFAULT_PROMPT);

	while ((ch = getopt(argc, argv, "dp:")) != -1) {
		switch (ch) {
		case 'd':
			debug++;
			break;
		case 'p':
			free(prompt);
			prompt = strdup(optarg);
			if (prompt == NULL)
				err(1, "strdup");
			break;
		default:
			exit(1);
		}
	}
	argc -= optind;
	argv += optind;

	if ((auth_sock = getenv("SSH_AUTH_SOCK")) == NULL)
		errx(1, "no SSH_AUTH_SOCK set");

	len = strlen(auth_sock) + 6;
	if ((upstream_auth_sock = malloc(len)) == NULL)
		err(1, "malloc");

	/* do this early so we can pledge */
	x11_init();

	/* move aside and let the man go through */
	snprintf(upstream_auth_sock, len, "%s.orig", auth_sock);
	DPRINTF(("%s -> %s\n", auth_sock, upstream_auth_sock));
	rename(auth_sock, upstream_auth_sock);

	/* listen on SSH_AUTH_SOCK path */
	memset(&sunaddr, 0, sizeof(sunaddr));
	sunaddr.sun_family = AF_UNIX;
	if (strlcpy(sunaddr.sun_path, auth_sock,
	    sizeof(sunaddr.sun_path)) >= sizeof(sunaddr.sun_path)) {
	    	rollback(0);
		err(1, "strlcpy");
	}

	sock = socket(PF_UNIX, SOCK_STREAM, 0);
	if (sock == -1) {
	    	rollback(0);
		err(1, "socket");
	}

	if (bind(sock, (struct sockaddr *)&sunaddr, sizeof(sunaddr)) == -1) {
		rollback(0);
		err(1, "bind");
	}

	if (listen(sock, 128) == -1) {
		rollback(0);
		err(1, "listen");
	}

#ifdef __OpenBSD__
	if (unveil(auth_sock, "rwc") == -1)
		err(1, "unveil");
	if (unveil(upstream_auth_sock, "rwc") == -1)
		err(1, "unveil");
	if (pledge("stdio unix rpath cpath ps", NULL) == -1)
		err(1, "pledge");
#endif

	signal(SIGPIPE, SIG_IGN);
	signal(SIGINT, rollback);
	signal(SIGTERM, rollback);

	/* forward connections to SSH_AUTH_SOCK to SSH_AUTH_SOCK+.orig */
	for (;;) {
		clientfd = accept(sock, (struct sockaddr *)&sunaddr, &slen);
		if (clientfd == -1) {
			warn("accept");
			continue;
		}

		if (getpeereid(clientfd, &euid, &egid) == -1) {
			warn("getpeereid");
			goto close;
		}

		if (euid != 0 && getuid() != euid) {
			warn("socket peer uid %u != uid %u", (u_int)euid,
			    (u_int)getuid());
			goto close;
		}

		if (getsockopt(clientfd, SOL_SOCKET, SO_PEERCRED, &peercred,
		    &slen) == -1) {
			warn("getsockopt(SO_PEERCRED)");
			goto close;
		}

		if ((upstreamfd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
			warn("socket");
			goto close;
		}

		memset(&sunaddr, 0, sizeof(sunaddr));
		sunaddr.sun_family = AF_UNIX;
		if (strlcpy(sunaddr.sun_path, upstream_auth_sock,
		    sizeof(sunaddr.sun_path)) >= sizeof(sunaddr.sun_path)) {
			warn("strlcpy");
			goto close;
		}

		if (connect(upstreamfd, (struct sockaddr *)&sunaddr,
		    sizeof(sunaddr)) == -1) {
			warn("connect to upstream");
			goto close;
		}

		pkcs_key_len = 0;

		DPRINTF(("got client connection and upstream connection\n"));

		memset(&pfd, 0, sizeof(pfd));
		pfd[0].fd = clientfd;
		pfd[0].events = POLLIN;
		pfd[1].fd = upstreamfd;
		pfd[1].events = POLLIN;

		for (;;) {
			if (poll(pfd, 2, INFTIM) == -1) {
				warn("poll failed");
				goto close;
			}

			if ((pfd[0].revents & (POLLIN|POLLHUP))) {
				/* client -> upstream */
				len = read(clientfd, buf, sizeof(buf));
				DPRINTF(("got client data (%zu)\n", len));
				if (len && (forward_agent_message(len, &buf,
				    upstreamfd, peercred.pid) == -1))
					goto close;
				if (pfd[0].revents & POLLHUP)
					goto close;
			}

			if ((pfd[1].revents & (POLLIN|POLLHUP))) {
				/* upstream -> client */
				len = read(upstreamfd, buf, sizeof(buf));
				DPRINTF(("got upstream data (%zu)\n", len));
				if (len && (forward_agent_message(len, &buf,
				    clientfd, peercred.pid) == -1))
					goto close;
				if (pfd[1].revents & POLLHUP)
					goto close;
			}
		}

	close:
		explicit_bzero(&buf, sizeof(buf));
		explicit_bzero(&pkcs_key, sizeof(pkcs_key));

		if (clientfd != -1) {
			close(clientfd);
			clientfd = -1;
		}
		if (upstreamfd != -1) {
			close(upstreamfd);
			upstreamfd = -1;
		}
	}

	if (dpy)
		XCloseDisplay(dpy);

	rollback(0);

	return 0;
}

int
forward_agent_message(ssize_t len, void *buf, int destfd, pid_t clientpid)
{
	struct agent_msg_hdr *hdr = (struct agent_msg_hdr *)buf;
	uint32_t nkeys, klen;
	ssize_t off;
	int x;

	if (debug >= 2) {
		DPRINTF(("forwarding data[%zu]:", len));
		for (x = 0; x < len; x++)
			DPRINTF((" %02x", ((unsigned char *)buf)[x]));
		DPRINTF(("\n"));
	}

	if (len < sizeof(struct agent_msg_hdr)) {
		warnx("short message (%zu < %zu)", len,
		    sizeof(struct agent_msg_hdr));
		return -1;
	}

	if (len != (be32toh(hdr->len) + sizeof(uint32_t))) {
		warn("message invalid len (%zu != %d + %zu)", len,
		    be32toh(hdr->len), sizeof(uint32_t));
		return -1;
	}

	if (write(destfd, buf, len) != len) {
		warn("write to destfd failed");
		return -1;
	}

	off = sizeof(struct agent_msg_hdr);
	len -= off;
	buf += off;

	/*
	 * The normal process for an SSH connection is for SSH to make an
	 * SSH_AGENTC_REQUEST_IDENTITIES request to the agent, the agent
	 * replies with SSH_AGENT_IDENTITIES_ANSWER with all of the key
	 * information, and then SSH makes a SSH_AGENTC_SIGN_REQUEST request
	 * with that key.
	 *
	 * Watch for a SSH_AGENT_IDENTITIES_ANSWER message and parse out the
	 * keys, making note of which key has a comment that looks like a pkcs
	 * key, so when we see that key blob in SSH_AGENTC_SIGN_REQUEST, we
	 * know it's for our key that needs a touch confirmation.
	 */
	switch (hdr->type) {
	case SSH_AGENT_IDENTITIES_ANSWER:
		if (len < sizeof(uint32_t)) {
			DPRINTF(("SSH_AGENT_IDENTITIES_ANSWER but remaining "
			    "len too short\n"));
			break;
		}

		nkeys = be32bytes(buf);
		len -= sizeof(uint32_t);
		buf += sizeof(uint32_t);
		if (nkeys <= 0)
			break;

		DPRINTF(("SSH_AGENT_IDENTITIES_ANSWER with %d key(s)\n",
		    nkeys));

		for (x = 0; x < nkeys && len > 0; x++) {
			uint32_t kbloblen, kcommlen;
			char *kblob, *kcomm;

			/* key blob len */
			if (len < sizeof(uint32_t)) {
				warn("SSH_AGENT_IDENTITIES_ANSWER short (1)");
				break;
			}
			kbloblen = be32bytes(buf);
			len -= sizeof(uint32_t);
			buf += sizeof(uint32_t);

			if (kbloblen > len) {
				warn("SSH_AGENT_IDENTITIES_ANSWER short (2)");
				break;
			}
			if (kbloblen <= 0)
				continue;

			/* key blob */
			len -= kbloblen;
			kblob = buf;
			buf += kbloblen;

			/* key comment len */
			if (len < sizeof(uint32_t)) {
				warn("SSH_AGENT_IDENTITIES_ANSWER short (3)");
				break;
			}
			kcommlen = be32bytes(buf);
			len -= sizeof(uint32_t);
			buf += sizeof(uint32_t);

			if (kcommlen > len) {
				warn("SSH_AGENT_IDENTITIES_ANSWER short (4)");
				break;
			}
			if (kcommlen <= 0)
				continue;

			/* key comment */
			kcomm = malloc(kcommlen + 2);
			if (kcomm == NULL) {
				warn("malloc %d", kcommlen + 2);
				break;
			}
			strlcpy(kcomm, buf, kcommlen + 1);
			DPRINTF(("key[%d] = %s\n", x, kcomm));

			/* match on pkcs11 or pkcs15 */
			if (strstr(kcomm, "pkcs1")) {
				DPRINTF(("found pkcs1 key at %d\n", x));
				pkcs_key_len = kbloblen;
				memcpy(pkcs_key, kblob, kbloblen);
			}
			free(kcomm);

			len -= kcommlen;
			buf += kcommlen;
		}
		break;

	case SSH_AGENTC_SIGN_REQUEST:
		/* key blob len */
		if (len < sizeof(uint32_t)) {
			DPRINTF(("SSH_AGENTC_SIGN_REQUEST but remaining "
			    "len too short\n"));
			break;
		}
		klen = be32bytes(buf);
		len -= sizeof(uint32_t);
		buf += sizeof(uint32_t);

		if (klen > len) {
			warn("SSH_AGENTC_SIGN_REQUEST short (1)");
			break;
		}
		if (klen <= 0)
			break;

		if (klen > 0 && klen == pkcs_key_len &&
		    memcmp(buf, pkcs_key, pkcs_key_len) == 0) {
			DPRINTF(("SSH_AGENTC_SIGN_REQUEST for our pkcs key\n"));
			if (x11_prompt(clientpid) == -1)
				return -1;
		}
	}

	return 0;
}

void
x11_init(void)
{
	dpy = XOpenDisplay(NULL);
	if (!dpy)
		errx(1, "XOpenDisplay failed");

	if (!XMatchVisualInfo(dpy, DefaultScreen(dpy), 32, TrueColor, &vinfo))
		errx(1, "!XMatchVisualInfo failed");

	colormap = XCreateColormap(dpy, DefaultRootWindow(dpy), vinfo.visual,
	    AllocNone);

	font = XftFontOpenName(dpy, DefaultScreen(dpy), FONT);
	if (font == NULL)
		errx(1, "failed opening font");

	smallfont = XftFontOpenName(dpy, DefaultScreen(dpy), FONT_SMALL);
	if (smallfont == NULL)
		errx(1, "failed opening small font");

	if (!XftColorAllocName(dpy, vinfo.visual, colormap, "white", &white))
		errx(1, "failed allocating white");
	if (!XftColorAllocName(dpy, vinfo.visual, colormap, "#eeeeee", &gray))
		errx(1, "failed allocating gray");
}

int
x11_prompt(pid_t clientpid)
{
	XSetWindowAttributes attr;
	Window win;
	XEvent ev;
	XftDraw *draw;
	XGlyphInfo gi;
	struct pollfd pfd[2];
	size_t len;
	char *clientproc, *word, *line;
	int grab, x, y, ret = -1;

	attr.colormap = colormap;
	attr.override_redirect = 1;
	attr.border_pixel = 0;
	attr.background_pixel = 0x28000000; /* 40% opacity */

	win = XCreateWindow(dpy, DefaultRootWindow(dpy), 0, 0,
	    DisplayWidth(dpy, DefaultScreen(dpy)),
	    DisplayHeight(dpy, DefaultScreen(dpy)), 0,
	    vinfo.depth, InputOutput, vinfo.visual,
	    CWOverrideRedirect|CWColormap|CWBorderPixel|CWBackPixel, &attr);

	draw = XftDrawCreate(dpy, win, vinfo.visual, colormap);
	if (!draw) {
		warnx("can't draw with font");
		ret = -1;
		goto done_x;
	}

	/* and now if we can't grab the keyboard, pinentry probably has it */
	for (x = 0; x < 30; x++) {
		grab = XGrabKeyboard(dpy, DefaultRootWindow(dpy), True,
		    GrabModeAsync, GrabModeAsync, CurrentTime);
		if (grab == GrabSuccess)
			break;

		warn("couldn't grab keyboard");
		sleep(1);
	}
	if (grab != GrabSuccess) {
		warn("couldn't grab keyboard, giving up");
		ret = -1;
		goto done_x;
	}

	XMapRaised(dpy, win);

	/* draw prompt */
	XftTextExtentsUtf8(dpy, font, (FcChar8 *)prompt, strlen(prompt), &gi);
	y = (DisplayHeight(dpy, DefaultScreen(dpy)) / 2) - (gi.height * 1.2);
	XftDrawStringUtf8(draw, &white, font,
	    (DisplayWidth(dpy, DefaultScreen(dpy)) / 2) - (gi.width / 2), y,
	    (FcChar8 *)prompt, strlen(prompt));
	y += (gi.height * 1.3);

	/* then add process info */
	if (procname(clientpid, &clientproc) == -1) {
		clientproc = strdup("(failed finding process info)");
		if (clientproc == NULL)
			err(1, "malloc");
	}
	line = malloc(strlen(clientproc) + 20);
	if (line == NULL)
		err(1, "malloc");
	snprintf(line, strlen(clientproc) + 20, "PID %d: %s", clientpid,
	    clientproc);
	clientproc = line;

	/* process info may be long, so wrap it to multiple lines */
	line = strdup("");
	if (line == NULL)
		err(1, "strdup");
	for ((word = strsep(&clientproc, " ")); word && *word != '\0';
	    (word = strsep(&clientproc, " "))) {
		char *oldline = strdup(line);
		if (oldline == NULL)
			err(1, "strdup");

	    	len = strlen(line) + 1 + strlen(word) + 1;
		line = realloc(line, len);

		if (line[0] != '\0')
			strlcat(line, " ", len);

		strlcat(line, word, len);

		XftTextExtentsUtf8(dpy, smallfont, (FcChar8 *)line,
		    strlen(line), &gi);
		if (gi.width > (DisplayWidth(dpy, DefaultScreen(dpy)) * 0.9)) {
			/* this line is now too long, draw the old one */
			XftTextExtentsUtf8(dpy, smallfont, (FcChar8 *)oldline,
			    strlen(oldline), &gi);
			XftDrawStringUtf8(draw, &gray, smallfont,
			    (DisplayWidth(dpy, DefaultScreen(dpy)) / 2) -
			    (gi.width / 2), y, (FcChar8 *)oldline,
			    strlen(oldline));
			y += (gi.height * 1.2);

			free(line);
			line = strdup(word);
			if (line == NULL)
				err(1, "strdup");
		}
	}

	if (line != NULL && line[0] != '\0') {
		XftTextExtentsUtf8(dpy, smallfont, (FcChar8 *)line,
		    strlen(line), &gi);
		XftDrawStringUtf8(draw, &gray, smallfont,
		    (DisplayWidth(dpy, DefaultScreen(dpy)) / 2) -
		    (gi.width / 2), y, (FcChar8 *)line, strlen(line));
		free(line);
	}
	free(clientproc);

	XSelectInput(dpy, win, StructureNotifyMask);
	XSync(dpy, False);

	memset(&pfd, 0, sizeof(pfd));
	pfd[0].fd = ConnectionNumber(dpy);
	pfd[0].events = POLLIN;
	pfd[1].fd = upstreamfd;
	pfd[1].events = POLLIN;

	for (;;) {
		if (poll(pfd, 2, INFTIM) < 1)
			continue;

		if ((pfd[0].revents & (POLLIN|POLLHUP))) {
			XNextEvent(dpy, &ev);
			DPRINTF(("got X11 event of type %d\n", ev.type));
			if (ev.type == KeyPress) {
				if (XLookupKeysym(&ev.xkey, 0) == XK_Escape) {
					DPRINTF(("escape pressed\n"));
					ret = -1;
					break;
				} else {
					DPRINTF(("key pressed, not escape\n"));
				}
			} else {
				DPRINTF(("got other X11 event, re-raising\n"));
				XRaiseWindow(dpy, win);
			}
		}

		if ((pfd[1].revents & (POLLIN|POLLHUP))) {
			/*
			 * gpg-agent is sending back data from
			 * SSH_AGENTC_SIGN_REQUEST, the key was touched
			 */
			DPRINTF(("got data from upstream, key must have been "
			    "touched\n"));
			ret = 0;
			break;
		}
	}

done_x:
	XftDrawDestroy(draw);
	XUngrabKeyboard(dpy, CurrentTime);
	XDestroyWindow(dpy, win);
	XSync(dpy, False);

	return ret;
}

int
procname(pid_t pid, char **outbuf)
{
#ifdef __OpenBSD__
	char *buf = NULL, **args;
	size_t buflen = 128;
	int mib[6] = { CTL_KERN, KERN_PROC_ARGS, 0, KERN_PROC_ARGV, 0, 0 };

	buf = malloc(buflen);
	if (buf == NULL)
		err(1, "malloc");

	/* fetch process args */
	mib[0] = CTL_KERN;
	mib[1] = KERN_PROC_ARGS;
	mib[2] = pid;
	mib[3] = KERN_PROC_ARGV;

	/* keep increasing buf size until it fits */
	while (sysctl(mib, 4, buf, &buflen, NULL, 0) == -1) {
		if (errno != ENOMEM) {
			free(buf);
			return -1;
		}

		if ((buf = realloc(buf, buflen + 128)) == NULL)
			err(1, "realloc");
		buflen += 128;
	}

	args = (char **)buf;
	if (args[0] == NULL) {
		free(buf);
		return -1;
	}

	*outbuf = malloc(1);
	if (*outbuf == NULL)
		err(1, "malloc");

	*outbuf[0] = '\0';
	buflen = 1;
	while (*args != NULL) {
		if (*outbuf[0] != '\0')
			buflen += 1;
		buflen += strlen(*args) + 1;
		*outbuf = realloc(*outbuf, buflen);
		if (*outbuf == NULL)
			err(1, "realloc");
		if (*outbuf[0] != '\0')
			strlcat(*outbuf, " ", buflen);
		strlcat(*outbuf, *args, buflen);
		args++;
	}

	DPRINTF(("PID %d: %s\n", pid, *outbuf));

	free(buf);
	return 0;
#else
	warn("procname not implemented");
	return -1;
#endif
}
