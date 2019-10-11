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
#include <err.h>
#include <unistd.h>
#include <signal.h>
#include <endian.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <X11/Xlib.h>
#include <X11/Xutil.h>
#include <X11/Xatom.h>
#include <X11/Xft/Xft.h>

#define TOUCH_PROMPT "Please tap the security key to continue with SSH signing request"

/* https://tools.ietf.org/html/draft-miller-ssh-agent-03 */
struct agent_msg_hdr {
	uint32_t	len;
	uint8_t		type;
#define SSH_AGENT_IDENTITIES_ANSWER	12
#define SSH_AGENTC_SIGN_REQUEST		13
} __packed;

uint32_t be32bytes(unsigned char *);
void	rollback(int);
int	forward_agent_message(ssize_t, void *, int);
void	x11_init(void);
int	x11_prompt(char *);

static char *auth_sock = NULL, *upstream_auth_sock = NULL;
static char pkcs_key[1024];
static unsigned int pkcs_key_len = 0;
static Display *dpy = NULL;
static XVisualInfo vinfo;
static Colormap colormap;
static XftFont *font;
static XftColor xftcolor;
static int upstreamfd = -1;
static int debug = 0;

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
	struct pollfd pfd[2];
	ssize_t len;
	socklen_t slen;
	unsigned char buf[4096];
	uid_t euid;
	gid_t egid;
	int ch, sock, clientfd = -1;

	while ((ch = getopt(argc, argv, "d")) != -1) {
		switch (ch) {
		case 'd':
			debug++;
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
	if (pledge("stdio unix rpath cpath", NULL) == -1)
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
				    upstreamfd) == -1))
					goto close;
				if (pfd[0].revents & POLLHUP)
					goto close;
			}

			if ((pfd[1].revents & (POLLIN|POLLHUP))) {
				/* upstream -> client */
				len = read(upstreamfd, buf, sizeof(buf));
				DPRINTF(("got upstream data (%zu)\n", len));
				if (len && (forward_agent_message(len, &buf,
				    clientfd) == -1))
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
forward_agent_message(ssize_t len, void *buf, int destfd)
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
			DPRINTF(("SSH_AGENTC_SIGN_REQUEST for our "
			    "pkcs key\n"));
			if (x11_prompt(TOUCH_PROMPT) == -1)
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

	font = XftFontOpenName(dpy, DefaultScreen(dpy), "monospace:size=30");
	if (font == NULL)
		errx(1, "failed opening font");

	if (!XftColorAllocName(dpy, vinfo.visual, colormap, "white", &xftcolor))
		errx(1, "failed allocating xft color");
}

int
x11_prompt(char *string)
{
	XSetWindowAttributes attr;
	Window win;
	XEvent ev;
	XftDraw *draw;
	XGlyphInfo gi;
	struct pollfd pfd[2];
	int grab, x, ret = -1;

	attr.colormap = colormap;
	attr.override_redirect = 1;
	attr.border_pixel = 0;
	attr.background_pixel = 0x01010101;

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

	XftTextExtentsUtf8(dpy, font, (FcChar8 *)string, strlen(string), &gi);
	XftDrawStringUtf8(draw, &xftcolor, font,
	    (DisplayWidth(dpy, DefaultScreen(dpy)) / 2) - (gi.width / 2),
	    (DisplayHeight(dpy, DefaultScreen(dpy)) / 2) - (gi.height / 2),
	    (FcChar8 *)string, strlen(string));

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
