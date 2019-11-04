# vim:ts=8

PREFIX?=	/usr/local
X11BASE?=	/usr/X11R6
SYSCONFDIR?=	/etc

PKGLIBS=	x11 xft

CC?=		cc
CFLAGS+=	-O2 -Wall \
		-Wunused -Wmissing-prototypes -Wstrict-prototypes \
		-Wpointer-sign \
		`pkg-config --cflags ${PKGLIBS}`
LDFLAGS+=	`pkg-config --libs ${PKGLIBS}`

# uncomment to enable debugging
#CFLAGS+=	-g

BINDIR=		$(PREFIX)/bin
MANDIR=		$(PREFIX)/man/man1

SRC!=		ls *.c
OBJ=            ${SRC:.c=.o}

BIN=		ssh-agent-card-prompt
MAN=		ssh-agent-card-prompt.1

all: ${BIN}

ssh-agent-card-prompt: $(OBJ)
	$(CC) -o $@ $(OBJ) $(LDFLAGS)

install: all
	mkdir -p $(BINDIR) $(MANDIR)
	install -s $(BIN) $(BINDIR)
	install -m 644 $(MAN) $(MANDIR)

clean:
	rm -f $(BIN) $(OBJ)

.PHONY: all install clean
