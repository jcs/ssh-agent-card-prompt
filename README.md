# ssh-agent-card-prompt

![https://jcs.org/images/ssh-agent-card-prompt.png](https://jcs.org/images/ssh-agent-card-prompt.png)

**ssh-agent-card-prompt** - intercept
ssh-agent(1)
requests for SSH key signing that requires tapping a physical security
key and prompt the user

# SYNOPSIS

**ssh-agent-card-prompt**
\[**-d**]
\[**-p**&nbsp;*prompt*]

# DESCRIPTION

On startup,
**ssh-agent-card-prompt**
moves the current
ssh-agent(1)
socket
(as set in the SSH\_AUTH\_SOCK environment variable)
to a temporary location and listens itself on that socket.

When an SSH client connects,
**ssh-agent-card-prompt**
connects to the original ssh-agent process and proxies requests and responses
between the two.

When
**ssh-agent-card-prompt**
detects an SSH\_AGENTC\_SIGN\_REQUEST message that appears to be for a PKCS key,
it presents a modal X11 window with the
*prompt*
text and information about the process that is making the SSH agent connection.

If the Escape key is pressed while presenting the dialog, the connections to
the client and ssh-agent are dropped.
If the security key is tapped, the original ssh-agent will send a response
and
**ssh-agent-card-prompt**
will automatically close its X11 window.

When
**ssh-agent-card-prompt**
exits, the original ssh-agent socket is moved back into place.

# OPTIONS

**-d**

> Print debugging messages to the terminal.
> If specified twice, the contents of each message passed will be printed to the
> terminal.

**-p** *prompt*

> The text presented to the user in the modal dialog.
> Defaults to "Tap the security key to continue with signing request".

# AUTHORS

**ssh-agent-card-prompt**
was written by
joshua stein &lt;[jcs@jcs.org](mailto:jcs@jcs.org)&gt;.

OpenBSD 6.6 - October 15, 2019
