# ssh-agent-card-prompt

![https://jcs.org/images/ssh-agent-card-prompt.png](https://jcs.org/images/ssh-agent-card-prompt.png)

**ssh-agent-card-prompt** -
prompt the user when SSH key signing requests to an
ssh-agent(1)
require tapping a physical security key (such as a YubiKey)

# SYNOPSIS

**ssh-agent-card-prompt**
\[**-d**]
\[**-p**&nbsp;*prompt*]

# DESCRIPTION

On startup,
**ssh-agent-card-prompt**
moves the current
ssh-agent(1)
socket (as set in the
`SSH_AUTH_SOCK`
environment variable) to a temporary location and creates a new socket at the
location pointed to by that variable.

When an SSH client connects,
**ssh-agent-card-prompt**
connects to the original
ssh-agent(1)
process and proxies requests and responses between the two.

After
**ssh-agent-card-prompt**
detects and forwards an SSH\_AGENTC\_SIGN\_REQUEST message that appears to be for
a PKCS key,
ssh-agent(1)
will block while waiting for the security key to be tapped and respond to the
request.
At that point,
**ssh-agent-card-prompt**
will present a modal X11 window with the
*prompt*
text and information about the process that is making the agent connection,
reminding the user to tap the key.

If the Escape key is pressed while presenting the dialog, the connections to
the client and ssh-agent are immediately dropped.
If the security key is tapped,
ssh-agent(1)
will send its response to
**ssh-agent-card-prompt**
which will then automatically close its X11 window.

When
**ssh-agent-card-prompt**
exits, the original ssh-agent socket is moved back to the path pointed to by
the
`SSH_AUTH_SOCK`
variable.

# OPTIONS

**-d**

> Print debugging messages to the terminal.
> If specified twice, the contents of each message passed will be printed to the
> terminal.

**-p** *prompt*

> The text presented to the user in the modal dialog.
> Defaults to "Tap the security key to continue with signing request".

# SEE ALSO

ssh-agent(1)

# AUTHORS

**ssh-agent-card-prompt**
was written by
joshua stein &lt;[jcs@jcs.org](mailto:jcs@jcs.org)&gt;.

OpenBSD 6.6 - October 15, 2019
