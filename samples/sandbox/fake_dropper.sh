#!/bin/bash
# HARMLESS demo sample for the malware sandbox. It imitates what a Linux
# dropper does, without doing damage. Do NOT run it outside the sandbox
# anyway: it appends a comment line to ~/.bashrc and deletes itself.
#
# - drops a hidden file in /tmp and marks it executable
# - "phones home" to 203.0.113.10 (TEST-NET-3, reserved, unroutable)
# - reads /etc/passwd for discovery
# - appends to the shell profile (persistence)
# - deletes itself
echo 'echo hello from the payload' > /tmp/.cache-update
chmod +x /tmp/.cache-update
/tmp/.cache-update
uname -a
cat /etc/passwd > /dev/null
(exec 3<>/dev/tcp/203.0.113.10/4444) 2>/dev/null
echo '# sandbox-demo persistence marker' >> ~/.bashrc
rm -f "$0"
