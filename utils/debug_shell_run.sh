#!/bin/sh

TERM_SANITIZED=""
STTY_CMD_S=""

case "$TERM" in
	[A-Za-z0-9.-,]*)
		TERM_SANITIZED="$TERM"
		;;
esac

STTY_CMD="$(stty -a | sed -n 's/^.*rows \([0-9]\+\).*columns \([0-9]\+\).*$/\1 \2/p' | head -n 1)"

case "$STTY_CMD" in
	[0-9\ ]*)
		STTY_CMD_S="$STTY_CMD"
		;;
esac

INIT_CMD="$(printf 'stty rows %d columns %d; export TERM="%s"\n' "${STTY_CMD_S%% *}" "${STTY_CMD_S##* }" "$TERM_SANITIZED")"

python3 /dev/fd/3 "$INIT_CMD" "$1" 3<<\EOF
import sys, socket, os, subprocess
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect((sys.argv[2]))
os.write(s.fileno(), bytes(sys.argv[1], encoding="utf-8") + b'\n')
s.set_inheritable(True)
# b_1 = subprocess.Popen(["cat"], stdout=s)
# b_2 = subprocess.Popen(["cat"], stdin=s)
# b_1.wait()
# b_2.wait()
os.execvp("socat", ["socat", "-t0", "STDIO,isig=0,icanon=0,echo=0", "FD:" + str(s.fileno())])
EOF
