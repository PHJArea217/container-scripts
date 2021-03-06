#!/bin/sh

set -eu

: ${ARCH=$(arch)}
[ -d current ] && exit 0
case "$ARCH" in
	i686)
		ln -sf x86-32 current
		;;
	x86_64)
		ln -sf x86-64 current
		;;
	*)
		printf 'Unknown architecture %s\n'
		exit 1
		;;
esac
