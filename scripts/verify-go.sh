#!/bin/sh
set -eu

if [ "$#" -eq 0 ]; then
	set -- cmd internal
fi

formatted=$(gofmt -l "$@")
if [ -n "$formatted" ]; then
	printf '%s\n' "gofmt required for:" >&2
	printf '%s\n' "$formatted" >&2
	exit 1
fi
