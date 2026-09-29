#!/bin/bash
# Captures the identity provider screenshots used by the provider guides in
# docs/how-to/providers/ and the Pocket ID tutorial.
#
# Usage: run.sh [keycloak|authelia|pocket-id|authentik ...]
#        make idp-screenshots [IDP=<name>]
#
# With no argument, every IdP is captured, one after the other: each script
# starts its IdP in its own containers and network, captures, and removes
# everything before the next one starts. The PNGs go to
# docs/assets/screenshots/idp/ (OUT_DIR overrides it), compressed losslessly.
#
# Needs docker and the devenv browser image (make build-images). The IdP
# images are pinned in each <idp>.sh; nothing is published on the host, and
# every password, key and client secret is generated for the run.

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ALL=(keycloak authelia pocket-id authentik)

if [ "$#" -eq 0 ]; then
	set -- "${ALL[@]}"
fi

for idp in "$@"; do
	if [ ! -f "$HERE/$idp.sh" ]; then
		echo "unknown IdP '$idp'; expected one of: ${ALL[*]}" >&2
		exit 2
	fi
done

for idp in "$@"; do
	bash "$HERE/$idp.sh"
done
