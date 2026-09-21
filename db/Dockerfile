FROM postgres:18.4@sha256:3a82e1f56c8f0f5616a11103ac3d47e632c3938698946a7ad26da0df1334744a

# Replace gosu (Go stdlib vulnerabilities) with runuser wrapper
# gosu is only used once in docker-entrypoint.sh: exec gosu postgres "$BASH_SOURCE" "$@"
#
# Known limitation — reviewed 2026-07-24:
# Docker Scout reports 2 Critical + 18 High vulnerabilities from the base image.
#
# Go stdlib (1C + 16H):
# Findings originate from the original gosu binary in a lower image layer.
# /usr/local/bin/gosu is replaced in the final runtime filesystem with a
# runuser wrapper, so the vulnerable binary is not executable in the running
# container. Scanner findings remain because historical image layers are scanned.
#
# Perl (1C + 2H):
# Perl is required by Debian's pg_wrapper (/usr/bin/psql -> pg_wrapper).
# A simulated purge also removes postgresql-18 and related client packages,
# so it cannot be safely removed from this image.
#
# Compensating controls:
# - Database has no published host port and uses an internal Docker network
# - cap_drop: ALL with only required capabilities restored
# - no-new-privileges enabled
# - PostgreSQL request processing runs as the postgres user
#
# init:true is retained for process reaping/signal handling; it is an
# operational control, not a CVE mitigation.
#
# Remediation: monitor the official PostgreSQL image, update the pinned digest
# when a patched base is available, then rebuild and rerun Docker Scout.
# Next review date: 2026-08-24 (or when upstream releases a patch).
RUN rm -f /usr/local/bin/gosu && \
    printf '#!/bin/sh\n# gosu replacement using runuser (no Go stdlib CVEs)\nif [ "$1" = "--" ]; then shift; fi\nUSER="$1"; shift\nexec runuser -u "$USER" -- "$@"\n' > /usr/local/bin/gosu && \
    chmod +x /usr/local/bin/gosu
