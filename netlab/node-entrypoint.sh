#!/bin/sh
# Turn TCP offload off on every network interface of this container, then run the command.
# Without offload the kernel sends normal packets of at most MTU size (1500 bytes) instead of
# one huge "super packet", so a capture on the bridge looks like a capture on a real cable.
# Needs the NET_ADMIN capability; without it the command still runs (offload stays on).
for dev in $(ls /sys/class/net); do
    [ "$dev" = lo ] && continue
    ethtool -K "$dev" tso off gso off gro off >/dev/null 2>&1 \
        || echo "offload: could not change $dev (NET_ADMIN missing?)" >&2
done
exec "$@"
