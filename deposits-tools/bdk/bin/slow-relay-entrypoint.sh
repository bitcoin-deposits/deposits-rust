#!/bin/sh
# Entrypoint for the slow (durable) relay container.
# Runs strfry relay as the main process, plus strfry stream to pull
# events from the fast relay as a belt-and-suspenders backup.
# The write policy drops ephemeral events from both sources.

set -e

FAST_RELAY_URL="${FAST_RELAY_URL:-ws://nostr-relay:7777}"
CONFIG="/app/strfry-slow.conf"

# Start the relay
/app/strfry --config "$CONFIG" relay &
RELAY_PID=$!

# Wait for relay to be listening before starting stream
echo "Waiting for slow relay to start..."
sleep 3

# Stream all events from the fast relay into our DB.
# The write policy will drop ephemeral events.
# --dir=down: pull events FROM the fast relay into our local DB.
echo "Starting stream from $FAST_RELAY_URL..."
/app/strfry --config "$CONFIG" stream "$FAST_RELAY_URL" --dir=down &
STREAM_PID=$!

# If either process exits, clean up and exit
trap "kill $RELAY_PID $STREAM_PID 2>/dev/null; exit" INT TERM

# Wait for either to exit
wait -n $RELAY_PID $STREAM_PID 2>/dev/null || true
echo "A process exited, shutting down..."
kill $RELAY_PID $STREAM_PID 2>/dev/null
wait
