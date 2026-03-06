#!/bin/sh
# Strfry write policy for the slow (durable) relay.
# Drops ephemeral events (kinds 20000-29999) — those are real-time only
# and handled by the fast relay. Accepts everything else for persistence.
#
# Uses pure awk — no python/jq dependencies needed in alpine.

exec awk '
{
    # Skip lookback events
    if (match($0, /"type":"lookback"/)) next

    # Only process "new" events
    if (!match($0, /"type":"new"/)) next

    # Extract event id
    id = ""
    if (match($0, /"id":"[^"]+"/)) {
        id = substr($0, RSTART+6, RLENGTH-7)
    }
    if (id == "") next

    # Extract kind (number after "kind":)
    kind = 0
    if (match($0, /"kind":[0-9]+/)) {
        kind = substr($0, RSTART+7, RLENGTH-7) + 0
    }

    # NIP-01 ephemeral range: 20000-29999
    if (kind >= 20000 && kind <= 29999) {
        printf "{\"id\":\"%s\",\"action\":\"reject\",\"msg\":\"ephemeral\"}\n", id
    } else {
        printf "{\"id\":\"%s\",\"action\":\"accept\"}\n", id
    }
    fflush()
}
'
