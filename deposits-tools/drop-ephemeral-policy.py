#!/usr/bin/env python3
"""
Strfry write policy for the slow (durable) relay.
Drops ephemeral events (kinds 20000-29999) — those are real-time only
and handled by the fast relay. Accepts everything else for persistence.
"""

import sys
import json

def respond(event_id, action, msg=""):
    r = json.dumps({"id": event_id, "action": action, "msg": msg}, separators=(",", ":"))
    print(r, end="\n", file=sys.stdout, flush=True)

def main():
    for line in sys.stdin:
        request = json.loads(line)

        if request.get("type") == "lookback":
            continue
        if request.get("type") != "new":
            continue

        event = request.get("event", {})
        event_id = event.get("id")
        if not event_id:
            continue

        kind = event.get("kind", 0)

        # NIP-01 ephemeral range: 20000-29999
        if 20000 <= kind <= 29999:
            respond(event_id, "reject", "ephemeral event dropped by slow relay")
            continue

        respond(event_id, "accept")

if __name__ == "__main__":
    main()
