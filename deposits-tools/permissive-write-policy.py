#!/usr/bin/env python3

import sys
import json

def eprint(*args, **kwargs):
  print(*args, **kwargs, file=sys.stderr, flush=True)

def accept(request):
  response = {
    'id' : request['event']['id']
  }

  response['action'] = 'accept'
  r = json.dumps(response,separators=(',', ':')) # output JSONL
  print(r, end='\n', file=sys.stdout, flush=True)

def main():
  for line in sys.stdin:
    request = json.loads(line)

    try:
      if request['type'] == 'lookback':
        continue
    except KeyError:
      eprint("input without type in write policy plugin")
      continue

    if request['type'] != 'new':
      eprint("unexpected request type in write policy plugin")
      continue

    try:
      if not request['event']['id']:
        eprint("input without event id in write policy plugin")
        continue
    except KeyError:
      eprint("input without event id in write policy plugin")
      continue

    # Accept all events - permissive policy for testing
    accept(request)

if __name__=='__main__':
  main()