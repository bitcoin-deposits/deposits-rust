#!/bin/bash

cd "$(dirname "$0")"

claude --dangerously-skip-permissions --mcp-config mcp-config.json --strict-mcp-config --mcp-debug --print "request a lightning wallet and make an invoice for 10 sats. write it to invoice-a.txt, and wait for it to be paid. once it's paid, read invoice-b.txt and pay that one"