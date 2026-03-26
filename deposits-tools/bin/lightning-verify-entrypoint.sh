#!/bin/sh
set -e
export LDK_API_KEY=$(cat /ldk-data/regtest/api_key | od -A n -t x1 | tr -d ' \n')
export LDK_REAL_CLI=/ldk-cli/ldk-server-cli
mkdir -p /self-pay
exec lightning-verify
