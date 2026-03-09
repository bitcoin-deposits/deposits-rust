../../target/release/transfer-simulator \
      --relay ws://localhost:7801 \
      --node sim:~/.deposits-wallet \
      --bootstrap --auto-topoff \
      --deposit-count 72 \
      --target-tps 500 --workers 50
