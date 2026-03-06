../../target/release/transfer-simulator \
      --relay ws://localhost:7778 \
      --node sim:~/.deposits-wallet \
      --bootstrap --auto-topoff \
      --target-tps 100 --workers 20
