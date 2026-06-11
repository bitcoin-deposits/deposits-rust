# CLN hold plugin (BoltzExchange/hold)

Drop the release binary here for the CLN hold-invoice integration test:

```
curl -sL -o hold.tar.gz https://github.com/BoltzExchange/hold/releases/download/v0.3.3/hold-linux-amd64.tar.gz
tar xzf hold.tar.gz
```

Leaves the plugin at `build/hold-linux-amd64`, where `bin/setup-cln-hold.sh` expects it.
