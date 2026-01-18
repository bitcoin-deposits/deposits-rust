# 🚀 Quick Start - Bitcoin Deposits Environment

## True Turnkey Setup

### First Time Setup
```bash
# Build images with Lightning endpoints (one-time)
docker-compose -f docker-compose-deposits.yml build

# Start everything
docker-compose -f docker-compose-deposits.yml up -d
```

### Everyday Use
```bash
# Just start the environment
docker-compose -f docker-compose-deposits.yml up -d

# See network status after startup
docker-compose -f docker-compose-deposits.yml --profile status up network-status

# Or use the helper script
./start.sh
```

### That's It! 

After ~15 seconds, you'll have:
- ✅ 6 Lightning nodes with real Lightning endpoints
- ✅ Bitcoin Core regtest
- ✅ Electrs indexer  
- ✅ Nostr relay for NWC

## Test the Environment

### Quick API Test
```bash
# Check Alice
curl http://localhost:3011/info

# Create Lightning invoice
curl -X POST http://localhost:3011/invoice \
  -H "Content-Type: application/json" \
  -d '{"amount_msat": 100000, "description": "test"}'
```

### Use the Tools
```bash
# NWC Client
cargo run --bin nwc-client alice

# Status Tool  
cargo run --bin status node alice
```

## Node Ports

| Node | API Port | Lightning Port |
|------|----------|----------------|
| Alice | 3011 | 9735 |
| Bob | 3012 | 9736 |
| Charlie | 3013 | 9737 |
| Diana | 3014 | 9738 |
| Eve | 3015 | 9739 |
| Frank | 3016 | 9740 |

## Management Commands

```bash
# Stop everything
docker-compose -f docker-compose-deposits.yml down

# Restart (keep data)
docker-compose -f docker-compose-deposits.yml restart

# Check network status
docker-compose -f docker-compose-deposits.yml --profile status up network-status

# Full reset (lose data)
docker-compose -f docker-compose-deposits.yml down --volumes

# Rebuild images (after code changes)
docker-compose -f docker-compose-deposits.yml build
```

## Troubleshooting

**Services not responding?**
- Wait 30 seconds for startup
- Check logs: `docker-compose -f docker-compose-deposits.yml logs alice`

**Need fresh environment?**  
```bash
docker-compose -f docker-compose-deposits.yml down --volumes
docker-compose -f docker-compose-deposits.yml up -d
```

**That's the whole setup!** 🎉