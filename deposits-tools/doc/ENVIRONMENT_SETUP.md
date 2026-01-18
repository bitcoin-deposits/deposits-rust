# 🚀 Turnkey Environment Setup

This directory contains scripts for reliably setting up and managing the Bitcoin Deposits Docker environment.

## Quick Start

### Full Environment Setup (Recommended)
```bash
./setup-environment.sh
```
This script provides a complete, reliable setup that:
- ✅ Cleans up any existing environment
- ✅ Builds fresh Docker images with latest code
- ✅ Starts all services in correct order
- ✅ Waits for health checks
- ✅ Tests Lightning endpoints
- ✅ Provides status summary

### Quick Reset (When Images Are Up-to-Date)
```bash
./reset-environment.sh
```
Use this when you just need to restart services without rebuilding images.

### Manual Cleanup
```bash
docker-compose -f docker-compose-deposits.yml down --volumes
```

## Environment Layout

After successful setup, you'll have:

### Infrastructure
- **Bitcoin Core**: `http://localhost:18443` (RPC: user/pass)
- **Electrs**: `http://localhost:3002`
- **Nostr Relay**: `ws://localhost:7777`

### Lightning Nodes
| Node | API Port | Lightning Port | URL |
|------|----------|----------------|-----|
| Alice | 3011 | 9735 | http://localhost:3011 |
| Bob | 3012 | 9736 | http://localhost:3012 |
| Charlie | 3013 | 9737 | http://localhost:3013 |
| Diana | 3014 | 9738 | http://localhost:3014 |
| Eve | 3015 | 9739 | http://localhost:3015 |
| Frank | 3016 | 9740 | http://localhost:3016 |

## Testing Lightning Functionality

### 1. Check Node Status
```bash
curl http://localhost:3011/info
```

### 2. Create Lightning Invoice
```bash
curl -X POST http://localhost:3011/invoice \
  -H "Content-Type: application/json" \
  -d '{"amount_msat": 100000, "description": "test invoice"}'
```

### 3. Use NWC Client
```bash
cargo run --bin nwc-client alice
```

### 4. Use Status Tool
```bash
cargo run --bin status node alice
```

## Troubleshooting

### Services Not Starting
1. Check Docker logs: `docker-compose -f docker-compose-deposits.yml logs [service-name]`
2. Ensure ports aren't in use: `lsof -i :3011`
3. Try full rebuild: `./setup-environment.sh`

### API Not Responding
1. Wait longer - nodes need time to sync with Bitcoin Core
2. Check node logs: `docker logs ldk-alice`
3. Verify Bitcoin Core is healthy: `curl http://localhost:18443` (should get auth error, not connection error)

### Build Issues
1. Clean Docker system: `docker system prune -af`
2. Remove all images: `docker-compose -f docker-compose-deposits.yml down --rmi all`
3. Re-run setup: `./setup-environment.sh`

## Environment Features

✅ **Real Lightning Endpoints**: Create invoices and payments  
✅ **Bitcoin Deposits Protocol**: Full protocol implementation  
✅ **NWC Client**: Nostr Wallet Connect testing  
✅ **6-Node Network**: Comprehensive Lightning network  
✅ **Status Monitoring**: Real-time node status  
✅ **Turnkey Setup**: One command deployment  

## Files

- `setup-environment.sh` - Complete environment setup
- `reset-environment.sh` - Quick restart without rebuild
- `docker-compose-deposits.yml` - Docker services configuration
- `Dockerfile.ldk-node` - LDK node container definition
- `ENVIRONMENT_SETUP.md` - This documentation

## Next Steps

After setup completes successfully:
1. Test Lightning invoice creation between nodes
2. Explore Bitcoin Deposits protocol features
3. Use NWC client for mobile wallet simulation
4. Monitor network with status tools