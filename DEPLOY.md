# Deployment Guide - Bandwidth Management Update

## Building and Deploying the Updated Image

### Step 1: Build Docker Image

```bash
cd c:\Users\user1\Desktop\amneziawg-web-ui

# Build the image
docker build -t losdan/amneziawg-web-ui:latest .

# Tag for versioning (optional)
docker tag losdan/amneziawg-web-ui:latest losdan/amneziawg-web-ui:v2.0.0
```

### Step 2: Push to Docker Hub

```bash
# Login to Docker Hub
docker login

# Push latest tag
docker push losdan/amneziawg-web-ui:latest

# Push version tag (optional)
docker push losdan/amneziawg-web-ui:v2.0.0
```

### Step 3: Deploy on VPS

**Option A: Using Docker Run (Recommended)**

```bash
# Stop and remove old container
docker stop amneziawg-api
docker rm amneziawg-api

# Pull latest image
docker pull losdan/amneziawg-web-ui:latest

# Run with all required parameters
docker run -d \
  --name amneziawg-api \
  --restart unless-stopped \
  --privileged \
  --cap-add=NET_ADMIN \
  --cap-add=SYS_MODULE \
  --device /dev/net/tun:/dev/net/tun \
  --sysctl net.ipv4.ip_forward=1 \
  -v /lib/modules:/lib/modules \
  -v /etc/amneziawg:/etc/amneziawg \
  -p 5000:5000 \
  -p 51820-51830:51820-51830/udp \
  losdan/amneziawg-web-ui:latest
```

**Option B: Using Docker Compose**

```bash
# Upload docker-compose.yml to your VPS
scp docker-compose.yml user@your-vps:/root/amneziawg/

# On VPS
cd /root/amneziawg/
docker-compose pull
docker-compose up -d
```

### Step 4: Verify Deployment

```bash
# Check container is running
docker ps | grep amneziawg-api

# Check logs
docker logs amneziawg-api --tail 50

# Test web UI
curl http://your-vps-ip:5000/api/system/status

# Test bandwidth API
curl http://your-vps-ip:5000/api/bandwidth/tiers
```

### Step 5: Test Bandwidth Management

1. **Access Web UI**: http://your-vps-ip:5000
2. **Go to Bandwidth Settings tab**
3. **Verify default tiers are loaded**:
   - Free: 6 Mbit/s
   - VIP: 50 Mbit/s
   - Super VIP: Unlimited
4. **Create a test client** with Free tier
5. **Start the server**
6. **Verify bandwidth limit is applied**:

```bash
docker exec -it amneziawg-api sh

# Check tc rules
tc qdisc show dev wg-XXXXXX
tc class show dev wg-XXXXXX
tc filter show dev wg-XXXXXX

# Should show HTB qdisc and classes
```

## Important Configuration Notes

### Required Parameters

These are **CRITICAL** for VPN functionality:

1. `--device /dev/net/tun:/dev/net/tun` - Required for VPN tunnel creation
2. `--privileged` or `--cap-add=NET_ADMIN` - Required for network configuration
3. `--sysctl net.ipv4.ip_forward=1` - Required for routing
4. UDP ports - For WireGuard traffic

### Port Configuration

- **5000**: Web UI (can be changed via NGINX_PORT env var)
- **51820-51830/udp**: WireGuard servers (adjust range as needed)

### Volume Persistence

- `/etc/amneziawg` - Stores server/client configs and settings
  - Persists between container restarts
  - Contains `web_config.json` with bandwidth tier settings

## Migration from Old Version

If you're upgrading from a previous version:

1. **Backup your config**:
```bash
docker exec amneziawg-api cat /etc/amnezia/web_config.json > backup_config.json
```

2. **Stop old container** (config will be preserved in volume):
```bash
docker stop amneziawg-api
docker rm amneziawg-api
```

3. **Pull and run new image** (same volume mount):
```bash
docker pull losdan/amneziawg-web-ui:latest
docker run -d ... (use same command as above)
```

4. **Verify migration**:
   - Existing servers should still be there
   - Existing clients should still work
   - New "Bandwidth Settings" tab should appear
   - All clients will have default "free" tier initially

5. **Update client tiers as needed** via web UI or API

## Troubleshooting

### Container Won't Start

Check logs:
```bash
docker logs amneziawg-api
```

Common issues:
- Missing `/dev/net/tun` - Add `--device /dev/net/tun:/dev/net/tun`
- Permission denied - Add `--privileged` flag
- Port conflict - Change port mapping `-p 5001:5000`

### Bandwidth Limits Not Working

1. **Verify server is running**:
```bash
docker exec -it amneziawg-api awg show
```

2. **Check tc rules**:
```bash
docker exec -it amneziawg-api tc qdisc show
```

3. **Check setup_iptables.sh executed**:
```bash
docker exec -it amneziawg-api cat /var/log/supervisor/supervisord.log | grep iptables
```

4. **Manually apply rules** (temporary test):
```bash
docker exec -it amneziawg-api iptables -t nat -A POSTROUTING -s 10.0.0.0/24 -o eth0 -j MASQUERADE
```

### Web UI Not Accessible

1. **Check container is running**: `docker ps`
2. **Check firewall**: `ufw status` or `iptables -L`
3. **Test from VPS**: `curl localhost:5000`
4. **Check nginx logs**:
```bash
docker exec -it amneziawg-api tail -f /var/log/nginx/error.log
```

## Performance Considerations

### Server Capacity

Make sure your VPS has sufficient bandwidth:
- **Free tier (6 Mbit/s)**: ~40 concurrent users per 250 Mbit/s server
- **VIP tier (50 Mbit/s)**: ~5 concurrent users per 250 Mbit/s server
- **Super VIP (unlimited)**: Limited by server capacity

### CPU Impact

Traffic control (tc) has minimal CPU impact:
- <1% CPU for up to 100 clients
- Scales well on modern servers

## Security Notes

1. **Change default web UI port** in production:
```bash
docker run -d ... -e NGINX_PORT=8080 -p 8080:8080 ...
```

2. **Use reverse proxy** (nginx/caddy) with SSL for web UI

3. **Restrict access** to web UI:
```bash
# In nginx config
allow 1.2.3.4;  # Your IP
deny all;
```

4. **Regularly update** the image:
```bash
docker pull losdan/amneziawg-web-ui:latest
docker-compose restart
```

## Next Steps

1. ✅ Deploy updated image
2. ✅ Test bandwidth management
3. ✅ Configure tiers for your use case
4. ✅ Create clients with appropriate tiers
5. ✅ Monitor and adjust as needed

See [BANDWIDTH_SETUP.md](BANDWIDTH_SETUP.md) for detailed bandwidth configuration guide.

