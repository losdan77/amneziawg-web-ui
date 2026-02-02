# Bandwidth Management Setup Guide

## Overview

The bandwidth management system allows you to control network speed for different user tiers. This is useful for creating a tiered VPN service with Free, VIP, and Super VIP plans.

## Quick Start

### 1. Access Bandwidth Settings

1. Open the web UI (default: `http://your-server:5000`)
2. Click on the **"Bandwidth Settings"** tab
3. You'll see three tiers with default settings:
   - **Free**: 6 Mbit/s (burst to 10 Mbit/s)
   - **VIP**: 50 Mbit/s (burst to 100 Mbit/s)
   - **Super VIP**: Unlimited (0 = no limit)

### 2. Customize Tier Settings

Each tier has three parameters:
- **Name**: Display name for the tier
- **Limit (Mbit/s)**: Sustained bandwidth limit (0 = unlimited)
- **Burst (Mbit/s)**: Short-term maximum speed for better user experience

Click **"Update [Tier]"** to save changes. Limits are applied immediately to all running servers.

### 3. Create Server with Specific Tier

When creating a new server:
1. Fill in server details (name, port, subnet, etc.)
2. Select **"Bandwidth Tier"** from dropdown:
   - Free (6 Mbit/s)
   - VIP (50 Mbit/s)
   - Super VIP (Unlimited)
3. Click **"Create Server"**

All clients created on this server will automatically have this bandwidth limit.

### 4. Add Clients

When adding clients:
1. Click **"Add Client"** button on a server
2. Enter the client name
3. Click **"Add Client"**

The client automatically inherits the server's bandwidth tier. The bandwidth limit is applied immediately if the server is running.

### 5. Change Server Tier

To upgrade/downgrade all clients on a server:

**Via Web UI:**
1. Click **"Change Tier"** button on the server
2. Select new tier from dropdown
3. Click **"Change Tier"**

All clients will be updated immediately if the server is running.

**Via API:**
```bash
curl -X PUT http://your-server:5000/api/servers/{server_id}/tier \
  -H "Content-Type: application/json" \
  -d '{"tier": "vip"}'
```

## Recommended Settings

### For General Public VPN Service

- **Free Tier (6 Mbit/s)**
  - YouTube 480p-720p
  - Web browsing
  - Light gaming (Clash Royale, casual games)
  - Social media
  - **Not suitable for:** 1080p streaming, large downloads

- **VIP Tier (50 Mbit/s)**
  - YouTube 1080p-1440p  
  - HD streaming (Netflix, Twitch)
  - All gaming types
  - Fast downloads
  - **Good for:** Premium users who need reliable speed

- **Super VIP Tier (Unlimited)**
  - No restrictions
  - Full server bandwidth
  - 4K streaming
  - **Good for:** Enterprise clients or high-value customers

### For Private Use

If you're running this for friends/family, you might want:
- **Free Tier**: 10-20 Mbit/s (more generous)
- **VIP Tier**: 100 Mbit/s
- **Super VIP**: Unlimited

## Technical Details

### How It Works

The system uses Linux `tc` (traffic control) with HTB (Hierarchical Token Bucket):

1. When a server starts, HTB qdisc is created on the WireGuard interface
2. Each client gets a class with their tier's bandwidth limit
3. Traffic filters direct client traffic to their respective class
4. Burst allows short-term speed increases for better UX

### Bandwidth Calculation

**What can users do at different speeds?**

| Speed | Activities |
|-------|-----------|
| 1-2 Mbit/s | YouTube 360p, light browsing, messaging |
| 3-5 Mbit/s | YouTube 480p, social media, casual gaming |
| 6-10 Mbit/s | YouTube 720p, web apps, most games |
| 25-50 Mbit/s | YouTube 1080p, HD streaming, downloads |
| 50+ Mbit/s | YouTube 1440p/4K, professional use |

### Burst Explained

Burst allows clients to temporarily exceed their limit for better responsiveness:
- Page loads feel faster
- Video buffering is smoother
- Downloads start quickly

Example: Free tier (6 Mbit/s sustained, 10 Mbit/s burst)
- Client can burst to 10 Mbit/s for a few seconds
- Then settles at 6 Mbit/s sustained rate

## API Usage

### Get All Tiers

```bash
curl http://your-server:5000/api/bandwidth/tiers
```

Response:
```json
{
  "free": {
    "name": "Free",
    "limit_mbit": 6,
    "burst_mbit": 10
  },
  "vip": {
    "name": "VIP",
    "limit_mbit": 50,
    "burst_mbit": 100
  },
  "super_vip": {
    "name": "Super VIP",
    "limit_mbit": 0,
    "burst_mbit": 0
  }
}
```

### Update Tier Settings

```bash
curl -X PUT http://your-server:5000/api/bandwidth/tiers/free \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Free Plan",
    "limit_mbit": 10,
    "burst_mbit": 15
  }'
```

### Create Server with Specific Tier

```bash
curl -X POST http://your-server:5000/api/servers \
  -H "Content-Type: application/json" \
  -d '{
    "name": "VIP Server",
    "port": 51820,
    "subnet": "10.0.0.0/24",
    "bandwidth_tier": "vip"
  }'
```

### Create Client (inherits server tier)

```bash
curl -X POST http://your-server:5000/api/servers/{server_id}/clients \
  -H "Content-Type: application/json" \
  -d '{
    "name": "John Doe"
  }'
```

The client automatically gets the server's bandwidth tier.

## Troubleshooting

### Bandwidth Limits Not Applied

1. Check if server is running: `docker exec -it amneziawg-api awg show`
2. Verify tc rules: `docker exec -it amneziawg-api tc qdisc show dev wg-XXXXX`
3. Check for errors: `docker logs amneziawg-api`

### Client Not Reaching Expected Speed

1. Test server bandwidth: `iperf3 -s` on server, `iperf3 -c server-ip` on client
2. Check if tier is correct in web UI
3. Verify tc class: `docker exec -it amneziawg-api tc class show dev wg-XXXXX`

### Changes Not Taking Effect

Restart the server to reapply all limits:
1. Stop server in web UI
2. Start server in web UI
3. All bandwidth limits will be reapplied

## Best Practices

1. **Start Conservative**: Begin with lower limits and increase based on feedback
2. **Monitor Usage**: Watch for users constantly hitting limits
3. **Adjust Based on Hardware**: Server bandwidth capacity matters
4. **Test Before Deploying**: Test all tiers with actual usage patterns
5. **Communicate Clearly**: Let users know what each tier includes

## Example Monetization

If you're running a commercial VPN service:

- **Free**: $0/month - 6 Mbit/s - Good for basic browsing
- **VIP**: $5/month - 50 Mbit/s - Perfect for streaming
- **Super VIP**: $10/month - Unlimited - No compromises

## Support

For issues or questions:
1. Check server logs: `docker logs amneziawg-api`
2. Verify configuration in web UI
3. Test with `tc` commands manually
4. Check original project issues on GitHub

