# garmin-mcp

## Garmin session persistence

Successful Garmin browser sessions are stored in a small SQLite database.

- Default path: `/tmp/garmin_state.db`
- Override with `GARMIN_STATE_DB_PATH`

If you want sessions to survive Render restarts or deploys, point `GARMIN_STATE_DB_PATH` at a persistent disk mount instead of `/tmp`.

## VPS deploy

Recommended target: Ubuntu 22.04 or 24.04 with `nginx`, `systemd`, Python 3.11, and a persistent disk path for Garmin state.

### 1. Install packages

```bash
sudo apt update
sudo apt install -y git python3.11 python3.11-venv python3-pip nginx certbot python3-certbot-nginx
```

### 2. Create app user and directories

```bash
sudo useradd --system --create-home --shell /usr/sbin/nologin garmin
sudo mkdir -p /opt/garmin-mcp /var/lib/garmin-mcp
sudo chown -R garmin:www-data /opt/garmin-mcp /var/lib/garmin-mcp
sudo chmod 775 /var/lib/garmin-mcp
```

### 3. Copy app and install dependencies

```bash
sudo -u garmin git clone https://github.com/roman-raducu/garmin-mcp.git /opt/garmin-mcp
cd /opt/garmin-mcp
sudo -u garmin python3.11 -m venv .venv
sudo -u garmin .venv/bin/pip install --upgrade pip
sudo -u garmin .venv/bin/pip install -r requirements.txt
```

### 4. Create environment file

```bash
sudo cp /opt/garmin-mcp/.env.example /etc/garmin-mcp.env
sudo nano /etc/garmin-mcp.env
```

Minimum useful values:

```env
PYTHONUNBUFFERED=1
GARMIN_STATE_DB_PATH=/var/lib/garmin-mcp/garmin_state.db
```

If you later bootstrap Garmin tokens once, add them here too:

```env
GARMIN_EMAIL=you@example.com
GARMIN_OAUTH1_TOKEN={...json...}
GARMIN_OAUTH2_TOKEN={...json...}
```

### 5. Install systemd service

```bash
sudo cp /opt/garmin-mcp/deployment/systemd/garmin-mcp.service /etc/systemd/system/garmin-mcp.service
sudo systemctl daemon-reload
sudo systemctl enable --now garmin-mcp
sudo systemctl status garmin-mcp
```

### 6. Install nginx site

```bash
sudo cp /opt/garmin-mcp/deployment/nginx/garmin.raducu.co.conf /etc/nginx/sites-available/garmin.raducu.co.conf
sudo ln -s /etc/nginx/sites-available/garmin.raducu.co.conf /etc/nginx/sites-enabled/garmin.raducu.co.conf
sudo rm -f /etc/nginx/sites-enabled/default
sudo nginx -t
sudo systemctl reload nginx
```

### 7. Point DNS to the VPS

Create or update:

- `A garmin.raducu.co -> <your_vps_ipv4>`
- optional `AAAA garmin.raducu.co -> <your_vps_ipv6>`

Remove the old Render `CNAME` first if it still exists.

### 8. Issue TLS certificate

```bash
sudo certbot --nginx -d garmin.raducu.co
```

### 9. Verify

```bash
curl -I http://127.0.0.1:8000/healthz
curl -I https://garmin.raducu.co/healthz
sudo journalctl -u garmin-mcp -n 100 --no-pager
```

## Notes

- `GARMIN_STATE_DB_PATH` should stay on persistent disk, for example `/var/lib/garmin-mcp/garmin_state.db`.
- This repo is now ready for `nginx -> uvicorn -> FastAPI` on a VPS.
- The remaining Garmin risk is not app hosting anymore, but Garmin auth policy. Once one login succeeds, persist and reuse tokens instead of re-authing frequently.
