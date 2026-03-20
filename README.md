# garmin-mcp

## Garmin session persistence

Successful Garmin browser sessions are stored in a small SQLite database.

- Default path: `/tmp/garmin_state.db`
- Override with `GARMIN_STATE_DB_PATH`

If you want sessions to survive restarts or deploys, point `GARMIN_STATE_DB_PATH` at a persistent disk mount instead of `/tmp`.

## VPS deploy

Recommended target: Debian 13 or Ubuntu 24.04 with `nginx`, `systemd`, Python 3, and a persistent disk path for Garmin state.

### 1. Install packages

```bash
sudo apt update
sudo apt install -y git python3 python3-venv python3-pip nginx certbot python3-certbot-nginx
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
sudo -u garmin python3 -m venv .venv
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
OLLAMA_ENABLED=true
OLLAMA_BASE_URL=http://127.0.0.1:11434
OLLAMA_MODEL=gemma3:1b
OLLAMA_TIMEOUT_SECONDS=120
```

Optional hosted LLM values if you want better language quality than a small local Ollama model:

```env
CHARLIE_LLM_ENABLED=true
CHARLIE_LLM_PROVIDER=groq
CHARLIE_LLM_MODEL=openai/gpt-oss-20b
CHARLIE_LLM_API_KEY=...
CHARLIE_LLM_TIMEOUT_SECONDS=20
```

To route across multiple providers sequentially, add for example:

```env
CHARLIE_LLM_PROVIDER_ORDER=groq,openrouter,huggingface,ollama
CHARLIE_LLM_MODEL_GROQ=openai/gpt-oss-20b
CHARLIE_LLM_MODEL_OPENROUTER=openrouter/auto
CHARLIE_LLM_MODEL_HUGGINGFACE=Qwen/Qwen3-32B
```

The app will try configured providers in order and fall back if one is missing or unavailable.

Supported hosted provider presets:

- `groq` -> `https://api.groq.com/openai/v1`
- `openrouter` -> `https://openrouter.ai/api/v1`
- `huggingface` -> `https://router.huggingface.co/v1`

You can also override the endpoint directly with:

```env
CHARLIE_LLM_BASE_URL=https://your-provider.example/v1
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

## SSH troubleshooting

If SSH to the VPS times out from the outside, check these first:

- the VPS is powered on
- the provider firewall or security group allows inbound `TCP 22`
- `sshd` is running: `systemctl status ssh` or `systemctl status sshd`
- root login is allowed if you plan to use `root`
- the IP address is correct
- the SSH port is really `22`

## Notes

- `GARMIN_STATE_DB_PATH` should stay on persistent disk, for example `/var/lib/garmin-mcp/garmin_state.db`.
- This repo is now ready for `nginx -> uvicorn -> FastAPI` on a VPS.
- The remaining Garmin risk is not app hosting anymore, but Garmin auth policy. Once one login succeeds, persist and reuse tokens instead of re-authing frequently.
- For a small VPS like `2 vCPU / 4 GB RAM`, start with a small Ollama model such as `gemma3:1b`.
