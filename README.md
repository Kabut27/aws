# CloudFront Telegram Manager

Telegram bot (inline buttons) ya kusimamia AWS CloudFront distributions kwenye accounts nyingi:
create, hariri origin/port/protocol, custom domain + ACM cert, purge, usage dhidi ya 1TB free tier, backup, delete.

## Install (VPS yoyote ya Linux)
```bash
git clone <repo-url> cfbot && cd cfbot
sudo bash install.sh            # inakuuliza bot token tu
```
- Docker haipo? Inainstall yenyewe. Ipo? Inaendelea.
- Kisha fungua bot, tuma `/start <code>` inayoonyeshwa mwishoni. Wewe ndiye mmiliki.
- Bila Docker: `sudo bash install.sh --no-docker` (systemd + venv; repo iwe `/opt/cfbot`).
- Non-interactive: `sudo bash install.sh --token 123:ABC...`

## Update / Uninstall
```bash
git pull && sudo bash install.sh     # update (config na data vinabaki)
sudo bash install.sh --uninstall     # ondoa service (data inabaki)
```

## AWS
Tengeneza IAM user kwa kila account kwa kutumia `iam-policy.json`, kisha kwenye bot: Accounts → Add account.

## Usalama
- Keys za AWS zinahifadhiwa zimesimbwa (Fernet) kwenye `data/data.json`; ufunguo ni `SECRET_KEY` kwenye `.env`. **Ibackup `.env` na `data/`.**
- Bot inajibu wamiliki tu (`data/owners.json` + `ADMIN_IDS` hiari).
- Backups za config za CloudFront zipo `data/backups/` (kila mabadiliko).

## Muundo
```
src/bot.py          bot yote (handlers, AWS helpers, UI)
install.sh          installer (docker / systemd)
Dockerfile, docker-compose.yml
iam-policy.json     ruhusa za chini za IAM
```

## Mawazo ya kuongeza
Behaviors/paths nyingi, multi-origin, kubadilisha cache policy, alarm ya usage (notify ukifika 80%),
kuongeza admin kupitia bot, kugawanya `bot.py` kuwa modules.
