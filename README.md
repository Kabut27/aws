<div align="center">

# ⚡ AWS Control Bot (CloudFront & EC2)

**Dhibiti AWS CloudFront, EC2 Servers, na Free Tier Guard moja kwa moja kutoka Telegram.**

[![Python](https://img.shields.io/badge/Python-3.12+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Telegram](https://img.shields.io/badge/Telegram-Bot_API-26A5E4?style=for-the-badge&logo=telegram&logoColor=white)](https://core.telegram.org/bots)
[![AWS](https://img.shields.io/badge/AWS-CloudFront_%26_EC2-FF9900?style=for-the-badge&logo=amazonwebservices&logoColor=white)](https://aws.amazon.com)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?style=for-the-badge&logo=docker&logoColor=white)](https://docker.com)
[![Security](https://img.shields.io/badge/Encryption-Fernet_AES-10B981?style=for-the-badge&logo=letsencrypt&logoColor=white)](#usalama)

</div>

---

## ✨ Vipengele Vikuu

| Huduma | Uwezo wa Bot |
| :--- | :--- |
| ☁️ **CloudFront** | Unda & futa distributions, hariri **Origin / HTTP & HTTPS Ports**, **HTTP/3**, Cache Policy, Geo-Restriction, AWS WAF, Custom Headers, **ACM SSL**, Custom Purge, na **Backup / Restore**. |
| 📊 **Analytics** | Fuatilia **Data (GB / 1 TB)**, **Requests (Mwezi & 24h / 10M)**, na **4xx / 5xx Error Rates** kwa progress bars za rangi (`🟩` `🟨` `🟥`). |
| 🖥 **EC2 Control** | **Scan Regions zote**, Start / Stop / Reboot / Terminate, Launch Templates, **Firewall / SG** *(pamoja na CloudFront Only)*, Elastic IP, EBS Snapshots, na **Run Command (SSM)**. |
| 🔗 **1-Click Link** | Unganisha Public DNS ya EC2 yako moja kwa moja kama Origin ya CloudFront kwa kubonyeza mara moja. |
| 🛡 **Free Tier Guard** | Amri ya `/freetier` hukagua CF GB + Requests, masaa ya EC2 (750h), Net Out, EBS, na EIP zisizotumika — na huzima CloudFront kiotomatiki ikikaribia kikomo. |

---

## 🚀 Usakinishaji (VPS ya Linux)

### 1️⃣ Njia ya Docker *(Inapendekezwa)*
Inainstall Docker yenyewe ikiwa haipo, inatengeneza `SECRET_KEY`, na kuwasha bot:

```bash
git clone https://github.com/Kabut27/aws.git /opt/cfbot && cd /opt/cfbot
sudo bash install.sh
```

> [!TIP]
> **Bila Docker (systemd + venv):** Endesha `sudo bash install.sh --no-docker`  
> **Bila maswali (Non-interactive):** `sudo bash install.sh --token <BOT_TOKEN>`

Baada ya kukamilika, fungua bot yako Telegram kisha tuma **`/start <code>`** itakayoonyeshwa mwishoni ili kujisajili kama mmiliki wa bot.

### 🔄 Update / Ondoa / Logs

```bash
cd /opt/cfbot && git pull && sudo bash install.sh   # Update (data inabaki salama)
docker logs cfbot -f                                # Tazama logs (Docker)
sudo bash install.sh --uninstall                    # Ondoa service (data inabaki)
```

---

## 🔑 Kuunganisha Akaunti ya AWS

1. Ingia **AWS IAM → Policies → Create policy**, chagua **JSON**, kisha paste maudhui ya [`iam-policy.json`](./iam-policy.json).
2. Nenda **Users → Create user**, mpe hiyo policy pekee (**Attach policies directly**).
3. Fungua user → **Security credentials → Create access key** (*Application running outside AWS*).
4. Kwenye bot Telegram: **`/start` → 👤 Accounts → ➕ Add Account** kisha weka **Access Key** na **Secret Key**.

> [!IMPORTANT]
> Unaweza kuunganisha akaunti nyingi za AWS kwa pamoja. Epuka kutumia Root Account keys.

---

## 🤖 Amri za Bot & Free Tier Config

| Amri | Kazi |
| :--- | :--- |
| `/start` au `/menu` | Fungua AWS Control Panel |
| `/freetier` | Ripoti kamili ya Free Tier (CloudFront + EC2 regions zote) |
| `/cancel` | Ghairi hatua unayoendelea nayo |

<details>
<summary>⚙️ <b>Hiari: Mipangilio ya Free Tier Guard kwenye <code>.env</code></b></summary>

```env
FT_CF_GB=1024                  # Kikomo cha CloudFront Data (GB)
FT_CF_REQ=10000000             # Kikomo cha CloudFront Requests (10M)
FT_EC2_HOURS=750               # Kikomo cha masaa ya EC2 kwa mwezi
FT_GUARD_PCT=95                # Asilimia ya kuzima CloudFront kiotomatiki
FT_AUTO_DISABLE_CF=1           # 1 = Zima CF ikifika limit, 0 = Arifa tu
FT_AUTO_STOP_EC2=0             # 1 = Zima EC2 zilizozidi limit, 0 = Arifa tu
FT_EC2_TYPES=t2.micro,t3.micro # Aina za EC2 zinazoruhusiwa
```

</details>

---

## 🔒 Usalama & Muundo

> [!CAUTION]
> Hifadhi nakala (backup) ya `.env` (`SECRET_KEY`) na folda ya `data/`. Ukipoteza `SECRET_KEY`, bot haitaweza kufungua AWS keys zilizohifadhiwa.

* **Encryption:** Keys zote husimbwa kwa **Fernet AES** ndani ya `data/bot_data.db` (`chmod 600`) na jumbe za keys Telegram hufutwa papo hapo.
* **Access Control:** Bot hujibu wamiliki walioidhinishwa pekee (`data/owners.json` / `ADMIN_IDS`).

```text
aws/
├── src/
│   ├── run.py          # Entry point (inaunganisha bot + freetier)
│   ├── bot.py          # CloudFront & EC2 Control Panel + UI + Watchers
│   └── freetier.py     # Free-tier guard, claim code & /freetier
├── install.sh          # Installer ya Docker / systemd
├── Dockerfile          # Docker image config
├── docker-compose.yml  # Container orchestration
└── iam-policy.json     # Ruhusa salama za IAM (Least Privilege)
```