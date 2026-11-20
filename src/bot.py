#!/usr/bin/env python3
"""
===============================================================================
AWS Control Bot — CloudFront & EC2 Full Control Panel (Telegram)
===============================================================================
Matumizi / Setup:
1. Badili jina la faili hili kuwa:  bot.py
2. Weka maktaba (packages):
   pip install "python-telegram-bot[job-queue]>=21.0" boto3 cryptography
3. Tengeneza SECRET_KEY (Fernet):
   python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
4. Weka Environment Variables (mfano kwenye .env au systemd/Docker):
   export BOT_TOKEN="123456:ABC-DEF..."
   export ADMIN_IDS="123456789"          # Tenganisha kwa koma ikiwa admins ni wengi
   export SECRET_KEY="gAAAAAB..."        # Ufunguo uliotengeneza hatua ya 3
   export DB_FILE="bot_data.db"          # Hiari (default: bot_data.db)
   export BACKUP_DIR="backups"           # Hiari (default: backups)
5. Endesha bot:
   python3 bot.py

Kumbuka kuhusu AWS IAM Policy (Least Privilege):
Tumia IAM User mwenye ruhusa za:
- CloudFront: cloudfront:*
- ACM (us-east-1): acm:ListCertificates, acm:DescribeCertificate, acm:RequestCertificate
- CloudWatch: cloudwatch:GetMetricStatistics
- EC2: ec2:Describe*, ec2:StartInstances, ec2:StopInstances, ec2:RebootInstances,
       ec2:TerminateInstances, ec2:RunInstances, ec2:AuthorizeSecurityGroupIngress,
       ec2:RevokeSecurityGroupIngress, ec2:AllocateAddress, ec2:AssociateAddress,
       ec2:DisassociateAddress, ec2:ReleaseAddress, ec2:CreateSnapshot
- WAFv2 (hiari): wafv2:ListWebACLs
- SSM (hiari kwa Run Command): ssm:SendCommand, ssm:GetCommandInvocation
- STS: sts:GetCallerIdentity
===============================================================================
"""

import asyncio
import html
import io
import json
import logging
import os
import re
import secrets
import sqlite3
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

import boto3
from botocore.exceptions import BotoCoreError, ClientError
from cryptography.fernet import Fernet
from telegram import (
    BotCommand,
    InlineKeyboardButton,
    InlineKeyboardMarkup as M,
    LinkPreviewOptions,
    Update,
)


def B(text: str, data: str) -> InlineKeyboardButton:
    return InlineKeyboardButton(text=text, callback_data=data)


NO_PREVIEW = LinkPreviewOptions(is_disabled=True)
from telegram.error import BadRequest, TelegramError
from telegram.ext import (
    Application,
    CallbackQueryHandler,
    CommandHandler,
    ContextTypes,
    MessageHandler,
    filters,
)

# ============================= CONFIG & CONSTANTS =============================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)
log = logging.getLogger("aws_control_bot")

TOKEN = os.environ["BOT_TOKEN"]
ADMINS = {int(x.strip()) for x in os.environ["ADMIN_IDS"].split(",") if x.strip()}
FERNET = Fernet(os.environ["SECRET_KEY"].encode())
DB_FILE = os.environ.get("DB_FILE", "bot_data.db")
BACKUP_DIR = os.environ.get("BACKUP_DIR", "backups")
os.makedirs(BACKUP_DIR, exist_ok=True)
try:
    os.chmod(BACKUP_DIR, 0o700)
except OSError:
    pass

# AWS Managed Policy IDs
CACHING_DISABLED = "4135ea2d-6df8-44a3-9df3-4b5a84be39ad"
CACHING_OPTIMIZED = "658327ea-f89d-4fab-a63d-7e88639e58f6"
ALL_VIEWER = "216adef6-5c7f-47e4-b989-5492eafa07d3"

FREE_TIER_GB = 1024.0
FREE_TIER_INV = 1000
MAX_BACKUPS_PER_DIST = 10

PRICE_CLASSES = ["PriceClass_All", "PriceClass_200", "PriceClass_100"]
ORIGIN_PROTOS = ["http-only", "https-only", "match-viewer"]
VIEWER_PROTOS = ["redirect-to-https", "https-only", "allow-all"]
HTTP_VERSIONS = ["http2and3", "http2", "http1.1"]

POPULAR_REGIONS = [
    ("us-east-1", "US East (N. Virginia)"),
    ("us-east-2", "US East (Ohio)"),
    ("us-west-2", "US West (Oregon)"),
    ("eu-central-1", "EU (Frankfurt)"),
    ("eu-west-1", "EU (Ireland)"),
    ("eu-west-2", "EU (London)"),
    ("ap-southeast-1", "Asia (Singapore)"),
    ("ap-northeast-1", "Asia (Tokyo)"),
    ("af-south-1", "Africa (Cape Town)"),
    ("me-south-1", "Middle East (Bahrain)"),
]

SSM_PRESETS = {
    "disk": ("💾 Disk (df -h)", "df -h"),
    "ram": ("🧠 RAM (free -m)", "free -m"),
    "uptime": ("⏱ Uptime & Load", "uptime && who"),
    "nginx_st": ("🌐 Nginx Status", "systemctl status nginx --no-pager -l | head -n 25"),
    "nginx_rs": ("🔄 Restart Nginx", "systemctl restart nginx && systemctl is-active nginx"),
    "caddy_st": ("🔒 Caddy Status", "systemctl status caddy --no-pager -l | head -n 25"),
    "caddy_rs": ("🔄 Restart Caddy", "systemctl restart caddy && systemctl is-active caddy"),
}

DB_LOCK = asyncio.Lock()

# ============================= STORAGE (SQLite + Fernet) =============================
def init_db() -> None:
    conn = sqlite3.connect(DB_FILE)
    try:
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS accounts (
                uid INTEGER NOT NULL,
                name TEXT NOT NULL,
                ak_enc TEXT NOT NULL,
                sk_enc TEXT NOT NULL,
                default_region TEXT DEFAULT 'us-east-1',
                created_at INTEGER NOT NULL,
                PRIMARY KEY (uid, name)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS settings (
                uid INTEGER PRIMARY KEY,
                alerts_on INTEGER DEFAULT 1,
                alert_interval_min INTEGER DEFAULT 30,
                alert_cf_pct INTEGER DEFAULT 80,
                alert_cpu_pct INTEGER DEFAULT 90
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS cb_tokens (
                token TEXT PRIMARY KEY,
                uid INTEGER NOT NULL,
                payload TEXT NOT NULL,
                created_at INTEGER NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS watchers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                uid INTEGER NOT NULL,
                acc TEXT NOT NULL,
                kind TEXT NOT NULL,
                target_id TEXT NOT NULL,
                meta TEXT DEFAULT '{}',
                created_at INTEGER NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS alert_log (
                alert_key TEXT PRIMARY KEY,
                sent_at INTEGER NOT NULL
            )
            """
        )
        conn.commit()
    finally:
        conn.close()
    try:
        os.chmod(DB_FILE, 0o600)
    except OSError:
        pass


def enc(s: str) -> str:
    return FERNET.encrypt(s.encode()).decode()


def dec(s: str) -> str:
    return FERNET.decrypt(s.encode()).decode()


def _db_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn


async def db_get_accounts(uid: int) -> Dict[str, Dict[str, str]]:
    async with DB_LOCK:
        def _op():
            conn = _db_conn()
            try:
                rows = conn.execute(
                    "SELECT name, ak_enc, sk_enc, default_region FROM accounts WHERE uid=? ORDER BY name",
                    (uid,),
                ).fetchall()
                return {
                    r["name"]: {
                        "ak": r["ak_enc"],
                        "sk": r["sk_enc"],
                        "region": r["default_region"] or "us-east-1",
                    }
                    for r in rows
                }
            finally:
                conn.close()
        return await asyncio.to_thread(_op)


async def db_get_all_accounts() -> List[Dict[str, Any]]:
    async with DB_LOCK:
        def _op():
            conn = _db_conn()
            try:
                rows = conn.execute(
                    "SELECT uid, name, ak_enc, sk_enc, default_region FROM accounts"
                ).fetchall()
                return [dict(r) for r in rows]
            finally:
                conn.close()
        return await asyncio.to_thread(_op)


async def db_save_account(uid: int, name: str, ak: str, sk: str, region: str = "us-east-1") -> None:
    async with DB_LOCK:
        def _op():
            conn = _db_conn()
            try:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO accounts (uid, name, ak_enc, sk_enc, default_region, created_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (uid, name, enc(ak), enc(sk), region, int(time.time())),
                )
                conn.commit()
            finally:
                conn.close()
        await asyncio.to_thread(_op)


async def db_update_account_region(uid: int, name: str, region: str) -> None:
    async with DB_LOCK:
        def _op():
            conn = _db_conn()
            try:
                conn.execute(
                    "UPDATE accounts SET default_region=? WHERE uid=? AND name=?",
                    (region, uid, name),
                )
                conn.commit()
            finally:
                conn.close()
        await asyncio.to_thread(_op)


async def db_delete_account(uid: int, name: str) -> None:
    async with DB_LOCK:
        def _op():
            conn = _db_conn()
            try:
                conn.execute("DELETE FROM accounts WHERE uid=? AND name=?", (uid, name))
                conn.execute("DELETE FROM watchers WHERE uid=? AND acc=?", (uid, name))
                conn.commit()
            finally:
                conn.close()
        await asyncio.to_thread(_op)


async def db_get_settings(uid: int) -> Dict[str, Any]:
    async with DB_LOCK:
        def _op():
            conn = _db_conn()
            try:
                row = conn.execute("SELECT * FROM settings WHERE uid=?", (uid,)).fetchone()
                if not row:
                    conn.execute("INSERT INTO settings (uid) VALUES (?)", (uid,))
                    conn.commit()
                    return {
                        "uid": uid,
                        "alerts_on": 1,
                        "alert_interval_min": 30,
                        "alert_cf_pct": 80,
                        "alert_cpu_pct": 90,
                    }
                return dict(row)
            finally:
                conn.close()
        return await asyncio.to_thread(_op)


async def db_update_settings(uid: int, **kwargs: Any) -> None:
    if not kwargs:
        return
    await db_get_settings(uid)
    async with DB_LOCK:
        def _op():
            conn = _db_conn()
            try:
                cols = ", ".join(f"{k}=?" for k in kwargs)
                vals = list(kwargs.values()) + [uid]
                conn.execute(f"UPDATE settings SET {cols} WHERE uid=?", vals)
                conn.commit()
            finally:
                conn.close()
        await asyncio.to_thread(_op)


async def cb_put(uid: int, action: str, **data: Any) -> str:
    """Stores arbitrary callback payload in SQLite and returns a short <=12 byte token."""
    payload = json.dumps({"a": action, **data}, separators=(",", ":"))
    token = secrets.token_urlsafe(6)
    async with DB_LOCK:
        def _op():
            conn = _db_conn()
            try:
                now = int(time.time())
                conn.execute(
                    "INSERT INTO cb_tokens (token, uid, payload, created_at) VALUES (?, ?, ?, ?)",
                    (token, uid, payload, now),
                )
                # Keep table compact: remove tokens older than 7 days
                conn.execute("DELETE FROM cb_tokens WHERE created_at < ?", (now - 7 * 86400,))
                conn.commit()
            finally:
                conn.close()
        await asyncio.to_thread(_op)
    return f"t|{token}"


async def cb_get(uid: int, token: str) -> Optional[Dict[str, Any]]:
    async with DB_LOCK:
        def _op():
            conn = _db_conn()
            try:
                row = conn.execute(
                    "SELECT payload FROM cb_tokens WHERE token=? AND uid=?",
                    (token, uid),
                ).fetchone()
                return json.loads(row["payload"]) if row else None
            finally:
                conn.close()
        return await asyncio.to_thread(_op)


async def db_add_watcher(uid: int, acc: str, kind: str, target_id: str, meta: Optional[Dict[str, Any]] = None) -> None:
    async with DB_LOCK:
        def _op():
            conn = _db_conn()
            try:
                exists = conn.execute(
                    "SELECT 1 FROM watchers WHERE uid=? AND acc=? AND kind=? AND target_id=?",
                    (uid, acc, kind, target_id),
                ).fetchone()
                if not exists:
                    conn.execute(
                        "INSERT INTO watchers (uid, acc, kind, target_id, meta, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                        (uid, acc, kind, target_id, json.dumps(meta or {}), int(time.time())),
                    )
                    conn.commit()
            finally:
                conn.close()
        await asyncio.to_thread(_op)


async def db_list_watchers() -> List[Dict[str, Any]]:
    async with DB_LOCK:
        def _op():
            conn = _db_conn()
            try:
                rows = conn.execute("SELECT * FROM watchers").fetchall()
                return [dict(r) for r in rows]
            finally:
                conn.close()
        return await asyncio.to_thread(_op)


async def db_remove_watcher(wid: int) -> None:
    async with DB_LOCK:
        def _op():
            conn = _db_conn()
            try:
                conn.execute("DELETE FROM watchers WHERE id=?", (wid,))
                conn.commit()
            finally:
                conn.close()
        await asyncio.to_thread(_op)


async def db_alert_recently_sent(alert_key: str, cooldown_sec: int = 86400) -> bool:
    async with DB_LOCK:
        def _op():
            conn = _db_conn()
            try:
                row = conn.execute("SELECT sent_at FROM alert_log WHERE alert_key=?", (alert_key,)).fetchone()
                now = int(time.time())
                if row and (now - row["sent_at"]) < cooldown_sec:
                    return True
                conn.execute(
                    "INSERT OR REPLACE INTO alert_log (alert_key, sent_at) VALUES (?, ?)",
                    (alert_key, now),
                )
                conn.commit()
                return False
            finally:
                conn.close()
        return await asyncio.to_thread(_op)


# ============================= AWS CLIENT & HELPERS =============================
async def aws_client(uid: int, acc: str, svc: str = "cloudfront", region: str = "us-east-1"):
    accounts = await db_get_accounts(uid)
    if acc not in accounts:
        raise ValueError(f"Account '{acc}' haipo.")
    a = accounts[acc]
    return boto3.client(
        svc,
        aws_access_key_id=dec(a["ak"]),
        aws_secret_access_key=dec(a["sk"]),
        region_name=region,
    )


async def run(fn: Callable, *args, **kwargs):
    return await asyncio.to_thread(fn, *args, **kwargs)


def esc(s: Any) -> str:
    return html.escape(str(s))


def progress_bar(val: float, max_val: float, width: int = 10) -> str:
    pct = 0.0 if max_val <= 0 else max(0.0, min(1.0, val / max_val))
    filled = int(round(pct * width))
    return "█" * filled + "░" * (width - filled)


def clean_domain(s: str) -> Optional[str]:
    s = re.sub(r"^https?://", "", s.strip().lower()).split("/")[0].split(":")[0]
    return s if re.fullmatch(r"[a-z0-9]([a-z0-9.-]*[a-z0-9])?", s) and "." in s else None


def save_dist_backup(did: str, cfg: Dict[str, Any]) -> str:
    ts = int(time.time())
    path = os.path.join(BACKUP_DIR, f"{did}-{ts}.json")
    with open(path, "w") as f:
        json.dump(cfg, f, indent=2, default=str)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    # Auto-prune old backups beyond MAX_BACKUPS_PER_DIST
    files = sorted(
        [fn for fn in os.listdir(BACKUP_DIR) if fn.startswith(f"{did}-") and fn.endswith(".json")],
        reverse=True,
    )
    for old in files[MAX_BACKUPS_PER_DIST:]:
        try:
            os.remove(os.path.join(BACKUP_DIR, old))
        except OSError:
            pass
    return path


def list_dist_backups(did: str) -> List[str]:
    if not os.path.isdir(BACKUP_DIR):
        return []
    return sorted(
        [fn for fn in os.listdir(BACKUP_DIR) if fn.startswith(f"{did}-") and fn.endswith(".json")],
        reverse=True,
    )[:MAX_BACKUPS_PER_DIST]


# ---------- CloudFront Helpers ----------
def cf_all_dists(cl) -> List[Dict[str, Any]]:
    out = []
    for pg in cl.get_paginator("list_distributions").paginate():
        out += pg.get("DistributionList", {}).get("Items", []) or []
    return out


def cf_mutate(cl, did: str, fn: Callable[[Dict[str, Any]], None]) -> Dict[str, Any]:
    r = cl.get_distribution_config(Id=did)
    cfg = r["DistributionConfig"]
    save_dist_backup(did, cfg)
    fn(cfg)
    resp = cl.update_distribution(Id=did, IfMatch=r["ETag"], DistributionConfig=cfg)
    return resp["Distribution"]


def cf_build_cfg(origin: str, http_port: int, label: str, proto: str = "http-only", https_port: int = 443) -> Dict[str, Any]:
    return {
        "CallerReference": str(time.time()),
        "Comment": label[:128],
        "Enabled": True,
        "Origins": {
            "Quantity": 1,
            "Items": [
                {
                    "Id": "origin-1",
                    "DomainName": origin,
                    "CustomHeaders": {"Quantity": 0},
                    "CustomOriginConfig": {
                        "HTTPPort": http_port,
                        "HTTPSPort": https_port,
                        "OriginProtocolPolicy": proto,
                        "OriginSslProtocols": {"Quantity": 1, "Items": ["TLSv1.2"]},
                        "OriginReadTimeout": 60,
                        "OriginKeepaliveTimeout": 60,
                    },
                }
            ],
        },
        "DefaultCacheBehavior": {
            "TargetOriginId": "origin-1",
            "ViewerProtocolPolicy": "redirect-to-https",
            "AllowedMethods": {
                "Quantity": 7,
                "Items": ["GET", "HEAD", "OPTIONS", "PUT", "POST", "PATCH", "DELETE"],
                "CachedMethods": {"Quantity": 2, "Items": ["GET", "HEAD"]},
            },
            "CachePolicyId": CACHING_DISABLED,
            "OriginRequestPolicyId": ALL_VIEWER,
            "Compress": False,
        },
        "HttpVersion": "http2and3",
        "IsIPV6Enabled": True,
        "PriceClass": "PriceClass_All",
    }


def cw_cf_metrics(cw, did: str) -> Dict[str, float]:
    now = datetime.now(timezone.utc)
    start_month = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    start_24h = now - timedelta(hours=24)
    dims = [
        {"Name": "DistributionId", "Value": did},
        {"Name": "Region", "Value": "Global"},
    ]

    def _sum(metric: str, start: datetime, period: int = 86400) -> float:
        r = cw.get_metric_statistics(
            Namespace="AWS/CloudFront",
            MetricName=metric,
            Dimensions=dims,
            StartTime=start,
            EndTime=now,
            Period=period,
            Statistics=["Sum"],
        )
        return float(sum(p["Sum"] for p in r.get("Datapoints", [])))

    def _avg(metric: str, start: datetime, period: int = 3600) -> float:
        r = cw.get_metric_statistics(
            Namespace="AWS/CloudFront",
            MetricName=metric,
            Dimensions=dims,
            StartTime=start,
            EndTime=now,
            Period=period,
            Statistics=["Average"],
        )
        pts = [p["Average"] for p in r.get("Datapoints", [])]
        return float(sum(pts) / len(pts)) if pts else 0.0

    gb_month = _sum("BytesDownloaded", start_month) / (1024 ** 3)
    reqs_month = _sum("Requests", start_month)
    err4xx = _avg("4xxErrorRate", start_24h)
    err5xx = _avg("5xxErrorRate", start_24h)
    return {
        "gb": gb_month,
        "requests": reqs_month,
        "err4xx": err4xx,
        "err5xx": err5xx,
    }


def cw_cf_month_gb_only(cw, did: str) -> float:
    now = datetime.now(timezone.utc)
    start_month = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    r = cw.get_metric_statistics(
        Namespace="AWS/CloudFront",
        MetricName="BytesDownloaded",
        Dimensions=[
            {"Name": "DistributionId", "Value": did},
            {"Name": "Region", "Value": "Global"},
        ],
        StartTime=start_month,
        EndTime=now,
        Period=86400,
        Statistics=["Sum"],
    )
    return float(sum(p["Sum"] for p in r.get("Datapoints", []))) / (1024 ** 3)


def cf_month_invalidations(cl, did: str) -> Tuple[int, List[Dict[str, Any]]]:
    r = cl.list_invalidations(DistributionId=did, MaxItems="50")
    items = r.get("InvalidationList", {}).get("Items", []) or []
    now = datetime.now(timezone.utc)
    start_month = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    month_count = sum(1 for i in items if i["CreateTime"] >= start_month)
    return month_count, items[:5]


# ---------- EC2 Helpers ----------
def ec2_tag_name(inst: Dict[str, Any]) -> str:
    for t in inst.get("Tags") or []:
        if t.get("Key") == "Name" and t.get("Value"):
            return t["Value"]
    return inst["InstanceId"]


def ec2_state_emoji(state: str) -> str:
    return {
        "running": "🟢",
        "stopped": "🔴",
        "pending": "🟡",
        "stopping": "🟠",
        "shutting-down": "🟠",
        "terminated": "⚫",
    }.get(state, "⚪")


def ec2_list_instances(ec2_cl) -> List[Dict[str, Any]]:
    out = []
    for pg in ec2_cl.get_paginator("describe_instances").paginate():
        for res in pg.get("Reservations", []):
            for inst in res.get("Instances", []):
                if inst.get("State", {}).get("Name") != "terminated":
                    out.append(inst)
    return out


def ec2_get_instance(ec2_cl, iid: str) -> Dict[str, Any]:
    r = ec2_cl.describe_instances(InstanceIds=[iid])
    return r["Reservations"][0]["Instances"][0]


def ec2_metrics(cw, iid: str) -> Dict[str, float]:
    now = datetime.now(timezone.utc)
    start_1h = now - timedelta(hours=1)
    start_24h = now - timedelta(hours=24)
    dims = [{"Name": "InstanceId", "Value": iid}]

    cpu_r = cw.get_metric_statistics(
        Namespace="AWS/EC2",
        MetricName="CPUUtilization",
        Dimensions=dims,
        StartTime=start_1h,
        EndTime=now,
        Period=300,
        Statistics=["Average"],
    )
    cpu_pts = sorted(cpu_r.get("Datapoints", []), key=lambda x: x["Timestamp"])
    cpu_now = float(cpu_pts[-1]["Average"]) if cpu_pts else 0.0

    net_out_r = cw.get_metric_statistics(
        Namespace="AWS/EC2",
        MetricName="NetworkOut",
        Dimensions=dims,
        StartTime=start_24h,
        EndTime=now,
        Period=3600,
        Statistics=["Sum"],
    )
    net_out_gb = float(sum(p["Sum"] for p in net_out_r.get("Datapoints", []))) / (1024 ** 3)

    net_in_r = cw.get_metric_statistics(
        Namespace="AWS/EC2",
        MetricName="NetworkIn",
        Dimensions=dims,
        StartTime=start_24h,
        EndTime=now,
        Period=3600,
        Statistics=["Sum"],
    )
    net_in_gb = float(sum(p["Sum"] for p in net_in_r.get("Datapoints", []))) / (1024 ** 3)
    return {"cpu": cpu_now, "net_out_gb": net_out_gb, "net_in_gb": net_in_gb}


def ec2_get_cf_prefix_list_id(ec2_cl) -> Optional[str]:
    r = ec2_cl.describe_managed_prefix_lists(
        Filters=[{"Name": "prefix-list-name", "Values": ["com.amazonaws.global.cloudfront.origin-facing"]}]
    )
    pls = r.get("PrefixLists", [])
    return pls[0]["PrefixListId"] if pls else None


def ec2_describe_sg_ports(ec2_cl, sg_ids: List[str]) -> Tuple[str, List[Dict[str, Any]]]:
    if not sg_ids:
        return "Hakuna SG", []
    r = ec2_cl.describe_security_groups(GroupIds=sg_ids)
    sgs = r.get("SecurityGroups", [])
    summary_parts = []
    for sg in sgs:
        for perm in sg.get("IpPermissions", []):
            fp = perm.get("FromPort")
            tp = perm.get("ToPort")
            proto = perm.get("IpProtocol")
            p_str = "ALL" if proto == "-1" else (f"{fp}" if fp == tp else f"{fp}-{tp}")
            if perm.get("PrefixListIds"):
                summary_parts.append(f"{p_str}(CF/PL)")
            elif any(x.get("CidrIp") == "0.0.0.0/0" for x in perm.get("IpRanges", [])):
                summary_parts.append(f"{p_str}(Public)")
            else:
                summary_parts.append(f"{p_str}(Restricted)")
    unique_summary = ", ".join(dict.fromkeys(summary_parts)) or "Hakuna ports wazi"
    return unique_summary, sgs


# ============================= UI HELPERS =============================
HOME_BTN = [B("🏠 Menu Kuu", "home")]
CANCEL_HOME = [[B("✖️ Ghairi", "home")]]


async def show(u: Update, text: str, rows: Optional[List[List[InlineKeyboardButton]]] = None, force_new: bool = False) -> None:
    kb = M(rows) if rows else None
    q = u.callback_query
    try:
        if q and not force_new:
            await q.edit_message_text(
                text, parse_mode="HTML", reply_markup=kb, link_preview_options=NO_PREVIEW
            )
            return
    except BadRequest as e:
        if "not modified" in str(e).lower():
            return
    except TelegramError:
        pass
    try:
        if u.effective_message and not force_new:
            await u.effective_message.reply_text(
                text, parse_mode="HTML", reply_markup=kb, link_preview_options=NO_PREVIEW
            )
            return
    except TelegramError:
        pass
    if u.effective_chat:
        await u.get_bot().send_message(
            chat_id=u.effective_chat.id,
            text=text,
            parse_mode="HTML",
            reply_markup=kb,
            link_preview_options=NO_PREVIEW,
        )


async def show_loading(u: Update, msg: str = "Inawasiliana na AWS...") -> None:
    q = u.callback_query
    if q:
        try:
            await q.edit_message_text(f"⏳ <i>{esc(msg)}</i>", parse_mode="HTML")
        except TelegramError:
            pass


async def safe_delete_msg(u: Update) -> None:
    try:
        if u.message:
            await u.message.delete()
    except TelegramError:
        pass


# ============================= HOME & SETTINGS =============================
async def h_home(u: Update, c: ContextTypes.DEFAULT_TYPE, p: Dict[str, Any]) -> None:
    uid = u.effective_user.id
    accs = await db_get_accounts(uid)
    st = await db_get_settings(uid)
    alerts_txt = "ON" if st["alerts_on"] else "OFF"

    summary_block = f"👤 <b>Accounts:</b> <code>{len(accs)}</code>\n"
    if not accs:
        summary_block += "ℹ️ <i>Unganisha AWS account kuanza kudhibiti CloudFront na EC2.</i>"
    else:
        acc_names = ", ".join(list(accs.keys())[:4])
        summary_block += (
            f"🔑 <b>Zilizounganishwa:</b> <code>{esc(acc_names)}</code>\n"
            f"🔔 <b>Alerts:</b> <code>{alerts_txt}</code> (CF ≥ {st['alert_cf_pct']}% · CPU ≥ {st['alert_cpu_pct']}%)"
        )

    text = (
        "⚡ <b>AWS Control Panel</b>\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        f"<blockquote>{summary_block}</blockquote>\n"
        "Chagua huduma unayotaka kudhibiti:"
    )
    rows = [
        [B("☁️ CloudFront", "pk|dl"), B("🖥 EC2 Servers", "pk|ec2")],
        [B("➕ Create CF", "pk|cr"), B("🔎 Scan Regions", "pk|scan")],
        [B("📊 Analytics", "pk|ua"), B(f"🔔 Alerts: {alerts_txt}", "tgl_al")],
        [B("👤 Accounts", "acc"), B("⚙️ Bot Settings", "bset")],
        [B("❓ Msaada", "help")],
    ]
    await show(u, text, rows)


async def h_tgl_al(u: Update, c: ContextTypes.DEFAULT_TYPE, p: Dict[str, Any]) -> None:
    uid = u.effective_user.id
    st = await db_get_settings(uid)
    await db_update_settings(uid, alerts_on=0 if st["alerts_on"] else 1)
    await h_home(u, c, {})


async def h_bset(u: Update, c: ContextTypes.DEFAULT_TYPE, p: Dict[str, Any]) -> None:
    uid = u.effective_user.id
    st = await db_get_settings(uid)
    alerts_txt = "🟢 ON" if st["alerts_on"] else "🔴 OFF"
    text = (
        "🏠 <b>Home</b> › ⚙️ <b>Bot Settings</b>\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        f"<blockquote>🔔 <b>Proactive Alerts:</b> {alerts_txt}\n"
        f"📊 <b>CloudFront Free Tier Alert:</b> <code>{st['alert_cf_pct']}%</code> ya 1024 GB\n"
        f"🔥 <b>EC2 CPU Alert:</b> <code>{st['alert_cpu_pct']}%</code>\n"
        f"⏱ <b>Check Interval:</b> kila dakika <code>{st['alert_interval_min']}</code></blockquote>"
    )
    rows = [
        [B("🔔 Washa/Zima Alerts", "tgl_al_s")],
        [B("📊 Badili CF % Alert", "set_cfp"), B("🔥 Badili CPU % Alert", "set_cpup")],
        HOME_BTN,
    ]
    await show(u, text, rows)


async def h_help(u: Update, c: ContextTypes.DEFAULT_TYPE, p: Dict[str, Any]) -> None:
    text = (
        "❓ <b>Mwongozo wa AWS Control Bot</b>\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        "<blockquote>1️⃣ <b>Accounts:</b> Unganisha IAM Access Key + Secret Key (husimbwa kwa Fernet AES).\n"
        "2️⃣ <b>CloudFront:</b> Unda, hariri Origin/HTTP & HTTPS Port, HTTP/3, Cache, Geo, WAF, Custom Headers, ACM SSL, Purge, na Backup/Restore.\n"
        "3️⃣ <b>EC2 Servers:</b> Chagua Region au bonyeza <i>Scan Regions</i>, Start/Stop/Reboot, Firewall/SG (pamoja na <i>CloudFront Only</i>), Elastic IP, Snapshot, na Run Command (SSM).\n"
        "4️⃣ <b>EC2 → CloudFront:</b> Unganisha DNS ya EC2 yako moja kwa moja kama Origin ya CloudFront kwa kubonyeza mara moja.\n"
        "5️⃣ <b>Auto-Notify:</b> Bot inafuatilia Deployments za CloudFront na ACM SSL na kukutumia taarifa ikikamilika.</blockquote>"
    )
    await show(u, text, [HOME_BTN])


# ============================= ACCOUNT PICKER & MANAGEMENT =============================
async def h_pk(u: Update, c: ContextTypes.DEFAULT_TYPE, p: Dict[str, Any]) -> None:
    uid = u.effective_user.id
    purpose = p["purpose"]
    accs = await db_get_accounts(uid)
    if not accs:
        return await show(
            u,
            "⚠️ Bado hujaunganisha AWS account yoyote.",
            [[B("➕ Add Account", "aa")], HOME_BTN],
        )
    # Shortcut if only 1 account exists
    if len(accs) == 1:
        only_acc = next(iter(accs))
        if purpose == "dl":
            return await h_dl(u, c, {"acc": only_acc, "pg": 0})
        if purpose == "cr":
            return await h_cr(u, c, {"acc": only_acc})
        if purpose == "ua":
            return await h_ua(u, c, {"acc": only_acc})
        if purpose == "ec2":
            return await h_ec2_regions(u, c, {"acc": only_acc})
        if purpose == "scan":
            return await h_ec2_scan(u, c, {"acc": only_acc})

    titles = {
        "dl": "☁️ Chagua account (CloudFront):",
        "cr": "➕ Create CloudFront kwenye account ipi?",
        "ua": "📊 Analytics za account ipi?",
        "ec2": "🖥 Chagua account (EC2 Servers):",
        "scan": "🔎 Scan EC2 Regions za account ipi?",
    }
    rows = []
    for name in accs:
        tok = await cb_put(uid, purpose, acc=name, pg=0)
        rows.append([B(f"👤 {name}", tok)])
    rows.append(HOME_BTN)
    await show(u, titles.get(purpose, "Chagua account:"), rows)


async def h_acc(u: Update, c: ContextTypes.DEFAULT_TYPE, p: Dict[str, Any]) -> None:
    uid = u.effective_user.id
    accs = await db_get_accounts(uid)
    rows = []
    for name, info in accs.items():
        t_info = await cb_put(uid, "ai", acc=name)
        t_del = await cb_put(uid, "ad", acc=name)
        rows.append([B(f"👤 {name} ({info['region']})", t_info), B("🗑", t_del)])
    rows += [[B("➕ Add Account", "aa")], HOME_BTN]
    await show(
        u,
        f"🏠 <b>Home</b> › 👤 <b>Accounts ({len(accs)})</b>\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        "Keys zote zimesimbwa (encrypted) kwenye SQLite.",
        rows,
    )


async def h_aa(u: Update, c: ContextTypes.DEFAULT_TYPE, p: Dict[str, Any]) -> None:
    c.user_data["flow"] = {"t": "aname"}
    await show(
        u,
        "➕ <b>Account Mpya</b>\n\n"
        "Tuma jina fupi la account (herufi/namba/_, max 15). Mfano: <code>aws_main</code>",
        CANCEL_HOME,
    )


async def h_ai(u: Update, c: ContextTypes.DEFAULT_TYPE, p: Dict[str, Any]) -> None:
    uid, acc = u.effective_user.id, p["acc"]
    await show_loading(u, f"Inakagua {acc}...")
    sts = await aws_client(uid, acc, "sts")
    cf = await aws_client(uid, acc, "cloudfront")
    me, ds = await asyncio.gather(run(sts.get_caller_identity), run(cf_all_dists, cf))
    accs = await db_get_accounts(uid)
    def_reg = accs[acc]["region"]
    t_cf = await cb_put(uid, "dl", acc=acc, pg=0)
    t_ec2 = await cb_put(uid, "ec2", acc=acc)
    t_scan = await cb_put(uid, "scan", acc=acc)
    await show(
        u,
        f"🏠 <b>Home</b> › 👤 <b>{esc(acc)}</b>\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        f"<blockquote>🆔 <b>AWS Account:</b> <code>{me['Account']}</code>\n"
        f"👤 <b>IAM ARN:</b> <code>{esc(me['Arn'].split(':')[-1])}</code>\n"
        f"☁️ <b>CloudFront:</b> <code>{len(ds)}</code> distributions\n"
        f"🌍 <b>Default EC2 Region:</b> <code>{def_reg}</code></blockquote>",
        [
            [B("☁️ CloudFront", t_cf), B("🖥 EC2 Servers", t_ec2)],
            [B("🔎 Scan All EC2 Regions", t_scan)],
            [B("⬅️ Accounts", "acc")],
        ],
    )


async def h_ad(u: Update, c: ContextTypes.DEFAULT_TYPE, p: Dict[str, Any]) -> None:
    uid, acc = u.effective_user.id, p["acc"]
    t_ok = await cb_put(uid, "adok", acc=acc)
    await show(
        u,
        f"🗑 Futa account <b>{esc(acc)}</b> kwenye bot? (AWS yako haiguswi)",
        [[B("✅ Ndiyo, Futa", t_ok), B("❌ Hapana", "acc")]],
    )


async def h_adok(u: Update, c: ContextTypes.DEFAULT_TYPE, p: Dict[str, Any]) -> None:
    await db_delete_account(u.effective_user.id, p["acc"])
    await h_acc(u, c, {})


# ============================= CLOUDFRONT LIST & DETAIL =============================
async def h_dl(u: Update, c: ContextTypes.DEFAULT_TYPE, p: Dict[str, Any]) -> None:
    uid, acc, page = u.effective_user.id, p["acc"], int(p.get("pg", 0))
    await show_loading(u, f"Inapakia CloudFront za {acc}...")
    cf = await aws_client(uid, acc, "cloudfront")
    ds = await run(cf_all_dists, cf)
    per = 8
    chunk = ds[page * per : (page + 1) * per]
    rows = []
    for d in chunk:
        al = (d.get("Aliases", {}).get("Items") or [d["DomainName"]])[0]
        label = d.get("Comment") or al
        dot = "🟢" if d["Enabled"] and d["Status"] == "Deployed" else ("🟡" if d["Status"] != "Deployed" else "🔴")
        tok = await cb_put(uid, "d", acc=acc, did=d["Id"])
        rows.append([B(f"{dot} {d['Id']} · {label}"[:55], tok)])

    nav = []
    if page > 0:
        nav.append(B("◀️ Nyuma", await cb_put(uid, "dl", acc=acc, pg=page - 1)))
    if (page + 1) * per < len(ds):
        nav.append(B("Mbele ▶️", await cb_put(uid, "dl", acc=acc, pg=page + 1)))
    if nav:
        rows.append(nav)

    rows += [
        [B("➕ Create CF", await cb_put(uid, "cr", acc=acc)), B("📊 Analytics", await cb_put(uid, "ua", acc=acc))],
        HOME_BTN,
    ]
    await show(
        u,
        f"🏠 <b>Home</b> › 👤 <b>{esc(acc)}</b> › ☁️ <b>CloudFront</b>\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        f"Jumla ya Distributions: <b>{len(ds)}</b> (Ukurasa {page + 1})",
        rows,
    )


async def show_cf_detail(u: Update, c: ContextTypes.DEFAULT_TYPE, acc: str, did: str, with_metrics: bool = True) -> None:
    uid = u.effective_user.id
    cf = await aws_client(uid, acc, "cloudfront")
    cw = await aws_client(uid, acc, "cloudwatch", "us-east-1")
    if with_metrics:
        dist_r, metrics = await asyncio.gather(
            run(cf.get_distribution, Id=did),
            run(cw_cf_metrics, cw, did),
        )
    else:
        dist_r = await run(cf.get_distribution, Id=did)
        metrics = None

    D = dist_r["Distribution"]
    cfg = D["DistributionConfig"]
    origins = cfg["Origins"]["Items"]
    o = origins[0]
    co = o.get("CustomOriginConfig") or {}
    al = cfg.get("Aliases", {}).get("Items") or []
    vc = cfg.get("ViewerCertificate", {})
    on = cfg["Enabled"]
    status = D["Status"]
    dot = "🟢" if (on and status == "Deployed") else ("🟡" if status != "Deployed" else "🔴")

    proto = co.get("OriginProtocolPolicy", "S3/Other")
    if proto == "http-only":
        port_txt = f"<code>{co.get('HTTPPort', '-')}</code> (http-only)"
    elif proto == "https-only":
        port_txt = f"<code>{co.get('HTTPSPort', '-')}</code> (https-only)"
    elif proto == "match-viewer":
        port_txt = f"HTTP <code>{co.get('HTTPPort', '-')}</code> / HTTPS <code>{co.get('HTTPSPort', '-')}</code>"
    else:
        port_txt = "S3 Origin"

    http_v = cfg.get("HttpVersion", "http2").upper().replace("HTTP2AND3", "HTTP/3")
    dcb = cfg.get("DefaultCacheBehavior", {})
    cache_lbl = "Disabled" if dcb.get("CachePolicyId") == CACHING_DISABLED else ("Optimized" if dcb.get("CachePolicyId") == CACHING_OPTIMIZED else "Custom")

    block = (
        f"🎯 <b>Origin ({len(origins)}):</b> <code>{esc(o['DomainName'])}</code>\n"
        f"🔌 <b>Port:</b> {port_txt} · {http_v}\n"
        f"🌐 <b>Edge:</b> <code>{D['DomainName']}</code>\n"
        f"🔗 <b>Custom:</b> <code>{esc(', '.join(al))}</code>\n" if al else
        f"🎯 <b>Origin ({len(origins)}):</b> <code>{esc(o['DomainName'])}</code>\n"
        f"🔌 <b>Port:</b> {port_txt} · {http_v}\n"
        f"🌐 <b>Edge:</b> <code>{D['DomainName']}</code>\n"
    )
    block += (
        f"⚡ <b>Cache:</b> {cache_lbl} · <b>Cert:</b> {'ACM' if vc.get('ACMCertificateArn') else 'Default'}\n"
        f"💲 <b>Price:</b> {cfg.get('PriceClass', '-').replace('PriceClass_', '')} · <b>IPv6:</b> {'ON' if cfg.get('IsIPV6Enabled') else 'OFF'}"
    )
    if metrics:
        block += (
            f"\n📊 <b>Mwezi huu:</b> <code>{metrics['gb']:.2f} GB</code> · "
            f"Reqs: <code>{int(metrics['requests']):,}</code>\n"
            f"⚠️ <b>Errors (24h):</b> 4xx <code>{metrics['err4xx']:.1f}%</code> · 5xx <code>{metrics['err5xx']:.1f}%</code>"
        )

    title = esc(cfg.get("Comment") or did)
    text = (
        f"🏠 <b>Home</b> › 👤 <b>{esc(acc)}</b> › ☁️ <code>{did}</code>\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        f"{dot} <b>{title}</b> · <i>{status} ({'ON' if on else 'OFF'})</i>\n\n"
        f"<blockquote>{block}</blockquote>"
    )
    if al:
        text += f"\n📌 <i>DNS: CNAME → <code>{D['DomainName']}</code> (DNS only)</i>"

    rows = [
        [
            B("⏸ Disable" if on else "▶️ Enable", await cb_put(uid, "tg", acc=acc, did=did)),
            B("🔄 Refresh", await cb_put(uid, "d", acc=acc, did=did)),
        ],
        [
            B("🎯 Origin & EC2", await cb_put(uid, "om", acc=acc, did=did, oi=0)),
            B("⚙️ Settings", await cb_put(uid, "sm", acc=acc, did=did)),
        ],
        [
            B("🌍 Domains & SSL", await cb_put(uid, "cd", acc=acc, did=did)),
            B("📊 Analytics", await cb_put(uid, "us", acc=acc, did=did)),
        ],
        [
            B("🧹 Purge", await cb_put(uid, "pm", acc=acc, did=did)),
            B("💾 Backup / Restore", await cb_put(uid, "bm", acc=acc, did=did)),
        ],
        [
            B("🗑 Delete", await cb_put(uid, "rm", acc=acc, did=did)),
            B("⬅️ Back", await cb_put(uid, "dl", acc=acc, pg=0)),
        ],
    ]
    await show(u, text, rows)


async def h_d(u: Update, c: ContextTypes.DEFAULT_TYPE, p: Dict[str, Any]) -> None:
    await show_loading(u, f"Inapakia {p['did']}...")
    await show_cf_detail(u, c, p["acc"], p["did"])


async def cf_edit_and_watch(
    u: Update,
    c: ContextTypes.DEFAULT_TYPE,
    acc: str,
    did: str,
    fn: Callable[[Dict[str, Any]], None],
    return_to: str = "d",
    oi: int = 0,
) -> None:
    uid = u.effective_user.id
    await show_loading(u, "Inahifadhi mabadiliko AWS...")
    cf = await aws_client(uid, acc, "cloudfront")
    await run(cf_mutate, cf, did, fn)
    await db_add_watcher(uid, acc, "cf_deploy", did)
    if return_to == "sm":
        await h_sm(u, c, {"acc": acc, "did": did})
    elif return_to == "om":
        await h_om(u, c, {"acc": acc, "did": did, "oi": oi})
    else:
        await show_cf_detail(u, c, acc, did)


async def h_tg(u: Update, c: ContextTypes.DEFAULT_TYPE, p: Dict[str, Any]) -> None:
    def _fn(cfg):
        cfg["Enabled"] = not cfg["Enabled"]
    await cf_edit_and_watch(u, c, p["acc"], p["did"], _fn)


# ============================= CLOUDFRONT ORIGIN & EC2 LINK SUB-MENU =============================
async def h_om(u: Update, c: ContextTypes.DEFAULT_TYPE, p: Dict[str, Any]) -> None:
    uid, acc, did = u.effective_user.id, p["acc"], p["did"]
    oi = int(p.get("oi", 0))
    cf = await aws_client(uid, acc, "cloudfront")
    cfg = (await run(cf.get_distribution_config, Id=did))["DistributionConfig"]
    origins = cfg["Origins"]["Items"]
    if oi >= len(origins):
        oi = 0
    o = origins[oi]
    co = o.get("CustomOriginConfig") or {}
    ch = o.get("CustomHeaders", {}).get("Items") or []
    hdr_txt = ", ".join(f"{h['HeaderName']}" for h in ch) if ch else "Hakuna"

    text = (
        f"🏠 <b>Home</b> › ☁️ <code>{did}</code> › 🎯 <b>Origin #{oi + 1}/{len(origins)}</b>\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        f"<blockquote>🆔 <b>Origin ID:</b> <code>{esc(o['Id'])}</code>\n"
        f"🎯 <b>Domain:</b> <code>{esc(o['DomainName'])}</code>\n"
        f"🔌 <b>HTTP Port:</b> <code>{co.get('HTTPPort', '-')}</code> · <b>HTTPS Port:</b> <code>{co.get('HTTPSPort', '-')}</code>\n"
        f"🔒 <b>Protocol:</b> <code>{co.get('OriginProtocolPolicy', 'S3')}</code>\n"
        f"⏱ <b>Read Timeout:</b> <code>{co.get('OriginReadTimeout', '-')}s</code>\n"
        f"🛡 <b>Custom Headers:</b> <code>{esc(hdr_txt)}</code></blockquote>"
    )
    rows = []
    if len(origins) > 1:
        next_i = (oi + 1) % len(origins)
        rows.append([B(f"🔀 Badili Origin ({oi + 1}/{len(origins)})", await cb_put(uid, "om", acc=acc, did=did, oi=next_i))])
    rows += [
        [
            B("✏️ Edit Domain", await cb_put(uid, "or_ed", acc=acc, did=did, oi=oi)),
            B("🖥 Pick from EC2", await cb_put(uid, "or_ec2", acc=acc, did=did, oi=oi)),
        ],
        [
            B("🔌 HTTP Port", await cb_put(uid, "pt_http", acc=acc, did=did, oi=oi)),
            B("🔒 HTTPS Port", await cb_put(uid, "pt_https", acc=acc, did=did, oi=oi)),
        ],
        [
            B("🔄 Origin Protocol", await cb_put(uid, "pp", acc=acc, did=did, oi=oi)),
            B("⏱ Read Timeout", await cb_put(uid, "to_ed", acc=acc, did=did, oi=oi)),
        ],
        [
            B("🛡 Set Custom Header", await cb_put(uid, "ch_ed", acc=acc, did=did, oi=oi)),
            B("🗑 Clear Headers", await cb_put(uid, "ch_cl", acc=acc, did=did, oi=oi)),
        ],
        [B("⬅️ Back to Distribution", await cb_put(uid, "d", acc=acc, did=did))],
    ]
    await show(u, text, rows)


async def h_pp(u: Update, c: ContextTypes.DEFAULT_TYPE, p: Dict[str, Any]) -> None:
    oi = int(p.get("oi", 0))
    def _fn(cfg):
        co = cfg["Origins"]["Items"][oi].get("CustomOriginConfig")
        if not co:
            raise ValueError("Origin hii si Custom Origin (inawezekana ni S3).")
        cur = co["OriginProtocolPolicy"]
        co["OriginProtocolPolicy"] = ORIGIN_PROTOS[(ORIGIN_PROTOS.index(cur) + 1) % len(ORIGIN_PROTOS)]
    await cf_edit_and_watch(u, c, p["acc"], p["did"], _fn, return_to="om", oi=oi)


async def h_ch_cl(u: Update, c: ContextTypes.DEFAULT_TYPE, p: Dict[str, Any]) -> None:
    oi = int(p.get("oi", 0))
    def _fn(cfg):
        cfg["Origins"]["Items"][oi]["CustomHeaders"] = {"Quantity": 0}
    await cf_edit_and_watch(u, c, p["acc"], p["did"], _fn, return_to="om", oi=oi)


async def h_or_ec2(u: Update, c: ContextTypes.DEFAULT_TYPE, p: Dict[str, Any]) -> None:
    """Scan active EC2 instances and let user pick one as CloudFront Origin in 1 click."""
    uid, acc, did, oi = u.effective_user.id, p["acc"], p["did"], int(p.get("oi", 0))
    await show_loading(u, "Inatafuta EC2 instances kwenye regions zote...")
    found = await _scan_ec2_all_regions(uid, acc)
    rows = []
    for reg, inst in found:
        dns = inst.get("PublicDnsName")
        if not dns:
            continue
        name = ec2_tag_name(inst)
        dot = ec2_state_emoji(inst["State"]["Name"])
        tok = await cb_put(uid, "or_ec2_set", acc=acc, did=did, oi=oi, dns=dns)
        rows.append([B(f"{dot} {name} ({reg}) · {inst.get('PublicIpAddress', '')}"[:55], tok)])
    rows.append([B("⬅️ Back", await cb_put(uid, "om", acc=acc, did=did, oi=oi))])
    msg = (
        f"🖥 <b>Chagua EC2 iwe Origin ya <code>{did}</code></b>\n\n"
        + ("Chagua server hapa chini:" if found else "<i>Hakuna EC2 yenye Public DNS iliyopatikana (hakikisha iko Running).</i>")
    )
    await show(u, msg, rows)


async def h_or_ec2_set(u: Update, c: ContextTypes.DEFAULT_TYPE, p: Dict[str, Any]) -> None:
    oi = int(p.get("oi", 0))
    dns = p["dns"]
    def _fn(cfg):
        cfg["Origins"]["Items"][oi]["DomainName"] = dns
    await cf_edit_and_watch(u, c, p["acc"], p["did"], _fn, return_to="om", oi=oi)


# ============================= CLOUDFRONT SETTINGS SUB-MENU =============================
async def h_sm(u: Update, c: ContextTypes.DEFAULT_TYPE, p: Dict[str, Any]) -> None:
    uid, acc, did = u.effective_user.id, p["acc"], p["did"]
    cf = await aws_client(uid, acc, "cloudfront")
    cfg = (await run(cf.get_distribution_config, Id=did))["DistributionConfig"]
    dcb = cfg["DefaultCacheBehavior"]
    geo = cfg.get("Restrictions", {}).get("GeoRestriction", {})
    geo_type = geo.get("RestrictionType", "none")
    geo_items = geo.get("Items") or []
    waf = cfg.get("WebACLId") or "Hakuna"
    cache_id = dcb.get("CachePolicyId", "")
    cache_lbl = "Disabled" if cache_id == CACHING_DISABLED else ("Optimized" if cache_id == CACHING_OPTIMIZED else "Custom")

    text = (
        f"🏠 <b>Home</b> › ☁️ <code>{did}</code> › ⚙️ <b>Settings</b>\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        f"<blockquote>⚡ <b>Cache Policy:</b> <code>{cache_lbl}</code>\n"
        f"🔐 <b>Viewer Protocol:</b> <code>{dcb.get('ViewerProtocolPolicy')}</code>\n"
        f"🚀 <b>HTTP Version:</b> <code>{cfg.get('HttpVersion')}</code>\n"
        f"📦 <b>Compression:</b> <code>{'ON' if dcb.get('Compress') else 'OFF'}</code> · "
        f"<b>IPv6:</b> <code>{'ON' if cfg.get('IsIPV6Enabled') else 'OFF'}</code>\n"
        f"💲 <b>Price Class:</b> <code>{cfg.get('PriceClass')}</code>\n"
        f"🌍 <b>Geo Restriction:</b> <code>{geo_type}</code> {esc(','.join(geo_items)) if geo_items else ''}\n"
        f"🛡 <b>WAF WebACL:</b> <code>{esc(waf.split('/')[-1] if '/' in waf else waf)}</code></blockquote>"
    )
    rows = [
        [
            B("⚡ Toggle Cache", await cb_put(uid, "s_cache", acc=acc, did=did)),
            B("🔐 Viewer Proto", await cb_put(uid, "s_vproto", acc=acc, did=did)),
        ],
        [
            B("🚀 HTTP Version", await cb_put(uid, "s_http", acc=acc, did=did)),
            B("📦 Compress", await cb_put(uid, "s_comp", acc=acc, did=did)),
        ],
        [
            B("🌐 Toggle IPv6", await cb_put(uid, "s_ipv6", acc=acc, did=did)),
            B("💲 Price Class", await cb_put(uid, "s_pc", acc=acc, did=did)),
        ],
        [
            B("🌍 Geo Restriction", await cb_put(uid, "s_geo", acc=acc, did=did)),
            B("🛡 WAF WebACL", await cb_put(uid, "s_waf", acc=acc, did=did)),
        ],
        [
            B("📝 Edit Label", await cb_put(uid, "s_lbl", acc=acc, did=did)),
            B("⬅️ Back", await cb_put(uid, "d", acc=acc, did=did)),
        ],
    ]
    await show(u, text, rows)


async def h_s_cache(u: Update, c: ContextTypes.DEFAULT_TYPE, p: Dict[str, Any]) -> None:
    def _fn(cfg):
        dcb = cfg["DefaultCacheBehavior"]
        cur = dcb.get("CachePolicyId")
        dcb["CachePolicyId"] = CACHING_OPTIMIZED if cur == CACHING_DISABLED else CACHING_DISABLED
        dcb.pop("ForwardedValues", None)
        dcb.pop("MinTTL", None)
        dcb.pop("DefaultTTL", None)
        dcb.pop("MaxTTL", None)
    await cf_edit_and_watch(u, c, p["acc"], p["did"], _fn, return_to="sm")


async def h_s_vproto(u: Update, c: ContextTypes.DEFAULT_TYPE, p: Dict[str, Any]) -> None:
    def _fn(cfg):
        dcb = cfg["DefaultCacheBehavior"]
        cur = dcb.get("ViewerProtocolPolicy", VIEWER_PROTOS[0])
        dcb["ViewerProtocolPolicy"] = VIEWER_PROTOS[(VIEWER_PROTOS.index(cur) + 1) % len(VIEWER_PROTOS)]
    await cf_edit_and_watch(u, c, p["acc"], p["did"], _fn, return_to="sm")


async def h_s_http(u: Update, c: ContextTypes.DEFAULT_TYPE, p: Dict[str, Any]) -> None:
    def _fn(cfg):
        cur = cfg.get("HttpVersion", "http2")
        idx = HTTP_VERSIONS.index(cur) if cur in HTTP_VERSIONS else 0
        cfg["HttpVersion"] = HTTP_VERSIONS[(idx + 1) % len(HTTP_VERSIONS)]
    await cf_edit_and_watch(u, c, p["acc"], p["did"], _fn, return_to="sm")


async def h_s_comp(u: Update, c: ContextTypes.DEFAULT_TYPE, p: Dict[str, Any]) -> None:
    def _fn(cfg):
        cfg["DefaultCacheBehavior"]["Compress"] = not cfg["DefaultCacheBehavior"].get("Compress", False)
    await cf_edit_and_watch(u, c, p["acc"], p["did"], _fn, return_to="sm")


async def h_s_ipv6(u: Update, c: ContextTypes.DEFAULT_TYPE, p: Dict[str, Any]) -> None:
    def _fn(cfg):
        cfg["IsIPV6Enabled"] = not cfg.get("IsIPV6Enabled", True)
    await cf_edit_and_watch(u, c, p["acc"], p["did"], _fn, return_to="sm")


async def h_s_pc(u: Update, c: ContextTypes.DEFAULT_TYPE, p: Dict[str, Any]) -> None:
    def _fn(cfg):
        cur = cfg.get("PriceClass", PRICE_CLASSES[0])
        cfg["PriceClass"] = PRICE_CLASSES[(PRICE_CLASSES.index(cur) + 1) % len(PRICE_CLASSES)]
    await cf_edit_and_watch(u, c, p["acc"], p["did"], _fn, return_to="sm")


async def h_s_geo(u: Update, c: ContextTypes.DEFAULT_TYPE, p: Dict[str, Any]) -> None:
    uid, acc, did = u.effective_user.id, p["acc"], p["did"]
    rows = [
        [B("🔓 Ondoa Geo-Restriction (None)", await cb_put(uid, "s_geo_none", acc=acc, did=did))],
        [
            B("✅ Whitelist (Ruhusu Nchi)", await cb_put(uid, "s_geo_ask", acc=acc, did=did, mode="whitelist")),
            B("🚫 Blacklist (Zuia Nchi)", await cb_put(uid, "s_geo_ask", acc=acc, did=did, mode="blacklist")),
        ],
        [B("⬅️ Back", await cb_put(uid, "sm", acc=acc, did=did))],
    ]
    await show(u, f"🌍 <b>Geo Restriction · <code>{did}</code></b>\n\nChagua aina ya kizuizi cha kijiografia:", rows)


async def h_s_geo_none(u: Update, c: ContextTypes.DEFAULT_TYPE, p: Dict[str, Any]) -> None:
    def _fn(cfg):
        cfg["Restrictions"] = {"GeoRestriction": {"RestrictionType": "none", "Quantity": 0}}
    await cf_edit_and_watch(u, c, p["acc"], p["did"], _fn, return_to="sm")


async def h_s_waf(u: Update, c: ContextTypes.DEFAULT_TYPE, p: Dict[str, Any]) -> None:
    uid, acc, did = u.effective_user.id, p["acc"], p["did"]
    await show_loading(u, "Inatafuta WAF WebACLs (us-east-1)...")
    waf_cl = await aws_client(uid, acc, "wafv2", "us-east-1")
    acls = (await run(waf_cl.list_web_acls, Scope="CLOUDFRONT")).get("WebACLs", [])
    rows = []
    for a in acls[:10]:
        tok = await cb_put(uid, "s_waf_set", acc=acc, did=did, arn=a["ARN"])
        rows.append([B(f"🛡 {a['Name']}", tok)])
    rows += [
        [B("❌ Ondoa WAF", await cb_put(uid, "s_waf_set", acc=acc, did=did, arn=""))],
        [B("⬅️ Back", await cb_put(uid, "sm", acc=acc, did=did))],
    ]
    await show(
        u,
        f"🛡 <b>AWS WAF · <code>{did}</code></b>\n\n"
        + ("Chagua WebACL ya kuunganisha:" if acls else "<i>Hakuna CloudFront WAF WebACL iliyopatikana.</i>"),
        rows,
    )


async def h_s_waf_set(u: Update, c: ContextTypes.DEFAULT_TYPE, p: Dict[str, Any]) -> None:
    arn = p["arn"]
    def _fn(cfg):
        cfg["WebACLId"] = arn
    await cf_edit_and_watch(u, c, p["acc"], p["did"], _fn, return_to="sm")


# ============================= CLOUDFRONT PURGE, BACKUP/RESTORE, DELETE =============================
async def h_pm(u: Update, c: ContextTypes.DEFAULT_TYPE, p: Dict[str, Any]) -> None:
    uid, acc, did = u.effective_user.id, p["acc"], p["did"]
    await show_loading(u, "Inakagua Invalidations...")
    cf = await aws_client(uid, acc, "cloudfront")
    m_cnt, recent = await run(cf_month_invalidations, cf, did)
    lines = [
        f"• <code>{i['Id']}</code> · {i['Status']} ({i['CreateTime'].strftime('%d/%m %H:%M')})"
        for i in recent
    ]
    text = (
        f"🏠 <b>Home</b> › ☁️ <code>{did}</code> › 🧹 <b>Purge / Invalidation</b>\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        f"<blockquote>📊 <b>Mwezi huu:</b> <code>{m_cnt} / {FREE_TIER_INV}</code> (Free Tier)\n"
        + ("\n".join(lines) if lines else "<i>Hakuna invalidations za hivi karibuni.</i>")
        + "</blockquote>"
    )
    rows = [
        [
            B("🧹 Purge All (/*)", await cb_put(uid, "pg_all", acc=acc, did=did)),
            B("🎯 Custom Paths", await cb_put(uid, "pg_cus", acc=acc, did=did)),
        ],
        [B("⬅️ Back", await cb_put(uid, "d", acc=acc, did=did))],
    ]
    await show(u, text, rows)


async def h_pg_all(u: Update, c: ContextTypes.DEFAULT_TYPE, p: Dict[str, Any]) -> None:
    uid, acc, did = u.effective_user.id, p["acc"], p["did"]
    cf = await aws_client(uid, acc, "cloudfront")
    await run(
        cf.create_invalidation,
        DistributionId=did,
        InvalidationBatch={"Paths": {"Quantity": 1, "Items": ["/*"]}, "CallerReference": str(time.time())},
    )
    await show(
        u,
        f"✅ Purge ya <code>/*</code> imetumwa kwenye <code>{did}</code>.",
        [[B("⬅️ Back", await cb_put(uid, "pm", acc=acc, did=did))]],
    )


async def h_bm(u: Update, c: ContextTypes.DEFAULT_TYPE, p: Dict[str, Any]) -> None:
    uid, acc, did = u.effective_user.id, p["acc"], p["did"]
    bks = list_dist_backups(did)
    rows = [[B("📥 Download Current JSON", await cb_put(uid, "bk_dl", acc=acc, did=did))]]
    for fn in bks[:6]:
        ts_str = fn.replace(f"{did}-", "").replace(".json", "")
        try:
            dt = datetime.fromtimestamp(int(ts_str), tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        except ValueError:
            dt = ts_str
        rows.append([B(f"♻️ Restore: {dt}", await cb_put(uid, "bk_rst", acc=acc, did=did, fn=fn))])
    rows.append([B("⬅️ Back", await cb_put(uid, "d", acc=acc, did=did))])
    await show(
        u,
        f"🏠 <b>Home</b> › ☁️ <code>{did}</code> › 💾 <b>Backup & Restore</b>\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        f"Backups zilizohifadhiwa: <b>{len(bks)}</b> (Max {MAX_BACKUPS_PER_DIST}).\n"
        "Chagua backup ya kurudisha au pakua ya sasa:",
        rows,
    )


async def h_bk_dl(u: Update, c: ContextTypes.DEFAULT_TYPE, p: Dict[str, Any]) -> None:
    uid, acc, did = u.effective_user.id, p["acc"], p["did"]
    cf = await aws_client(uid, acc, "cloudfront")
    cfg = (await run(cf.get_distribution_config, Id=did))["DistributionConfig"]
    buf = io.BytesIO(json.dumps(cfg, indent=2, default=str).encode())
    buf.name = f"{did}-backup.json"
    await u.get_bot().send_document(
        chat_id=u.effective_chat.id,
        document=buf,
        caption=f"💾 CloudFront Config Backup: <code>{did}</code>",
        parse_mode="HTML",
    )


async def h_bk_rst(u: Update, c: ContextTypes.DEFAULT_TYPE, p: Dict[str, Any]) -> None:
    uid, acc, did, fn = u.effective_user.id, p["acc"], p["did"], p["fn"]
    await show(
        u,
        f"♻️ Una uhakika unataka kurudisha config kutoka <code>{esc(fn)}</code> kwenye <code>{did}</code>?",
        [
            [
                B("✅ Ndiyo, Restore", await cb_put(uid, "bk_rst_ok", acc=acc, did=did, fn=fn)),
                B("❌ Hapana", await cb_put(uid, "bm", acc=acc, did=did)),
            ]
        ],
    )


async def h_bk_rst_ok(u: Update, c: ContextTypes.DEFAULT_TYPE, p: Dict[str, Any]) -> None:
    uid, acc, did, fn = u.effective_user.id, p["acc"], p["did"], p["fn"]
    path = os.path.join(BACKUP_DIR, os.path.basename(fn))
    if not os.path.isfile(path):
        raise ValueError("Faili la backup halikupatikana.")
    with open(path) as f:
        saved_cfg = json.load(f)
    await show_loading(u, "Inarudisha backup AWS...")
    cf = await aws_client(uid, acc, "cloudfront")
    cur = await run(cf.get_distribution_config, Id=did)
    save_dist_backup(did, cur["DistributionConfig"])
    await run(cf.update_distribution, Id=did, IfMatch=cur["ETag"], DistributionConfig=saved_cfg)
    await db_add_watcher(uid, acc, "cf_deploy", did)
    await show_cf_detail(u, c, acc, did)


async def h_rm(u: Update, c: ContextTypes.DEFAULT_TYPE, p: Dict[str, Any]) -> None:
    uid, acc, did = u.effective_user.id, p["acc"], p["did"]
    await show(
        u,
        f"⚠️ <b>Futa Distribution <code>{did}</code>?</b>\n\n"
        "Ikiwa bado iko ON, itazimwa kwanza na utapata taarifa ikishakuwa <b>Deployed</b> ili ufute moja kwa moja.",
        [
            [
                B("🗑 Ndiyo, Endelea", await cb_put(uid, "rmok", acc=acc, did=did)),
                B("❌ Hapana", await cb_put(uid, "d", acc=acc, did=did)),
            ]
        ],
    )


async def h_rmok(u: Update, c: ContextTypes.DEFAULT_TYPE, p: Dict[str, Any]) -> None:
    uid, acc, did = u.effective_user.id, p["acc"], p["did"]
    await show_loading(u, "Inakagua hali ya distribution...")
    cf = await aws_client(uid, acc, "cloudfront")
    dist_r = await run(cf.get_distribution, Id=did)
    etag = dist_r["ETag"]
    dist = dist_r["Distribution"]
    status = dist["Status"]
    cfg = dist["DistributionConfig"]

    if cfg["Enabled"]:
        await run(cf_mutate, cf, did, lambda x: x.__setitem__("Enabled", False))
        await db_add_watcher(uid, acc, "cf_deploy", did)
        return await show(
            u,
            f"⏳ <code>{did}</code> imezimwa.\n"
            "Subiri notification ya <b>Deployed</b> (dakika 3–10), kisha bonyeza Delete tena.",
            [[B("⬅️ Back", await cb_put(uid, "d", acc=acc, did=did))]],
        )
    if status != "Deployed":
        await db_add_watcher(uid, acc, "cf_deploy", did)
        return await show(
            u,
            f"⏳ <code>{did}</code> bado ipo <b>{status}</b>.\n"
            "Bot itakujulisha mara tu itakapokuwa <b>Deployed</b> ili uweze kuifuta.",
            [[B("⬅️ Back", await cb_put(uid, "d", acc=acc, did=did))]],
        )
    await run(cf.delete_distribution, Id=did, IfMatch=etag)
    await show(u, f"✅ Distribution <code>{did}</code> imefutwa kabisa.", [[B("⬅️ List", await cb_put(uid, "dl", acc=acc, pg=0))]])


# ============================= CLOUDFRONT ANALYTICS & ACM =============================
async def h_us(u: Update, c: ContextTypes.DEFAULT_TYPE, p: Dict[str, Any]) -> None:
    uid, acc, did = u.effective_user.id, p["acc"], p["did"]
    await show_loading(u, "Inavuta takwimu kutoka CloudWatch...")
    cw = await aws_client(uid, acc, "cloudwatch", "us-east-1")
    m = await run(cw_cf_metrics, cw, did)
    pct = m["gb"] / FREE_TIER_GB * 100
    text = (
        f"🏠 <b>Home</b> › ☁️ <code>{did}</code> › 📊 <b>Analytics</b>\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        f"<blockquote>📦 <b>Bandwidth (Mwezi):</b> <code>{m['gb']:.2f} GB</code> ({pct:.1f}% ya 1TB)\n"
        f"{progress_bar(m['gb'], FREE_TIER_GB)}\n"
        f"📈 <b>Total Requests (Mwezi):</b> <code>{int(m['requests']):,}</code>\n"
        f"⚠️ <b>4xx Error Rate (24h):</b> <code>{m['err4xx']:.2f}%</code>\n"
        f"🔥 <b>5xx Error Rate (24h):</b> <code>{m['err5xx']:.2f}%</code></blockquote>"
    )
    await show(
        u,
        text,
        [
            [B("🔄 Refresh", await cb_put(uid, "us", acc=acc, did=did))],
            [B("⬅️ Back", await cb_put(uid, "d", acc=acc, did=did))],
        ],
    )


async def h_ua(u: Update, c: ContextTypes.DEFAULT_TYPE, p: Dict[str, Any]) -> None:
    uid, acc = u.effective_user.id, p["acc"]
    await show_loading(u, f"Inavuta matumizi ya {acc} kwa mkupuo...")
    cf = await aws_client(uid, acc, "cloudfront")
    cw = await aws_client(uid, acc, "cloudwatch", "us-east-1")
    ds = (await run(cf_all_dists, cf))[:30]

    # Parallel CloudWatch queries with asyncio.gather!
    gbs = await asyncio.gather(*(run(cw_cf_month_gb_only, cw, d["Id"]) for d in ds))
    tot = sum(gbs)
    paired = sorted(zip(ds, gbs), key=lambda x: x[1], reverse=True)
    lines = []
    for d, g in paired:
        al = (d.get("Aliases", {}).get("Items") or [d.get("Comment") or d["DomainName"]])[0]
        lines.append(f"• <code>{d['Id']}</code> {esc(al[:24])}: <b>{g:.2f} GB</b>")

    text = (
        f"🏠 <b>Home</b> › 👤 <b>{esc(acc)}</b> › 📊 <b>Monthly Usage</b>\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        f"<blockquote>{progress_bar(tot, FREE_TIER_GB)} <b>{tot:.1f} / {int(FREE_TIER_GB)} GB</b> "
        f"({tot / FREE_TIER_GB * 100:.1f}%)\n"
        f"Distributions: <b>{len(ds)}</b></blockquote>\n"
        + (f"<blockquote expandable>{chr(10).join(lines)}</blockquote>" if lines else "<i>Hakuna distributions.</i>")
    )
    await show(u, text, [[B("🔄 Refresh", await cb_put(uid, "ua", acc=acc))], HOME_BTN])


async def h_cd(u: Update, c: ContextTypes.DEFAULT_TYPE, p: Dict[str, Any]) -> None:
    uid, acc, did = u.effective_user.id, p["acc"], p["did"]
    await show_loading(u, "Inasoma vyeti vya ACM (us-east-1)...")
    acm = await aws_client(uid, acc, "acm", "us-east-1")
    issued_r, pend_r = await asyncio.gather(
        run(acm.list_certificates, CertificateStatuses=["ISSUED"]),
        run(acm.list_certificates, CertificateStatuses=["PENDING_VALIDATION"]),
    )
    certs = issued_r.get("CertificateSummaryList", [])[:10]
    pending = pend_r.get("CertificateSummaryList", [])[:5]

    rows = []
    for x in certs:
        tok = await cb_put(uid, "cc", acc=acc, did=did, arn=x["CertificateArn"])
        rows.append([B(f"🔐 {x['DomainName']}", tok)])
    for x in pending:
        tok = await cb_put(uid, "cp", acc=acc, did=did, arn=x["CertificateArn"])
        rows.append([B(f"⏳ Pending: {x['DomainName']}", tok)])

    rows += [
        [
            B("➕ Request Cert", await cb_put(uid, "cn", acc=acc, did=did)),
            B("❌ Remove Custom", await cb_put(uid, "cdr", acc=acc, did=did)),
        ],
        [B("⬅️ Back", await cb_put(uid, "d", acc=acc, did=did))],
    ]
    await show(
        u,
        f"🏠 <b>Home</b> › ☁️ <code>{did}</code> › 🌍 <b>Domains & SSL</b>\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        "Chagua cheti kilichothibitishwa (🔐) au kagua cheti kinachosubiri (⏳):",
        rows,
    )


async def h_cp(u: Update, c: ContextTypes.DEFAULT_TYPE, p: Dict[str, Any]) -> None:
    uid, acc, did, arn = u.effective_user.id, p["acc"], p["did"], p["arn"]
    acm = await aws_client(uid, acc, "acm", "us-east-1")
    cert = (await run(acm.describe_certificate, CertificateArn=arn))["Certificate"]
    dv = (cert.get("DomainValidationOptions") or [{}])[0]
    rec = dv.get("ResourceRecord")
    msg = f"⏳ <b>Cheti:</b> <code>{esc(cert.get('DomainName'))}</code>\nHali: <b>{cert.get('Status')}</b>\n\n"
    if rec:
        msg += (
            "Weka CNAME hii kwenye DNS (Cloudflare: <b>DNS only</b>):\n"
            f"<blockquote>Type: <code>{rec['Type']}</code>\n"
            f"Name: <code>{esc(rec['Name'])}</code>\n"
            f"Value: <code>{esc(rec['Value'])}</code></blockquote>"
        )
    await show(u, msg, [[B("⬅️ Back", await cb_put(uid, "cd", acc=acc, did=did))]])


async def h_cdr(u: Update, c: ContextTypes.DEFAULT_TYPE, p: Dict[str, Any]) -> None:
    def _fn(cfg):
        cfg["Aliases"] = {"Quantity": 0}
        cfg["ViewerCertificate"] = {"CloudFrontDefaultCertificate": True, "MinimumProtocolVersion": "TLSv1"}
    await cf_edit_and_watch(u, c, p["acc"], p["did"], _fn)


async def h_cr(u: Update, c: ContextTypes.DEFAULT_TYPE, p: Dict[str, Any]) -> None:
    c.user_data["flow"] = {"t": "c1", "acc": p["acc"]}
    await show(
        u,
        f"➕ <b>Create CloudFront · {esc(p['acc'])}</b>\n\n"
        "1/3 Tuma <b>Origin Domain</b> (mfano <code>ec2-1-2-3-4.compute-1.amazonaws.com</code>):",
        CANCEL_HOME,
    )


# ============================= EC2 REGIONS, SCAN & DETAIL =============================
async def _scan_ec2_all_regions(uid: int, acc: str) -> List[Tuple[str, Dict[str, Any]]]:
    async def _one(reg: str):
        try:
            cl = await aws_client(uid, acc, "ec2", reg)
            insts = await run(ec2_list_instances, cl)
            return [(reg, i) for i in insts]
        except Exception:
            return []

    results = await asyncio.gather(*(_one(r) for r, _ in POPULAR_REGIONS))
    flat: List[Tuple[str, Dict[str, Any]]] = []
    for chunk in results:
        flat.extend(chunk)
    return flat


async def h_ec2_regions(u: Update, c: ContextTypes.DEFAULT_TYPE, p: Dict[str, Any]) -> None:
    uid, acc = u.effective_user.id, p["acc"]
    accs = await db_get_accounts(uid)
    def_reg = accs[acc]["region"]
    rows = [[B("🔎 Scan All Active Regions", await cb_put(uid, "scan", acc=acc))]]
    pair = []
    for code, label in POPULAR_REGIONS:
        star = "⭐ " if code == def_reg else ""
        tok = await cb_put(uid, "e_list", acc=acc, reg=code)
        pair.append(B(f"{star}{code}", tok))
        if len(pair) == 2:
            rows.append(pair)
            pair = []
    if pair:
        rows.append(pair)
    rows.append(HOME_BTN)
    await show(
        u,
        f"🏠 <b>Home</b> › 👤 <b>{esc(acc)}</b> › 🖥 <b>EC2 Regions</b>\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        f"Chagua region (⭐ default: <code>{def_reg}</code>) au bonyeza <b>Scan All</b>:",
        rows,
    )


async def h_ec2_scan(u: Update, c: ContextTypes.DEFAULT_TYPE, p: Dict[str, Any]) -> None:
    uid, acc = u.effective_user.id, p["acc"]
    await show_loading(u, f"Ina-scan regions {len(POPULAR_REGIONS)} za {acc}...")
    found = await _scan_ec2_all_regions(uid, acc)
    rows = []
    for reg, inst in found:
        name = ec2_tag_name(inst)
        dot = ec2_state_emoji(inst["State"]["Name"])
        ip = inst.get("PublicIpAddress") or "no-ip"
        tok = await cb_put(uid, "e_det", acc=acc, reg=reg, iid=inst["InstanceId"])
        rows.append([B(f"{dot} {name} · {reg} · {ip}"[:56], tok)])
    rows += [
        [B("🌍 Chagua Region", await cb_put(uid, "ec2", acc=acc)), B("🔄 Rescan", await cb_put(uid, "scan", acc=acc))],
        HOME_BTN,
    ]
    await show(
        u,
        f"🏠 <b>Home</b> › 👤 <b>{esc(acc)}</b> › 🔎 <b>EC2 Scan</b>\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        f"Zilizopatikana: <b>{len(found)}</b> instances kwenye regions {len(POPULAR_REGIONS)}.",
        rows,
    )


async def h_e_list(u: Update, c: ContextTypes.DEFAULT_TYPE, p: Dict[str, Any]) -> None:
    uid, acc, reg = u.effective_user.id, p["acc"], p["reg"]
    await db_update_account_region(uid, acc, reg)
    await show_loading(u, f"Inapakia EC2 ({reg})...")
    cl = await aws_client(uid, acc, "ec2", reg)
    insts = await run(ec2_list_instances, cl)
    rows = []
    for inst in insts:
        name = ec2_tag_name(inst)
        dot = ec2_state_emoji(inst["State"]["Name"])
        itype = inst.get("InstanceType", "")
        tok = await cb_put(uid, "e_det", acc=acc, reg=reg, iid=inst["InstanceId"])
        rows.append([B(f"{dot} {name} ({itype})"[:56], tok)])
    rows += [
        [
            B("➕ Launch Template", await cb_put(uid, "e_lt", acc=acc, reg=reg)),
            B("🔄 Refresh", await cb_put(uid, "e_list", acc=acc, reg=reg)),
        ],
        [B("🌍 Regions", await cb_put(uid, "ec2", acc=acc)), B("🏠 Menu", "home")],
    ]
    await show(
        u,
        f"🏠 <b>Home</b> › 👤 <b>{esc(acc)}</b> › 🖥 <b>{reg}</b>\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        f"EC2 Instances: <b>{len(insts)}</b>",
        rows,
    )


async def show_ec2_detail(u: Update, c: ContextTypes.DEFAULT_TYPE, acc: str, reg: str, iid: str) -> None:
    uid = u.effective_user.id
    ec2_cl = await aws_client(uid, acc, "ec2", reg)
    cw_cl = await aws_client(uid, acc, "cloudwatch", reg)

    inst, metrics, eips_r = await asyncio.gather(
        run(ec2_get_instance, ec2_cl, iid),
        run(ec2_metrics, cw_cl, iid),
        run(ec2_cl.describe_addresses, Filters=[{"Name": "instance-id", "Values": [iid]}]),
    )
    sg_ids = [g["GroupId"] for g in inst.get("SecurityGroups", [])]
    sg_summary, _ = await run(ec2_describe_sg_ports, ec2_cl, sg_ids)

    name = ec2_tag_name(inst)
    state = inst["State"]["Name"]
    dot = ec2_state_emoji(state)
    pub_ip = inst.get("PublicIpAddress") or "—"
    pub_dns = inst.get("PublicDnsName") or "—"
    priv_ip = inst.get("PrivateIpAddress") or "—"
    eips = eips_r.get("Addresses", [])
    eip_txt = f"Attached ({eips[0]['PublicIp']})" if eips else "None"

    block = (
        f"🆔 <b>ID:</b> <code>{iid}</code>\n"
        f"🌐 <b>Public IP:</b> <code>{pub_ip}</code> · <b>EIP:</b> {eip_txt}\n"
        f"🔗 <b>Public DNS:</b> <code>{esc(pub_dns)}</code>\n"
        f"🏠 <b>Private IP:</b> <code>{priv_ip}</code>\n"
        f"📊 <b>CPU (1h):</b> <code>{metrics['cpu']:.1f}%</code> · <b>Net Out (24h):</b> <code>{metrics['net_out_gb']:.2f} GB</code>\n"
        f"🛡 <b>Ports:</b> <code>{esc(sg_summary[:90])}</code>"
    )
    text = (
        f"🏠 <b>Home</b> › 👤 <b>{esc(acc)}</b> › 🖥 <b>{reg}</b>\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        f"{dot} <b>{esc(name)}</b> (<code>{inst.get('InstanceType')}</code>) · <i>{state}</i>\n\n"
        f"<blockquote>{block}</blockquote>"
    )

    power_btn = (
        B("⏹ Stop", await cb_put(uid, "e_act", acc=acc, reg=reg, iid=iid, op="stop"))
        if state == "running"
        else B("▶️ Start", await cb_put(uid, "e_act", acc=acc, reg=reg, iid=iid, op="start"))
    )
    rows = [
        [power_btn, B("🔄 Reboot", await cb_put(uid, "e_act", acc=acc, reg=reg, iid=iid, op="reboot"))],
        [B("☁️ Set as CF Origin", await cb_put(uid, "e_cf", acc=acc, reg=reg, iid=iid))],
        [
            B("🛡 Firewall / SG", await cb_put(uid, "e_sg", acc=acc, reg=reg, iid=iid)),
            B("📊 Metrics", await cb_put(uid, "e_met", acc=acc, reg=reg, iid=iid)),
        ],
        [
            B("🌐 Elastic IP", await cb_put(uid, "e_eip", acc=acc, reg=reg, iid=iid)),
            B("📸 Snapshot", await cb_put(uid, "e_snap", acc=acc, reg=reg, iid=iid)),
        ],
        [
            B("💻 Run Command", await cb_put(uid, "e_ssm", acc=acc, reg=reg, iid=iid)),
            B("🗑 Terminate", await cb_put(uid, "e_term", acc=acc, reg=reg, iid=iid)),
        ],
        [
            B("🔄 Refresh", await cb_put(uid, "e_det", acc=acc, reg=reg, iid=iid)),
            B("⬅️ Back", await cb_put(uid, "e_list", acc=acc, reg=reg)),
        ],
    ]
    await show(u, text, rows)


async def h_e_det(u: Update, c: ContextTypes.DEFAULT_TYPE, p: Dict[str, Any]) -> None:
    await show_loading(u, f"Inapakia {p['iid']}...")
    await show_ec2_detail(u, c, p["acc"], p["reg"], p["iid"])


async def h_e_act(u: Update, c: ContextTypes.DEFAULT_TYPE, p: Dict[str, Any]) -> None:
    uid, acc, reg, iid, op = u.effective_user.id, p["acc"], p["reg"], p["iid"], p["op"]
    await show_loading(u, f"Inatekeleza {op.upper()} kwenye {iid}...")
    cl = await aws_client(uid, acc, "ec2", reg)
    if op == "start":
        await run(cl.start_instances, InstanceIds=[iid])
    elif op == "stop":
        await run(cl.stop_instances, InstanceIds=[iid])
    elif op == "reboot":
        await run(cl.reboot_instances, InstanceIds=[iid])
    await asyncio.sleep(2)
    await show_ec2_detail(u, c, acc, reg, iid)


async def h_e_term(u: Update, c: ContextTypes.DEFAULT_TYPE, p: Dict[str, Any]) -> None:
    uid, acc, reg, iid = u.effective_user.id, p["acc"], p["reg"], p["iid"]
    await show(
        u,
        f"🚨 <b>HATARI: Terminate EC2 <code>{iid}</code>?</b>\n\n"
        "Hatua hii itafuta server hii na disk yake <b>MOJA KWA MOJA</b>. Hutaweza kuirudisha!",
        [
            [
                B("🔥 Ndiyo, Endelea (1/2)", await cb_put(uid, "e_term2", acc=acc, reg=reg, iid=iid)),
                B("❌ Hapana", await cb_put(uid, "e_det", acc=acc, reg=reg, iid=iid)),
            ]
        ],
    )


async def h_e_term2(u: Update, c: ContextTypes.DEFAULT_TYPE, p: Dict[str, Any]) -> None:
    uid, acc, reg, iid = u.effective_user.id, p["acc"], p["reg"], p["iid"]
    await show(
        u,
        f"⚠️ <b>Uthibitisho wa Mwisho (2/2)</b>\nBonyeza hapa chini kufuta <code>{iid}</code> ({reg}) kabisa:",
        [
            [
                B("💀 TERMINATE SASA", await cb_put(uid, "e_term_ok", acc=acc, reg=reg, iid=iid)),
                B("❌ Ghairi", await cb_put(uid, "e_det", acc=acc, reg=reg, iid=iid)),
            ]
        ],
    )


async def h_e_term_ok(u: Update, c: ContextTypes.DEFAULT_TYPE, p: Dict[str, Any]) -> None:
    uid, acc, reg, iid = u.effective_user.id, p["acc"], p["reg"], p["iid"]
    cl = await aws_client(uid, acc, "ec2", reg)
    await run(cl.terminate_instances, InstanceIds=[iid])
    await show(u, f"🗑 Termination imeanzishwa kwa <code>{iid}</code>.", [[B("⬅️ EC2 List", await cb_put(uid, "e_list", acc=acc, reg=reg))]])


# ---------- EC2 -> CloudFront Killer Feature ----------
async def h_e_cf(u: Update, c: ContextTypes.DEFAULT_TYPE, p: Dict[str, Any]) -> None:
    uid, acc, reg, iid = u.effective_user.id, p["acc"], p["reg"], p["iid"]
    await show_loading(u, "Inapakia distributions za kuunganisha...")
    ec2_cl = await aws_client(uid, acc, "ec2", reg)
    cf_cl = await aws_client(uid, acc, "cloudfront")
    inst, ds = await asyncio.gather(run(ec2_get_instance, ec2_cl, iid), run(cf_all_dists, cf_cl))
    dns = inst.get("PublicDnsName")
    if not dns:
        return await show(
            u,
            "⚠️ EC2 hii haina Public DNS kwa sasa (hakikisha iko <b>Running</b>).",
            [[B("⬅️ Back", await cb_put(uid, "e_det", acc=acc, reg=reg, iid=iid))]],
        )
    rows = []
    for d in ds[:15]:
        al = (d.get("Aliases", {}).get("Items") or [d.get("Comment") or d["DomainName"]])[0]
        tok = await cb_put(uid, "e_cf_set", acc=acc, reg=reg, iid=iid, did=d["Id"], dns=dns)
        rows.append([B(f"☁️ {d['Id']} · {al}"[:55], tok)])
    rows.append([B("⬅️ Back", await cb_put(uid, "e_det", acc=acc, reg=reg, iid=iid))])
    await show(
        u,
        f"☁️ <b>Weka EC2 hii kuwa Origin ya CloudFront</b>\n\n"
        f"DNS: <code>{esc(dns)}</code>\nChagua Distribution ya kubadilisha Origin yake:",
        rows,
    )


async def h_e_cf_set(u: Update, c: ContextTypes.DEFAULT_TYPE, p: Dict[str, Any]) -> None:
    uid, acc, reg, iid, did, dns = u.effective_user.id, p["acc"], p["reg"], p["iid"], p["did"], p["dns"]
    await show_loading(u, f"Inaunganisha {did} → EC2...")
    cf = await aws_client(uid, acc, "cloudfront")
    await run(cf_mutate, cf, did, lambda cfg: cfg["Origins"]["Items"][0].__setitem__("DomainName", dns))
    await db_add_watcher(uid, acc, "cf_deploy", did)
    await show(
        u,
        f"✅ <b>Imefanikiwa!</b>\n\n"
        f"Origin ya <code>{did}</code> sasa ni:\n<code>{esc(dns)}</code>\n\n"
        "<i>Bot itakujulisha ikimaliza ku-deploy.</i>",
        [
            [B("☁️ Fungua CloudFront", await cb_put(uid, "d", acc=acc, did=did))],
            [B("⬅️ Rudi EC2", await cb_put(uid, "e_det", acc=acc, reg=reg, iid=iid))],
        ],
    )


# ---------- EC2 Firewall / Security Groups ----------
async def h_e_sg(u: Update, c: ContextTypes.DEFAULT_TYPE, p: Dict[str, Any]) -> None:
    uid, acc, reg, iid = u.effective_user.id, p["acc"], p["reg"], p["iid"]
    await show_loading(u, "Inasoma Security Groups...")
    cl = await aws_client(uid, acc, "ec2", reg)
    inst = await run(ec2_get_instance, cl, iid)
    sg_ids = [g["GroupId"] for g in inst.get("SecurityGroups", [])]
    _, sgs = await run(ec2_describe_sg_ports, cl, sg_ids)
    if not sgs:
        raise ValueError("EC2 hii haina Security Group iliyounganishwa.")
    sg = sgs[0]
    sgid = sg["GroupId"]

    lines = []
    rule_btns = []
    for idx, perm in enumerate(sg.get("IpPermissions", [])):
        proto = perm.get("IpProtocol")
        fp, tp = perm.get("FromPort"), perm.get("ToPort")
        p_str = "ALL" if proto == "-1" else (f"{fp}" if fp == tp else f"{fp}-{tp}")
        for r in perm.get("IpRanges", []):
            cidr = r.get("CidrIp")
            lines.append(f"• {proto.upper()} <code>{p_str}</code> ← <code>{cidr}</code>")
            tok = await cb_put(uid, "sg_rm", acc=acc, reg=reg, iid=iid, sg=sgid, pr=proto, fp=fp, tp=tp, cidr=cidr)
            rule_btns.append([B(f"🔒 Funga {p_str} ({cidr})", tok)])
        for pl in perm.get("PrefixListIds", []):
            plid = pl.get("PrefixListId")
            lines.append(f"• {proto.upper()} <code>{p_str}</code> ← <code>{plid}</code> (PrefixList)")
            tok = await cb_put(uid, "sg_rm", acc=acc, reg=reg, iid=iid, sg=sgid, pr=proto, fp=fp, tp=tp, pl=plid)
            rule_btns.append([B(f"🔒 Funga {p_str} ({plid})", tok)])

    text = (
        f"🏠 <b>Home</b> › 🖥 <code>{iid}</code> › 🛡 <b>Firewall ({sgid})</b>\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        f"<blockquote><b>Inbound Rules ({esc(sg['GroupName'])}):</b>\n"
        + ("\n".join(lines) if lines else "<i>Hakuna inbound rules.</i>")
        + "</blockquote>"
    )
    rows = [
        [
            B("🔓 Open Port (Public)", await cb_put(uid, "sg_add", acc=acc, reg=reg, iid=iid, sg=sgid, src="pub")),
            B("☁️ Open (CF Only)", await cb_put(uid, "sg_add", acc=acc, reg=reg, iid=iid, sg=sgid, src="cf")),
        ],
    ] + rule_btns[:8] + [[B("⬅️ Back", await cb_put(uid, "e_det", acc=acc, reg=reg, iid=iid))]]
    await show(u, text, rows)


async def h_sg_rm(u: Update, c: ContextTypes.DEFAULT_TYPE, p: Dict[str, Any]) -> None:
    uid, acc, reg, iid, sgid = u.effective_user.id, p["acc"], p["reg"], p["iid"], p["sg"]
    cl = await aws_client(uid, acc, "ec2", reg)
    perm: Dict[str, Any] = {"IpProtocol": p["pr"]}
    if p.get("fp") is not None:
        perm["FromPort"] = int(p["fp"])
    if p.get("tp") is not None:
        perm["ToPort"] = int(p["tp"])
    if p.get("cidr"):
        perm["IpRanges"] = [{"CidrIp": p["cidr"]}]
    if p.get("pl"):
        perm["PrefixListIds"] = [{"PrefixListId": p["pl"]}]
    await run(cl.revoke_security_group_ingress, GroupId=sgid, IpPermissions=[perm])
    await h_e_sg(u, c, {"acc": acc, "reg": reg, "iid": iid})


# ---------- EC2 Metrics, Elastic IP, Snapshot, Launch Template, SSM ----------
async def h_e_met(u: Update, c: ContextTypes.DEFAULT_TYPE, p: Dict[str, Any]) -> None:
    uid, acc, reg, iid = u.effective_user.id, p["acc"], p["reg"], p["iid"]
    await show_loading(u, "Inavuta EC2 metrics...")
    cw = await aws_client(uid, acc, "cloudwatch", reg)
    m = await run(ec2_metrics, cw, iid)
    text = (
        f"🏠 <b>Home</b> › 🖥 <code>{iid}</code> › 📊 <b>Metrics</b>\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        f"<blockquote>🔥 <b>CPU (Last 1h):</b> <code>{m['cpu']:.1f}%</code>\n"
        f"{progress_bar(m['cpu'], 100.0)}\n"
        f"📤 <b>Network Out (24h):</b> <code>{m['net_out_gb']:.3f} GB</code>\n"
        f"📥 <b>Network In (24h):</b> <code>{m['net_in_gb']:.3f} GB</code></blockquote>"
    )
    await show(
        u,
        text,
        [
            [B("🔄 Refresh", await cb_put(uid, "e_met", acc=acc, reg=reg, iid=iid))],
            [B("⬅️ Back", await cb_put(uid, "e_det", acc=acc, reg=reg, iid=iid))],
        ],
    )


async def h_e_eip(u: Update, c: ContextTypes.DEFAULT_TYPE, p: Dict[str, Any]) -> None:
    uid, acc, reg, iid = u.effective_user.id, p["acc"], p["reg"], p["iid"]
    cl = await aws_client(uid, acc, "ec2", reg)
    eips = (await run(cl.describe_addresses, Filters=[{"Name": "instance-id", "Values": [iid]}])).get("Addresses", [])
    rows = []
    if eips:
        e = eips[0]
        info = f"🟢 <b>Attached EIP:</b> <code>{e['PublicIp']}</code>\nAllocation: <code>{e['AllocationId']}</code>"
        rows.append([B("🔌 Disassociate & Release EIP", await cb_put(uid, "eip_rel", acc=acc, reg=reg, iid=iid, aid=e["AllocationId"], asid=e.get("AssociationId", "")))])
    else:
        info = "⚪ Hakuna Elastic IP iliyounganishwa na EC2 hii.\n<i>Kumbuka: AWS hutoza $0.005/saa kwa Public IPv4.</i>"
        rows.append([B("➕ Allocate & Attach Elastic IP", await cb_put(uid, "eip_add", acc=acc, reg=reg, iid=iid))])
    rows.append([B("⬅️ Back", await cb_put(uid, "e_det", acc=acc, reg=reg, iid=iid))])
    await show(u, f"🌐 <b>Elastic IP · <code>{iid}</code></b>\n\n<blockquote>{info}</blockquote>", rows)


async def h_eip_add(u: Update, c: ContextTypes.DEFAULT_TYPE, p: Dict[str, Any]) -> None:
    uid, acc, reg, iid = u.effective_user.id, p["acc"], p["reg"], p["iid"]
    await show_loading(u, "Inatengeneza na kuunganisha Elastic IP...")
    cl = await aws_client(uid, acc, "ec2", reg)
    alloc = await run(cl.allocate_address, Domain="vpc")
    await run(cl.associate_address, InstanceId=iid, AllocationId=alloc["AllocationId"])
    await h_e_eip(u, c, p)


async def h_eip_rel(u: Update, c: ContextTypes.DEFAULT_TYPE, p: Dict[str, Any]) -> None:
    uid, acc, reg, iid = u.effective_user.id, p["acc"], p["reg"], p["iid"]
    await show_loading(u, "Inaondoa Elastic IP...")
    cl = await aws_client(uid, acc, "ec2", reg)
    if p.get("asid"):
        await run(cl.disassociate_address, AssociationId=p["asid"])
    await run(cl.release_address, AllocationId=p["aid"])
    await h_e_eip(u, c, p)


async def h_e_snap(u: Update, c: ContextTypes.DEFAULT_TYPE, p: Dict[str, Any]) -> None:
    uid, acc, reg, iid = u.effective_user.id, p["acc"], p["reg"], p["iid"]
    await show_loading(u, "Inasoma volumes & snapshots...")
    cl = await aws_client(uid, acc, "ec2", reg)
    inst = await run(ec2_get_instance, cl, iid)
    vols = [b["Ebs"]["VolumeId"] for b in inst.get("BlockDeviceMappings", []) if b.get("Ebs")]
    snaps = []
    if vols:
        r = await run(cl.describe_snapshots, Filters=[{"Name": "volume-id", "Values": vols}], OwnerIds=["self"])
        snaps = sorted(r.get("Snapshots", []), key=lambda x: x["StartTime"], reverse=True)[:5]

    lines = [
        f"• <code>{s['SnapshotId']}</code> · {s['State']} ({s['Progress']}) · {s['StartTime'].strftime('%d/%m %H:%M')}"
        for s in snaps
    ]
    rows = [
        [B(f"📸 Create Snapshot ({v})", await cb_put(uid, "snap_mk", acc=acc, reg=reg, iid=iid, vid=v))]
        for v in vols
    ]
    rows.append([B("⬅️ Back", await cb_put(uid, "e_det", acc=acc, reg=reg, iid=iid))])
    await show(
        u,
        f"📸 <b>EBS Snapshots · <code>{iid}</code></b>\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        f"<blockquote><b>Volumes:</b> <code>{', '.join(vols) or 'Hakuna'}</code>\n"
        + ("\n".join(lines) if lines else "<i>Hakuna snapshots za hivi karibuni.</i>")
        + "</blockquote>",
        rows,
    )


async def h_snap_mk(u: Update, c: ContextTypes.DEFAULT_TYPE, p: Dict[str, Any]) -> None:
    uid, acc, reg, iid, vid = u.effective_user.id, p["acc"], p["reg"], p["iid"], p["vid"]
    await show_loading(u, f"Inaunda snapshot ya {vid}...")
    cl = await aws_client(uid, acc, "ec2", reg)
    desc = f"Bot backup of {iid} ({datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')})"
    await run(cl.create_snapshot, VolumeId=vid, Description=desc)
    await h_e_snap(u, c, p)


async def h_e_lt(u: Update, c: ContextTypes.DEFAULT_TYPE, p: Dict[str, Any]) -> None:
    uid, acc, reg = u.effective_user.id, p["acc"], p["reg"]
    await show_loading(u, f"Inatafuta Launch Templates ({reg})...")
    cl = await aws_client(uid, acc, "ec2", reg)
    lts = (await run(cl.describe_launch_templates)).get("LaunchTemplates", [])
    rows = []
    for lt in lts[:10]:
        tok = await cb_put(uid, "e_lt_go", acc=acc, reg=reg, ltid=lt["LaunchTemplateId"], ltn=lt["LaunchTemplateName"])
        rows.append([B(f"🚀 {lt['LaunchTemplateName']}", tok)])
    rows.append([B("⬅️ Back", await cb_put(uid, "e_list", acc=acc, reg=reg))])
    await show(
        u,
        f"➕ <b>Launch EC2 via Template ({reg})</b>\n\n"
        + ("Chagua Launch Template ya kuwasha server mpya:" if lts else "<i>Hakuna Launch Templates kwenye region hii. Unda moja kwenye AWS Console kwanza.</i>"),
        rows,
    )


async def h_e_lt_go(u: Update, c: ContextTypes.DEFAULT_TYPE, p: Dict[str, Any]) -> None:
    uid, acc, reg, ltid, ltn = u.effective_user.id, p["acc"], p["reg"], p["ltid"], p["ltn"]
    await show(
        u,
        f"🚀 Washa EC2 mpya kutoka Launch Template <b>{esc(ltn)}</b> ({reg})?",
        [
            [
                B("✅ Ndiyo, Launch", await cb_put(uid, "e_lt_ok", acc=acc, reg=reg, ltid=ltid)),
                B("❌ Hapana", await cb_put(uid, "e_lt", acc=acc, reg=reg)),
            ]
        ],
    )


async def h_e_lt_ok(u: Update, c: ContextTypes.DEFAULT_TYPE, p: Dict[str, Any]) -> None:
    uid, acc, reg, ltid = u.effective_user.id, p["acc"], p["reg"], p["ltid"]
    await show_loading(u, "Inawasha EC2 mpya...")
    cl = await aws_client(uid, acc, "ec2", reg)
    r = await run(cl.run_instances, LaunchTemplate={"LaunchTemplateId": ltid}, MinCount=1, MaxCount=1)
    iid = r["Instances"][0]["InstanceId"]
    await asyncio.sleep(2)
    await show_ec2_detail(u, c, acc, reg, iid)


async def h_e_ssm(u: Update, c: ContextTypes.DEFAULT_TYPE, p: Dict[str, Any]) -> None:
    uid, acc, reg, iid = u.effective_user.id, p["acc"], p["reg"], p["iid"]
    rows = []
    pair = []
    for k, (lbl, _) in SSM_PRESETS.items():
        tok = await cb_put(uid, "ssm_go", acc=acc, reg=reg, iid=iid, pk=k)
        pair.append(B(lbl, tok))
        if len(pair) == 2:
            rows.append(pair)
            pair = []
    if pair:
        rows.append(pair)
    rows += [
        [B("⌨️ Custom Bash Command", await cb_put(uid, "ssm_cus", acc=acc, reg=reg, iid=iid))],
        [B("⬅️ Back", await cb_put(uid, "e_det", acc=acc, reg=reg, iid=iid))],
    ]
    await show(
        u,
        f"💻 <b>Run Command (AWS SSM) · <code>{iid}</code></b>\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        "<i>Inahitaji SSM Agent na IAM Role ya SSM kwenye EC2.</i>\nChagua amri:",
        rows,
    )


async def _exec_ssm(u: Update, acc: str, reg: str, iid: str, cmd_str: str) -> None:
    uid = u.effective_user.id
    await show_loading(u, f"Inaendesha: {cmd_str[:40]}...")
    ssm = await aws_client(uid, acc, "ssm", reg)
    r = await run(
        ssm.send_command,
        InstanceIds=[iid],
        DocumentName="AWS-RunShellScript",
        Parameters={"commands": [cmd_str]},
    )
    cid = r["Command"]["CommandId"]
    out, err, st = "", "", "InProgress"
    for _ in range(10):
        await asyncio.sleep(2)
        try:
            inv = await run(ssm.get_command_invocation, CommandId=cid, InstanceId=iid)
            st = inv.get("Status", "InProgress")
            if st in ("Success", "Failed", "Cancelled", "TimedOut"):
                out = inv.get("StandardOutputContent") or ""
                err = inv.get("StandardErrorContent") or ""
                break
        except ClientError:
            pass

    body = (out or err or "(Hakuna output)").strip()[:3000]
    dot = "✅" if st == "Success" else "⚠️"
    await show(
        u,
        f"{dot} <b>SSM Result ({st})</b>\n"
        f"<code>$ {esc(cmd_str)}</code>\n\n"
        f"<blockquote expandable><code>{esc(body)}</code></blockquote>",
        [[B("⬅️ Run Command", await cb_put(uid, "e_ssm", acc=acc, reg=reg, iid=iid))]],
    )


async def h_ssm_go(u: Update, c: ContextTypes.DEFAULT_TYPE, p: Dict[str, Any]) -> None:
    _, cmd_str = SSM_PRESETS[p["pk"]]
    await _exec_ssm(u, p["acc"], p["reg"], p["iid"], cmd_str)


# ============================= TEXT FLOWS =============================
async def start_flow(u: Update, c: ContextTypes.DEFAULT_TYPE, flow_data: Dict[str, Any], prompt: str, back_cb: str) -> None:
    c.user_data["flow"] = flow_data
    await show(u, prompt, [[B("✖️ Ghairi", back_cb)]])


async def on_text(u: Update, c: ContextTypes.DEFAULT_TYPE) -> None:
    uid = u.effective_user.id
    if uid not in ADMINS:
        return
    f = c.user_data.get("flow")
    txt = (u.message.text or "").strip() if u.message else ""
    if not f:
        return await h_home(u, c, {})
    t = f["t"]
    try:
        # ---- Account Add ----
        if t == "aname":
            accs = await db_get_accounts(uid)
            if not re.fullmatch(r"\w{1,15}", txt) or txt in accs:
                return await show(u, "❌ Jina si sahihi au lipo tayari. Jaribu jingine:", CANCEL_HOME)
            c.user_data["flow"] = {"t": "aak", "name": txt}
            await show(u, "🔑 Tuma <b>AWS Access Key ID</b> (ujumbe utafutwa mara moja):", CANCEL_HOME)
        elif t == "aak":
            await safe_delete_msg(u)
            c.user_data["flow"] = {"t": "ask", "name": f["name"], "ak": txt}
            await show(u, "🔑 Tuma <b>AWS Secret Access Key</b> (ujumbe utafutwa mara moja):", CANCEL_HOME, force_new=True)
        elif t == "ask":
            await safe_delete_msg(u)
            sts = boto3.client("sts", aws_access_key_id=f["ak"], aws_secret_access_key=txt, region_name="us-east-1")
            me = await run(sts.get_caller_identity)
            await db_save_account(uid, f["name"], f["ak"], txt)
            c.user_data.pop("flow", None)
            await show(
                u,
                f"✅ Account <b>{esc(f['name'])}</b> imeunganishwa!\nAWS ID: <code>{me['Account']}</code>",
                [
                    [B("☁️ CloudFront", await cb_put(uid, "dl", acc=f["name"], pg=0)), B("🖥 EC2", await cb_put(uid, "ec2", acc=f["name"]))],
                    HOME_BTN,
                ],
                force_new=True,
            )

        # ---- Bot Alert Thresholds ----
        elif t in ("set_cfp", "set_cpup"):
            if not txt.isdigit() or not 10 <= int(txt) <= 100:
                return await show(u, "❌ Weka namba kati ya 10 na 100:", CANCEL_HOME)
            c.user_data.pop("flow", None)
            if t == "set_cfp":
                await db_update_settings(uid, alert_cf_pct=int(txt))
            else:
                await db_update_settings(uid, alert_cpu_pct=int(txt))
            await h_bset(u, c, {})

        # ---- CloudFront Origin Edits ----
        elif t == "origin":
            dom = clean_domain(txt)
            if not dom:
                return await show(u, "❌ Domain si sahihi. Jaribu tena:", CANCEL_HOME)
            c.user_data.pop("flow", None)
            oi = f["oi"]
            await cf_edit_and_watch(u, c, f["acc"], f["did"], lambda cfg: cfg["Origins"]["Items"][oi].__setitem__("DomainName", dom), return_to="om", oi=oi)
        elif t in ("pt_http", "pt_https"):
            if not txt.isdigit() or not 1 <= int(txt) <= 65535:
                return await show(u, "❌ Port si sahihi (1–65535). Jaribu tena:", CANCEL_HOME)
            c.user_data.pop("flow", None)
            oi = f["oi"]
            key = "HTTPPort" if t == "pt_http" else "HTTPSPort"
            def _set_port(cfg):
                co = cfg["Origins"]["Items"][oi].get("CustomOriginConfig")
                if not co:
                    raise ValueError("Origin hii si Custom Origin.")
                co[key] = int(txt)
            await cf_edit_and_watch(u, c, f["acc"], f["did"], _set_port, return_to="om", oi=oi)
        elif t == "to_ed":
            if not txt.isdigit() or not 1 <= int(txt) <= 60:
                return await show(u, "❌ Timeout lazima iwe kati ya sekunde 1 na 60:", CANCEL_HOME)
            c.user_data.pop("flow", None)
            oi = f["oi"]
            def _set_to(cfg):
                co = cfg["Origins"]["Items"][oi].get("CustomOriginConfig")
                if not co:
                    raise ValueError("Origin hii si Custom Origin.")
                co["OriginReadTimeout"] = int(txt)
            await cf_edit_and_watch(u, c, f["acc"], f["did"], _set_to, return_to="om", oi=oi)
        elif t == "ch_ed":
            if ":" not in txt:
                return await show(u, "❌ Tumia muundo <code>Header-Name: Value</code>. Mfano: <code>X-Origin-Secret: siri123</code>", CANCEL_HOME)
            k, v = [x.strip() for x in txt.split(":", 1)]
            if not k or not v:
                return await show(u, "❌ Header na thamani haziwezi kuwa tupu:", CANCEL_HOME)
            c.user_data.pop("flow", None)
            oi = f["oi"]
            def _set_hdr(cfg):
                ch = cfg["Origins"]["Items"][oi].setdefault("CustomHeaders", {"Quantity": 0, "Items": []})
                items = [x for x in ch.get("Items", []) if x["HeaderName"].lower() != k.lower()]
                items.append({"HeaderName": k, "HeaderValue": v})
                cfg["Origins"]["Items"][oi]["CustomHeaders"] = {"Quantity": len(items), "Items": items}
            await cf_edit_and_watch(u, c, f["acc"], f["did"], _set_hdr, return_to="om", oi=oi)

        # ---- CloudFront Settings Flows ----
        elif t == "s_lbl":
            c.user_data.pop("flow", None)
            await cf_edit_and_watch(u, c, f["acc"], f["did"], lambda cfg: cfg.__setitem__("Comment", txt[:128]), return_to="sm")
        elif t == "s_geo":
            codes = [x.strip().upper() for x in re.split(r"[,\s]+", txt) if x.strip()]
            if not codes or any(not re.fullmatch(r"[A-Z]{2}", x) for x in codes):
                return await show(u, "❌ Tumia misimbo ya nchi ya herufi 2 (ISO), mfano: <code>TZ, KE, UG</code>", CANCEL_HOME)
            c.user_data.pop("flow", None)
            mode = f["mode"]
            def _geo(cfg):
                cfg["Restrictions"] = {
                    "GeoRestriction": {"RestrictionType": mode, "Quantity": len(codes), "Items": codes}
                }
            await cf_edit_and_watch(u, c, f["acc"], f["did"], _geo, return_to="sm")
        elif t == "pg_cus":
            paths = [x.strip() for x in re.split(r"[,\s]+", txt) if x.strip()]
            if not paths:
                return await show(u, "❌ Tuma angalau path moja (mfano <code>/index.html, /assets/*</code>):", CANCEL_HOME)
            paths = [p if p.startswith("/") else "/" + p for p in paths]
            c.user_data.pop("flow", None)
            cf = await aws_client(uid, f["acc"], "cloudfront")
            await run(
                cf.create_invalidation,
                DistributionId=f["did"],
                InvalidationBatch={"Paths": {"Quantity": len(paths), "Items": paths}, "CallerReference": str(time.time())},
            )
            await show(u, f"✅ Purge imetumwa kwa paths: <code>{esc(', '.join(paths))}</code>", [[B("⬅️ Back", await cb_put(uid, "pm", acc=f["acc"], did=f["did"]))]])

        # ---- CloudFront Custom Domain & ACM ----
        elif t == "alias":
            doms = [clean_domain(x) for x in re.split(r"[,\s]+", txt) if x.strip()]
            if not doms or None in doms:
                return await show(u, "❌ Domain si sahihi. Jaribu tena:", CANCEL_HOME)
            c.user_data.pop("flow", None)
            arn = f["arn"]
            def _al(cfg):
                cfg["Aliases"] = {"Quantity": len(doms), "Items": doms}
                cfg["ViewerCertificate"] = {
                    "ACMCertificateArn": arn,
                    "SSLSupportMethod": "sni-only",
                    "MinimumProtocolVersion": "TLSv1.2_2021",
                }
            await cf_edit_and_watch(u, c, f["acc"], f["did"], _al)
        elif t == "cert":
            c.user_data.pop("flow", None)
            acm = await aws_client(uid, f["acc"], "acm", "us-east-1")
            arn = (await run(acm.request_certificate, DomainName=txt.lower(), ValidationMethod="DNS"))["CertificateArn"]
            await db_add_watcher(uid, f["acc"], "acm_cert", arn, {"domain": txt.lower(), "did": f["did"]})
            rec = None
            for _ in range(6):
                await asyncio.sleep(2)
                dv = (await run(acm.describe_certificate, CertificateArn=arn))["Certificate"].get("DomainValidationOptions", [{}])[0]
                rec = dv.get("ResourceRecord")
                if rec:
                    break
            msg = "✅ <b>Cheti kimeombwa!</b>\n\nWeka CNAME hii kwenye DNS (Cloudflare: <b>DNS only</b>):\n"
            if rec:
                msg += (
                    f"<blockquote>Type: <code>{rec['Type']}</code>\n"
                    f"Name: <code>{esc(rec['Name'])}</code>\n"
                    f"Value: <code>{esc(rec['Value'])}</code></blockquote>\n"
                )
            else:
                msg += "<i>Record bado inatengenezwa, fungua Domains & SSL → Pending baada ya sekunde chache.</i>\n"
            msg += "🔔 Bot inakifuatilia na itakutumia ujumbe mara kitakapokuwa <b>ISSUED</b>."
            await show(u, msg, [[B("🌍 Domains & SSL", await cb_put(uid, "cd", acc=f["acc"], did=f["did"]))]])

        # ---- Create CloudFront ----
        elif t == "c1":
            dom = clean_domain(txt)
            if not dom:
                return await show(u, "❌ Domain si sahihi. Jaribu tena:", CANCEL_HOME)
            f.update(t="c2", origin=dom)
            await show(u, "2/3 Tuma <b>Port</b> ya origin (mfano <code>80</code> au <code>8080</code>):", CANCEL_HOME)
        elif t == "c2":
            if not txt.isdigit() or not 1 <= int(txt) <= 65535:
                return await show(u, "❌ Port si sahihi (1–65535):", CANCEL_HOME)
            f.update(t="c3", port=int(txt))
            await show(u, "3/3 Tuma <b>Jina / Label</b> ya distribution:", CANCEL_HOME)
        elif t == "c3":
            c.user_data.pop("flow", None)
            cf = await aws_client(uid, f["acc"], "cloudfront")
            r = await run(cf.create_distribution, DistributionConfig=cf_build_cfg(f["origin"], f["port"], txt))
            did = r["Distribution"]["Id"]
            await db_add_watcher(uid, f["acc"], "cf_deploy", did)
            await show_cf_detail(u, c, f["acc"], did, with_metrics=False)

        # ---- EC2 Security Group Add Port ----
        elif t == "sg_add":
            if not txt.isdigit() or not 1 <= int(txt) <= 65535:
                return await show(u, "❌ Tuma namba ya port sahihi (1–65535):", CANCEL_HOME)
            port = int(txt)
            c.user_data.pop("flow", None)
            cl = await aws_client(uid, f["acc"], "ec2", f["reg"])
            perm: Dict[str, Any] = {"IpProtocol": "tcp", "FromPort": port, "ToPort": port}
            if f["src"] == "cf":
                pl_id = await run(ec2_get_cf_prefix_list_id, cl)
                if not pl_id:
                    raise ValueError("CloudFront Managed Prefix List haikupatikana kwenye region hii.")
                perm["PrefixListIds"] = [{"PrefixListId": pl_id, "Description": "CloudFront Only (Bot)"}]
            else:
                perm["IpRanges"] = [{"CidrIp": "0.0.0.0/0", "Description": "Public (Bot)"}]
            await run(cl.authorize_security_group_ingress, GroupId=f["sg"], IpPermissions=[perm])
            await h_e_sg(u, c, {"acc": f["acc"], "reg": f["reg"], "iid": f["iid"]})

        # ---- EC2 Custom SSM Command ----
        elif t == "ssm_cus":
            c.user_data.pop("flow", None)
            await _exec_ssm(u, f["acc"], f["reg"], f["iid"], txt)

    except Exception as e:
        await fail(u, e)


# ============================= BACKGROUND JOBS (WATCHERS & ALERTS) =============================
async def job_watchers(ctx: ContextTypes.DEFAULT_TYPE) -> None:
    """Checks pending CloudFront deployments & ACM certs every 30s and notifies user."""
    watchers = await db_list_watchers()
    now = int(time.time())
    for w in watchers:
        wid, uid, acc, kind, tid = w["id"], w["uid"], w["acc"], w["kind"], w["target_id"]
        # Drop stale watchers older than 24h
        if now - w["created_at"] > 86400:
            await db_remove_watcher(wid)
            continue
        try:
            if kind == "cf_deploy":
                cf = await aws_client(uid, acc, "cloudfront")
                dist = (await run(cf.get_distribution, Id=tid))["Distribution"]
                if dist["Status"] == "Deployed":
                    state = "ON" if dist["DistributionConfig"]["Enabled"] else "OFF"
                    await ctx.bot.send_message(
                        chat_id=uid,
                        text=(
                            f"✅ <b>CloudFront Deployed!</b>\n\n"
                            f"<blockquote>👤 Account: <code>{esc(acc)}</code>\n"
                            f"🆔 ID: <code>{tid}</code>\n"
                            f"📦 Hali: <b>Deployed ({state})</b></blockquote>"
                        ),
                        parse_mode="HTML",
                    )
                    await db_remove_watcher(wid)
            elif kind == "acm_cert":
                acm = await aws_client(uid, acc, "acm", "us-east-1")
                cert = (await run(acm.describe_certificate, CertificateArn=tid))["Certificate"]
                st = cert.get("Status")
                if st == "ISSUED":
                    await ctx.bot.send_message(
                        chat_id=uid,
                        text=(
                            f"🔐 <b>ACM SSL Certificate ISSUED!</b>\n\n"
                            f"<blockquote>👤 Account: <code>{esc(acc)}</code>\n"
                            f"🌍 Domain: <code>{esc(cert.get('DomainName'))}</code>\n"
                            "Sasa unaweza kuiunganisha kwenye CloudFront → Domains & SSL.</blockquote>"
                        ),
                        parse_mode="HTML",
                    )
                    await db_remove_watcher(wid)
                elif st in ("FAILED", "EXPIRED", "VALIDATION_TIMED_OUT", "REVOKED"):
                    await ctx.bot.send_message(
                        chat_id=uid,
                        text=f"❌ Cheti cha ACM <code>{esc(cert.get('DomainName'))}</code> kimeshindwa ({st}).",
                        parse_mode="HTML",
                    )
                    await db_remove_watcher(wid)
        except Exception as e:
            log.warning("Watcher %s error: %s", wid, e)


async def job_health_alerts(ctx: ContextTypes.DEFAULT_TYPE) -> None:
    """Periodic check for CloudFront Free Tier threshold & high EC2 CPU."""
    all_accs = await db_get_all_accounts()
    ym = datetime.now(timezone.utc).strftime("%Y-%m")
    for row in all_accs:
        uid, acc, def_reg = row["uid"], row["name"], row["default_region"] or "us-east-1"
        st = await db_get_settings(uid)
        if not st["alerts_on"]:
            continue
        try:
            # 1) CloudFront Free Tier Usage Check
            cf = await aws_client(uid, acc, "cloudfront")
            cw = await aws_client(uid, acc, "cloudwatch", "us-east-1")
            ds = (await run(cf_all_dists, cf))[:25]
            gbs = await asyncio.gather(*(run(cw_cf_month_gb_only, cw, d["Id"]) for d in ds))
            tot_gb = sum(gbs)
            pct = tot_gb / FREE_TIER_GB * 100
            if pct >= st["alert_cf_pct"]:
                akey = f"cf:{uid}:{acc}:{ym}:{st['alert_cf_pct']}"
                if not await db_alert_recently_sent(akey, cooldown_sec=7 * 86400):
                    await ctx.bot.send_message(
                        chat_id=uid,
                        text=(
                            f"🚨 <b>CloudFront Free Tier Alert ({esc(acc)})</b>\n\n"
                            f"<blockquote>{progress_bar(tot_gb, FREE_TIER_GB)} "
                            f"<b>{tot_gb:.1f} / {int(FREE_TIER_GB)} GB ({pct:.0f}%)</b>\n"
                            f"Umevuka kiwango chako cha tahadhari cha {st['alert_cf_pct']}%.</blockquote>"
                        ),
                        parse_mode="HTML",
                    )

            # 2) EC2 High CPU Check (Default Region)
            ec2_cl = await aws_client(uid, acc, "ec2", def_reg)
            cw_ec2 = await aws_client(uid, acc, "cloudwatch", def_reg)
            insts = await run(ec2_list_instances, ec2_cl)
            for inst in insts:
                if inst["State"]["Name"] != "running":
                    continue
                iid = inst["InstanceId"]
                m = await run(ec2_metrics, cw_ec2, iid)
                if m["cpu"] >= st["alert_cpu_pct"]:
                    akey = f"cpu:{uid}:{acc}:{iid}"
                    if not await db_alert_recently_sent(akey, cooldown_sec=3600):
                        await ctx.bot.send_message(
                            chat_id=uid,
                            text=(
                                f"🔥 <b>EC2 High CPU Alert ({esc(acc)} · {def_reg})</b>\n\n"
                                f"<blockquote>🖥 Server: <b>{esc(ec2_tag_name(inst))}</b> (<code>{iid}</code>)\n"
                                f"⚡ CPU: <b>{m['cpu']:.1f}%</b> (Limit: {st['alert_cpu_pct']}%)</blockquote>"
                            ),
                            parse_mode="HTML",
                        )
        except Exception as e:
            log.warning("Health alert error for %s/%s: %s", uid, acc, e)


# ============================= ROUTER & ERROR HANDLER =============================
async def fail(u: Update, e: Exception) -> None:
    if isinstance(e, ClientError):
        m = f"{e.response['Error']['Code']}: {e.response['Error']['Message']}"
    elif isinstance(e, BotoCoreError):
        m = str(e)
    else:
        m = str(e) or type(e).__name__
    log.exception("Handler error")
    await show(u, f"❌ <b>Hitilafu</b>\n<blockquote><code>{esc(m)[:900]}</code></blockquote>", [HOME_BTN])


TOKEN_HANDLERS: Dict[str, Callable] = {
    "ai": h_ai,
    "ad": h_ad,
    "adok": h_adok,
    "dl": h_dl,
    "d": h_d,
    "tg": h_tg,
    "om": h_om,
    "pp": h_pp,
    "ch_cl": h_ch_cl,
    "or_ec2": h_or_ec2,
    "or_ec2_set": h_or_ec2_set,
    "sm": h_sm,
    "s_cache": h_s_cache,
    "s_vproto": h_s_vproto,
    "s_http": h_s_http,
    "s_comp": h_s_comp,
    "s_ipv6": h_s_ipv6,
    "s_pc": h_s_pc,
    "s_geo": h_s_geo,
    "s_geo_none": h_s_geo_none,
    "s_waf": h_s_waf,
    "s_waf_set": h_s_waf_set,
    "pm": h_pm,
    "pg_all": h_pg_all,
    "bm": h_bm,
    "bk_dl": h_bk_dl,
    "bk_rst": h_bk_rst,
    "bk_rst_ok": h_bk_rst_ok,
    "rm": h_rm,
    "rmok": h_rmok,
    "us": h_us,
    "ua": h_ua,
    "cd": h_cd,
    "cp": h_cp,
    "cdr": h_cdr,
    "cr": h_cr,
    "ec2": h_ec2_regions,
    "scan": h_ec2_scan,
    "e_list": h_e_list,
    "e_det": h_e_det,
    "e_act": h_e_act,
    "e_term": h_e_term,
    "e_term2": h_e_term2,
    "e_term_ok": h_e_term_ok,
    "e_cf": h_e_cf,
    "e_cf_set": h_e_cf_set,
    "e_sg": h_e_sg,
    "sg_rm": h_sg_rm,
    "e_met": h_e_met,
    "e_eip": h_e_eip,
    "eip_add": h_eip_add,
    "eip_rel": h_eip_rel,
    "e_snap": h_e_snap,
    "snap_mk": h_snap_mk,
    "e_lt": h_e_lt,
    "e_lt_go": h_e_lt_go,
    "e_lt_ok": h_e_lt_ok,
    "e_ssm": h_e_ssm,
    "ssm_go": h_ssm_go,
}


async def on_cb(u: Update, c: ContextTypes.DEFAULT_TYPE) -> None:
    q = u.callback_query
    await q.answer()
    uid = u.effective_user.id
    if uid not in ADMINS:
        return
    c.user_data.pop("flow", None)
    data = q.data or ""
    try:
        # Static short callbacks
        if data == "home":
            return await h_home(u, c, {})
        if data == "help":
            return await h_help(u, c, {})
        if data == "acc":
            return await h_acc(u, c, {})
        if data == "aa":
            return await h_aa(u, c, {})
        if data == "bset":
            return await h_bset(u, c, {})
        if data == "tgl_al":
            return await h_tgl_al(u, c, {})
        if data == "tgl_al_s":
            st = await db_get_settings(uid)
            await db_update_settings(uid, alerts_on=0 if st["alerts_on"] else 1)
            return await h_bset(u, c, {})
        if data == "set_cfp":
            return await start_flow(u, c, {"t": "set_cfp"}, "📊 Tuma asilimia ya tahadhari ya CloudFront (mfano <code>80</code>):", "bset")
        if data == "set_cpup":
            return await start_flow(u, c, {"t": "set_cpup"}, "🔥 Tuma asilimia ya tahadhari ya EC2 CPU (mfano <code>90</code>):", "bset")
        if data.startswith("pk|"):
            return await h_pk(u, c, {"purpose": data.split("|", 1)[1]})

        # Tokenized callbacks (safe against 64-byte limit & restarts)
        if data.startswith("t|"):
            payload = await cb_get(uid, data.split("|", 1)[1])
            if not payload:
                return await show(u, "⌛ Kitufe hiki kimeisha muda. Rudi Menu Kuu:", [HOME_BTN])
            act = payload["a"]

            # Flow-initiating tokenized actions
            if act == "or_ed":
                back = await cb_put(uid, "om", acc=payload["acc"], did=payload["did"], oi=payload["oi"])
                return await start_flow(u, c, {"t": "origin", **payload}, "🎯 Tuma <b>Origin Domain</b> mpya:", back)
            if act == "pt_http":
                back = await cb_put(uid, "om", acc=payload["acc"], did=payload["did"], oi=payload["oi"])
                return await start_flow(u, c, {"t": "pt_http", **payload}, "🔌 Tuma <b>HTTP Port</b> mpya (mfano <code>80</code> au <code>8080</code>):", back)
            if act == "pt_https":
                back = await cb_put(uid, "om", acc=payload["acc"], did=payload["did"], oi=payload["oi"])
                return await start_flow(u, c, {"t": "pt_https", **payload}, "🔒 Tuma <b>HTTPS Port</b> mpya (mfano <code>443</code> au <code>8443</code>):", back)
            if act == "to_ed":
                back = await cb_put(uid, "om", acc=payload["acc"], did=payload["did"], oi=payload["oi"])
                return await start_flow(u, c, {"t": "to_ed", **payload}, "⏱ Tuma <b>Origin Read Timeout</b> kwa sekunde (1–60):", back)
            if act == "ch_ed":
                back = await cb_put(uid, "om", acc=payload["acc"], did=payload["did"], oi=payload["oi"])
                return await start_flow(u, c, {"t": "ch_ed", **payload}, "🛡 Tuma Custom Header kwa muundo <code>Header-Name: Value</code>:", back)
            if act == "s_lbl":
                back = await cb_put(uid, "sm", acc=payload["acc"], did=payload["did"])
                return await start_flow(u, c, {"t": "s_lbl", **payload}, "📝 Tuma <b>Label / Comment</b> mpya:", back)
            if act == "s_geo_ask":
                back = await cb_put(uid, "s_geo", acc=payload["acc"], did=payload["did"])
                return await start_flow(u, c, {"t": "s_geo", **payload}, f"🌍 Tuma misimbo ya nchi ({payload['mode']}), mfano: <code>TZ, KE, UG</code>:", back)
            if act == "pg_cus":
                back = await cb_put(uid, "pm", acc=payload["acc"], did=payload["did"])
                return await start_flow(u, c, {"t": "pg_cus", **payload}, "🎯 Tuma paths za ku-purge (tenganisha kwa koma), mfano: <code>/index.html, /assets/*</code>:", back)
            if act == "cc":
                back = await cb_put(uid, "cd", acc=payload["acc"], did=payload["did"])
                return await start_flow(u, c, {"t": "alias", **payload}, "🌍 Tuma custom domain(s) (tenganisha kwa koma), mfano: <code>cdn.domain.com</code>:", back)
            if act == "cn":
                back = await cb_put(uid, "cd", acc=payload["acc"], did=payload["did"])
                return await start_flow(u, c, {"t": "cert", **payload}, "➕ Tuma domain ya cheti cha ACM (mfano <code>cdn.domain.com</code> au <code>*.domain.com</code>):", back)
            if act == "sg_add":
                back = await cb_put(uid, "e_sg", acc=payload["acc"], reg=payload["reg"], iid=payload["iid"])
                lbl = "CloudFront Only (Prefix List)" if payload["src"] == "cf" else "Public (0.0.0.0/0)"
                return await start_flow(u, c, {"t": "sg_add", **payload}, f"🔓 Fungua TCP Port ({lbl}).\nTuma namba ya port (mfano <code>80</code>, <code>443</code>, <code>8080</code>):", back)
            if act == "ssm_cus":
                back = await cb_put(uid, "e_ssm", acc=payload["acc"], reg=payload["reg"], iid=payload["iid"])
                return await start_flow(u, c, {"t": "ssm_cus", **payload}, "⌨️ Tuma Bash command ya kuendesha kwenye EC2:", back)

            handler = TOKEN_HANDLERS.get(act)
            if handler:
                return await handler(u, c, payload)

        await h_home(u, c, {})
    except Exception as e:
        await fail(u, e)


async def cmd_start(u: Update, c: ContextTypes.DEFAULT_TYPE) -> None:
    if u.effective_user.id not in ADMINS:
        return
    c.user_data.pop("flow", None)
    try:
        await h_home(u, c, {})
    except Exception as e:
        await fail(u, e)


async def post_init(app: Application) -> None:
    await app.bot.set_my_commands(
        [
            BotCommand("start", "Fungua AWS Control Panel"),
            BotCommand("menu", "Rudi Menu Kuu"),
            BotCommand("cancel", "Ghairi hatua ya sasa"),
        ]
    )


def main() -> None:
    init_db()
    app = Application.builder().token(TOKEN).post_init(post_init).build()
    app.add_handler(CommandHandler(["start", "menu", "cancel"], cmd_start))
    app.add_handler(CallbackQueryHandler(on_cb))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, on_text))

    # Background jobs (Watchers every 30s, Health & Free Tier alerts every 30m)
    if app.job_queue:
        app.job_queue.run_repeating(job_watchers, interval=30, first=15)
        app.job_queue.run_repeating(job_health_alerts, interval=1800, first=120)
    else:
        log.warning("JobQueue haipo! Weka: pip install 'python-telegram-bot[job-queue]'")

    log.info("AWS Control Bot imeanza kufanya kazi...")
    app.run_polling(drop_pending_updates=True)


if __name__ == "__main__":
    main()