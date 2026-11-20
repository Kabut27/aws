"""Free-tier guard + fixes for bot.py (hupakiwa na run.py; bot.py haiguswi).

Inaongeza:
  * Claim code (/start <code>) + owners.json  (inaendana na install.sh)
  * Ukaguzi wa free tier: CloudFront GB + Requests, EC2 hours (regions zote),
    Network Out, EBS GB, EIP zisizotumika, aina ya instance isiyo-free
  * Auto-disable CloudFront ikikaribia limit (FT_AUTO_DISABLE_CF=1)
  * Kuzuia kuwasha/launch EC2 ambazo si free-tier type
  * Scan EC2 kwenye regions ZOTE zilizo wazi (si 10 tu)
  * Amri /freetier
"""
import asyncio, hmac, json, logging, os
from datetime import datetime, timedelta, timezone

from telegram.ext import CommandHandler

import bot

log = logging.getLogger("freetier")


def _f(name, default):
    return float(os.environ.get(name, default))


CF_GB = _f("FT_CF_GB", 1024)
CF_REQ = _f("FT_CF_REQ", 10_000_000)
EC2_HOURS = _f("FT_EC2_HOURS", 750)
EC2_NET_GB = _f("FT_EC2_NET_GB", 100)
EBS_GB = _f("FT_EBS_GB", 30)
GUARD_PCT = _f("FT_GUARD_PCT", 95)
AUTO_DISABLE_CF = os.environ.get("FT_AUTO_DISABLE_CF", "1") == "1"
AUTO_STOP_EC2 = os.environ.get("FT_AUTO_STOP_EC2", "0") == "1"
ALLOWED_TYPES = {x.strip() for x in os.environ.get("FT_EC2_TYPES", "t2.micro,t3.micro").split(",") if x.strip()}
CLAIM_CODE = os.environ.get("CLAIM_CODE", "")
OWNERS_FILE = os.path.join(os.environ.get("DATA_DIR", "data"), "owners.json")
MONTH = 32 * 86400


# ---------------- owners / claim ----------------
def owners():
    try:
        with open(OWNERS_FILE) as f:
            return {int(x) for x in json.load(f)}
    except (FileNotFoundError, ValueError):
        return set()


def add_owner(uid):
    with open(OWNERS_FILE, "w") as f:
        json.dump(sorted(owners() | {uid}), f)
    os.chmod(OWNERS_FILE, 0o600)


class _Admins(set):
    def __contains__(self, x):
        return set.__contains__(self, x) or x in owners()


async def claim(u, c):
    """/start <code>: wa kwanza kuitumia anakuwa mmiliki (kama hakuna mmiliki bado)."""
    if not (CLAIM_CODE and c.args and u.effective_user):
        return
    if owners() or u.effective_user.id in bot.ADMINS:
        return
    if hmac.compare_digest(c.args[0], CLAIM_CODE):
        add_owner(u.effective_user.id)
        try:
            await u.message.delete()  # ficha code
        except Exception:
            pass
        await c.bot.send_message(u.effective_chat.id, "✅ Wewe sasa ni mmiliki wa bot.")


# ---------------- sync AWS helpers (run in threads) ----------------
def _month():
    now = datetime.now(timezone.utc)
    return now, now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)


def cf_usage(cw, ids):
    now, start = _month()
    gb = req = 0.0
    for did in ids:
        dims = [{"Name": "DistributionId", "Value": did}, {"Name": "Region", "Value": "Global"}]
        for metric in ("BytesDownloaded", "Requests"):
            r = cw.get_metric_statistics(
                Namespace="AWS/CloudFront", MetricName=metric, Dimensions=dims,
                StartTime=start, EndTime=now, Period=86400, Statistics=["Sum"])
            s = sum(p["Sum"] for p in r.get("Datapoints", []))
            if metric == "Requests":
                req += s
            else:
                gb += s / 1024 ** 3
    return gb, req


def ec2_region_scan(ec2, cw):
    now, start = _month()
    out = {"hours": 0.0, "net_gb": 0.0, "running": [], "bad": [], "idle_eip": [], "ebs_gb": 0}
    for inst in bot.ec2_list_instances(ec2):
        iid, st, typ = inst["InstanceId"], inst["State"]["Name"], inst.get("InstanceType", "?")
        dims = [{"Name": "InstanceId", "Value": iid}]
        if st in ("running", "stopped", "stopping", "pending"):
            r = cw.get_metric_statistics(
                Namespace="AWS/EC2", MetricName="CPUUtilization", Dimensions=dims,
                StartTime=start, EndTime=now, Period=3600, Statistics=["SampleCount"])
            out["hours"] += len(r.get("Datapoints", []))
            r = cw.get_metric_statistics(
                Namespace="AWS/EC2", MetricName="NetworkOut", Dimensions=dims,
                StartTime=start, EndTime=now, Period=86400, Statistics=["Sum"])
            out["net_gb"] += sum(p["Sum"] for p in r.get("Datapoints", [])) / 1024 ** 3
        if st == "running":
            item = (iid, typ, bot.ec2_tag_name(inst))
            out["running"].append(item)
            if typ not in ALLOWED_TYPES:
                out["bad"].append(item)
    for a in ec2.describe_addresses().get("Addresses", []):
        if not a.get("AssociationId"):
            out["idle_eip"].append(a.get("PublicIp", "?"))
    for pg in ec2.get_paginator("describe_volumes").paginate():
        out["ebs_gb"] += sum(v.get("Size", 0) for v in pg.get("Volumes", []))
    return out


# ---------------- async collection ----------------
async def regions_of(uid, acc):
    try:
        cl = await bot.aws_client(uid, acc, "ec2", "us-east-1")
        r = await bot.run(cl.describe_regions)
        return [x["RegionName"] for x in r["Regions"]]
    except Exception:
        return [r for r, _ in bot.POPULAR_REGIONS]


async def scan_all(uid, acc):
    async def one(reg):
        try:
            cl = await bot.aws_client(uid, acc, "ec2", reg)
            return [(reg, i) for i in await bot.run(bot.ec2_list_instances, cl)]
        except Exception:
            return []
    res = await asyncio.gather(*(one(r) for r in await regions_of(uid, acc)))
    return [x for chunk in res for x in chunk]


async def collect(uid, acc):
    cf = await bot.aws_client(uid, acc, "cloudfront")
    cw = await bot.aws_client(uid, acc, "cloudwatch", "us-east-1")
    ds = await bot.run(bot.cf_all_dists, cf)
    gb, req = await bot.run(cf_usage, cw, [d["Id"] for d in ds])

    async def one(reg):
        try:
            e = await bot.aws_client(uid, acc, "ec2", reg)
            w = await bot.aws_client(uid, acc, "cloudwatch", reg)
            return reg, await bot.run(ec2_region_scan, e, w)
        except Exception as ex:
            log.warning("scan %s/%s/%s: %s", uid, acc, reg, ex)
            return reg, None

    res = await asyncio.gather(*(one(r) for r in await regions_of(uid, acc)))
    regs = [x for x in res if x[1]]
    now, start = _month()
    nxt = (start + timedelta(days=32)).replace(day=1)
    remaining = (nxt - now).total_seconds() / 3600
    s = {"ds": ds, "gb": gb, "req": req, "hours": 0.0, "net": 0.0, "ebs": 0,
         "running": [], "bad": [], "idle": []}
    for reg, r in regs:
        s["hours"] += r["hours"]; s["net"] += r["net_gb"]; s["ebs"] += r["ebs_gb"]
        s["running"] += [(reg,) + x for x in r["running"]]
        s["bad"] += [(reg,) + x for x in r["bad"]]
        s["idle"] += [(reg, ip) for ip in r["idle_eip"]]
    s["proj"] = s["hours"] + len(s["running"]) * remaining
    return s


def pct(v, lim):
    return v / lim * 100 if lim else 0


def fmt_report(acc, s):
    pb = bot.progress_bar
    lines = [
        f"👤 <b>{bot.esc(acc)}</b>",
        f"☁️ CF Data: {pb(s['gb'], CF_GB)} <b>{s['gb']:.1f}/{CF_GB:.0f} GB</b> ({pct(s['gb'], CF_GB):.0f}%)",
        f"☁️ CF Requests: {pb(s['req'], CF_REQ)} <b>{s['req']:,.0f}/{CF_REQ:,.0f}</b> ({pct(s['req'], CF_REQ):.0f}%)",
        f"🖥 EC2 Hours: {pb(s['hours'], EC2_HOURS)} <b>{s['hours']:.0f}/{EC2_HOURS:.0f}</b> · makadirio mwisho wa mwezi: <b>{s['proj']:.0f}</b>",
        f"📤 EC2 Net Out: <b>{s['net']:.1f}/{EC2_NET_GB:.0f} GB</b> · 💽 EBS: <b>{s['ebs']}/{EBS_GB:.0f} GB</b>",
        f"▶️ Running: <b>{len(s['running'])}</b>",
    ]
    if s["bad"]:
        lines.append("⚠️ Si free-type: " + bot.esc(", ".join(f"{b[3]}({b[2]})" for b in s["bad"])))
    if s["idle"]:
        lines.append("⚠️ EIP zisizotumika (zinatozwa): " + bot.esc(", ".join(i[1] for i in s["idle"])))
    return "\n".join(lines)


# ---------------- guard job ----------------
async def _alert(ctx, uid, key, text):
    if not await bot.db_alert_recently_sent(key, MONTH if ":m:" in key else 86400):
        await ctx.bot.send_message(uid, text, parse_mode="HTML")


async def guard_account(ctx, uid, acc, notify):
    s = await collect(uid, acc)
    ym = datetime.now(timezone.utc).strftime("%Y-%m")
    st = await bot.db_get_settings(uid)
    warn = st["alert_cf_pct"]
    k = f"ft:{uid}:{acc}"
    rep = fmt_report(acc, s)

    # 1) CloudFront: auto-disable karibu na limit
    worst = max(pct(s["gb"], CF_GB), pct(s["req"], CF_REQ))
    if AUTO_DISABLE_CF and worst >= GUARD_PCT:
        cf = await bot.aws_client(uid, acc, "cloudfront")
        done = []
        for d in s["ds"]:
            if d.get("Enabled"):
                try:
                    await bot.run(bot.cf_mutate, cf, d["Id"], lambda cfg: cfg.__setitem__("Enabled", False))
                    await bot.db_add_watcher(uid, acc, "cf_deploy", d["Id"])
                    done.append(d["Id"])
                except Exception as e:
                    log.warning("auto-disable %s: %s", d["Id"], e)
        if done:
            await ctx.bot.send_message(
                uid, f"🛑 <b>Free-tier guard:</b> CloudFront imefikia {worst:.0f}%. "
                     f"Nimezima: <code>{bot.esc(', '.join(done))}</code>\nWasha tena mwezi ujao.\n\n{rep}",
                parse_mode="HTML")
    elif notify and pct(s["req"], CF_REQ) >= warn:
        await _alert(ctx, uid, f"{k}:m:req:{ym}:{warn}", f"🚨 <b>CF Requests ≥ {warn}%</b>\n\n{rep}")

    if not notify:
        return
    # 2) EC2 hours
    if s["hours"] >= EC2_HOURS * 0.9 or s["proj"] > EC2_HOURS:
        await _alert(ctx, uid, f"{k}:m:hrs:{ym}:{len(s['running'])}",
                     f"⏱ <b>EC2 hours zinakaribia/zitazidi limit</b>\n\n{rep}")
    if s["hours"] >= EC2_HOURS and AUTO_STOP_EC2:
        await stop_running(ctx, uid, acc, s["running"], "EC2 hours zimeisha")
    # 3) instance isiyo-free
    if s["bad"]:
        await _alert(ctx, uid, f"{k}:bad:{','.join(b[2] for b in s['bad'])}", f"⚠️ <b>Instance si free-tier type</b>\n\n{rep}")
        if AUTO_STOP_EC2:
            await stop_running(ctx, uid, acc, s["bad"], "si free-tier type")
    # 4) network, EBS, EIP
    if s["net"] >= EC2_NET_GB * 0.8:
        await _alert(ctx, uid, f"{k}:m:net:{ym}", f"📤 <b>EC2 Net Out ≥ 80%</b>\n\n{rep}")
    if s["ebs"] > EBS_GB:
        await _alert(ctx, uid, f"{k}:ebs:{s['ebs']}", f"💽 <b>EBS imezidi {EBS_GB:.0f} GB</b>\n\n{rep}")
    if s["idle"]:
        await _alert(ctx, uid, f"{k}:eip:{len(s['idle'])}", f"💸 <b>Elastic IP isiyotumika (inatozwa)</b>\n\n{rep}")


async def stop_running(ctx, uid, acc, items, why):
    for reg, iid, typ, name in items:
        try:
            cl = await bot.aws_client(uid, acc, "ec2", reg)
            await bot.run(cl.stop_instances, InstanceIds=[iid])
            await ctx.bot.send_message(uid, f"🛑 Nimezima <code>{iid}</code> ({bot.esc(name)}) — {bot.esc(why)}.", parse_mode="HTML")
        except Exception as e:
            log.warning("stop %s: %s", iid, e)


async def job_guard(ctx):
    for row in await bot.db_get_all_accounts():
        uid, acc = row["uid"], row["name"]
        try:
            st = await bot.db_get_settings(uid)
            await guard_account(ctx, uid, acc, bool(st["alerts_on"]))
        except Exception as e:
            log.warning("guard %s/%s: %s", uid, acc, e)


async def cmd_freetier(u, c):
    uid = u.effective_user.id
    if uid not in bot.ADMINS:
        return
    m = await u.message.reply_text("⏳ Inakagua free tier (regions zote)...")
    parts = []
    for acc in await bot.db_get_accounts(uid):
        try:
            parts.append(fmt_report(acc, await collect(uid, acc)))
        except Exception as e:
            parts.append(f"❌ {bot.esc(acc)}: {bot.esc(str(e)[:200])}")
    await m.edit_text(("\n\n".join(parts) or "Hakuna account.")[:4000], parse_mode="HTML")


# ---------------- launch/start guards ----------------
def install_guards():
    orig_lt, orig_act = bot.TOKEN_HANDLERS["e_lt_ok"], bot.TOKEN_HANDLERS["e_act"]
    deny = lambda typ: (f"⛔ <b>Imezuiwa:</b> aina <code>{bot.esc(typ or 'haijatajwa')}</code> si free-tier.\n"
                        f"Zinazoruhusiwa: <code>{bot.esc(', '.join(sorted(ALLOWED_TYPES)))}</code>\n"
                        "<i>(badilisha kwa FT_EC2_TYPES kwenye .env)</i>")

    async def lt_ok(u, c, p):
        cl = await bot.aws_client(u.effective_user.id, p["acc"], "ec2", p["reg"])
        r = await bot.run(cl.describe_launch_template_versions, LaunchTemplateId=p["ltid"], Versions=["$Default"])
        typ = r["LaunchTemplateVersions"][0]["LaunchTemplateData"].get("InstanceType")
        if typ not in ALLOWED_TYPES:
            return await bot.show(u, deny(typ), [bot.HOME_BTN])
        return await orig_lt(u, c, p)

    async def act(u, c, p):
        if p.get("op") == "start":
            cl = await bot.aws_client(u.effective_user.id, p["acc"], "ec2", p["reg"])
            typ = (await bot.run(bot.ec2_get_instance, cl, p["iid"])).get("InstanceType")
            if typ not in ALLOWED_TYPES:
                return await bot.show(u, deny(typ), [bot.HOME_BTN])
        return await orig_act(u, c, p)

    bot.TOKEN_HANDLERS["e_lt_ok"] = lt_ok
    bot.TOKEN_HANDLERS["e_act"] = act


def setup(app):
    bot.ADMINS = _Admins(bot.ADMINS)
    bot._scan_ec2_all_regions = scan_all
    install_guards()
    app.add_handler(CommandHandler("start", claim), group=-1)
    app.add_handler(CommandHandler("freetier", cmd_freetier))
    if app.job_queue:
        app.job_queue.run_repeating(job_guard, interval=900, first=90)
