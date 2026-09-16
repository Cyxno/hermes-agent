#!/usr/bin/env python3
"""Cost-first homelab monitor: deterministic collection, optional compact LLM triage."""
import argparse, datetime as dt, hashlib, json, os, re, sqlite3, subprocess, sys, urllib.error, urllib.parse, urllib.request, uuid
from pathlib import Path

HOME = Path(os.environ.get("HERMES_HOME", "/opt/data"))
ROOT = HOME / "homelab"
DB = ROOT / "monitor.db"
COST_LOG = ROOT / "cost-calls.jsonl"
SNAPSHOT = os.environ.get("HOMELAB_SNAPSHOT_URL", "http://192.168.1.2:8090/api/snapshot")
PROM = os.environ.get("PROMETHEUS_URL", "http://192.168.1.2:9090")
ARRSIGHT_PASSWORD_FILE = Path(os.environ.get("ARRSIGHT_PASSWORD_FILE", str(HOME / "secrets" / "arrsight-admin-password.txt")))
MODELS = {
    "ling": "inclusionai/ling-3.0-flash",
    "deepseek": "deepseek/deepseek-v4-flash-0731",
    "glm": "z-ai/glm-5.3-flash",
    "luna": "openai/gpt-5.6-luna",
}
MODEL_ROUTES = {
    "ling": [MODELS["ling"], MODELS["deepseek"], MODELS["glm"]],
}
PRICES = {
    MODELS["ling"]: (0.021, 0.063),
    MODELS["deepseek"]: (0.065, 0.18),
    MODELS["glm"]: (0.075, 0.25),
    MODELS["luna"]: (0.20, 1.20),
}
CRITICAL = {"InfiniDysk", "binhex-sonarr", "binhex-radarr", "binhex-plexpass", "binhex-sabnzbd", "prometheus"}

def load_env_file():
    path = HOME / ".env"
    if not path.exists(): return
    for raw in path.read_text(encoding="utf-8").splitlines():
        if not raw or raw.lstrip().startswith("#") or "=" not in raw: continue
        key, value = raw.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip())

load_env_file()

def now(): return dt.datetime.now(dt.timezone.utc).isoformat()
def fetch_json(url, timeout=12, cookie=None):
    headers = {"Cookie": cookie} if cookie else {}
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.load(r)


def arrsight_cookie():
    """ArrSight beschermt /api/snapshot met een admin-sessie; log in en geef de cookie terug."""
    try:
        password = ARRSIGHT_PASSWORD_FILE.read_text(encoding="utf-8").strip()
    except OSError:
        return None
    if not password:
        return None
    parts = urllib.parse.urlsplit(SNAPSHOT)
    base = f"{parts.scheme}://{parts.netloc}"
    body = json.dumps({"password": password}).encode("utf-8")
    # ArrSight weigert de login zonder Origin-header die matcht met de Host.
    req = urllib.request.Request(f"{base}/api/auth/login", data=body,
                                 headers={"Content-Type": "application/json", "Origin": base})
    try:
        with urllib.request.urlopen(req, timeout=12) as r:
            set_cookie = r.headers.get("Set-Cookie", "")
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"ArrSight login HTTP {exc.code}") from exc
    cookie = set_cookie.split(";", 1)[0].strip()
    if not cookie.startswith("arrsight_session="):
        raise RuntimeError("ArrSight login gaf geen sessie-cookie terug")
    return cookie

def db():
    ROOT.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(DB)
    c.executescript("""
      create table if not exists cursors(service text primary key,last_successful_check text,last_log_timestamp text,last_event_id text,last_daily_audit text,last_incident text,last_pattern_seen text);
      create table if not exists events(id integer primary key, ts text, service text, fingerprint text, severity text, summary text, unique(fingerprint,ts));
      create table if not exists adaptive_monitors(id integer primary key,hypothesis text,reason text,created_at text,expires_at text,measurement_plan text,result text,conclusion text,status text default 'active');
      create table if not exists runs(run_id text primary key,ts text,job text,status text,llm_calls int default 0,estimated_cost real default 0,detail text);
    """)
    return c

def prometheus(query):
    u = PROM + "/api/v1/query?" + urllib.parse.urlencode({"query": query})
    data = fetch_json(u)
    vals = data.get("data", {}).get("result", [])
    return [float(x["value"][1]) for x in vals if x.get("value")]

def collect():
    issues=[]; compact={"at":now(),"containers":{},"services":{},"mounts":{}}
    try:
        s=fetch_json(SNAPSHOT, cookie=arrsight_cookie())
        for x in s.get("containers",[]):
            if x.get("name") in CRITICAL:
                ok=bool(x.get("ok")) and x.get("status")=="running" and x.get("health") not in ("unhealthy","starting")
                compact["containers"][x["name"]]={"ok":ok,"status":x.get("status"),"health":x.get("health")}
                if not ok: issues.append({"service":x["name"],"severity":"incident","event":"container_not_healthy"})
        for name,x in s.get("health",{}).items():
            compact["services"][name]={"ok":bool(x.get("ok")),"status":x.get("status")}
            if not x.get("ok"): issues.append({"service":name,"severity":"warning","event":"api_health_failed"})
        compact["mounts"]={k:bool(v) for k,v in s.get("mounts",{}).items()}
        if compact["mounts"].get("nzbdav") is False:
            issues.append({"service":"InfiniDysk","severity":"warning","event":"nzbdav_mount_missing"})
    except Exception as e:
        issues.append({"service":"dashboard","severity":"incident","event":"snapshot_unreachable","error":type(e).__name__})
    queries={
      "memory_used_pct":"100*(1-(node_memory_MemAvailable_bytes/node_memory_MemTotal_bytes))",
      "root_free_pct":"100*node_filesystem_avail_bytes{mountpoint=\"/\"}/node_filesystem_size_bytes{mountpoint=\"/\"}",
    }
    compact["metrics"]={}
    for name,q in queries.items():
        try:
            v=prometheus(q); compact["metrics"][name]=round(max(v),2) if v else None
        except Exception: compact["metrics"][name]=None
    if (compact["metrics"].get("memory_used_pct") or 0)>92: issues.append({"service":"host","severity":"warning","event":"memory_above_92pct"})
    if compact["metrics"].get("root_free_pct") is not None and compact["metrics"]["root_free_pct"]<10: issues.append({"service":"host","severity":"incident","event":"disk_below_10pct"})
    return compact,issues

def collect_incremental_logs(c):
    """Fetch bounded recent logs and return deduplicated fingerprints, never raw history."""
    row=c.execute("select last_daily_audit from cursors where service='__daily__'").fetchone()
    since="24h"
    if row and row[0]:
        try:
            age=max(1,int((dt.datetime.now(dt.timezone.utc)-dt.datetime.fromisoformat(row[0])).total_seconds()))
            since=f"{min(age,86400)}s"
        except Exception: pass
    patt=re.compile(r"\b(error|err|warn|warning|critical|fatal|failed|failure|exception|traceback|timeout|unhealthy|oom|out of memory|connection refused|permission denied|panic|i/o error)\b",re.I)
    grouped={}
    for service in sorted(CRITICAL):
        cmd=["ssh","-i",str(HOME/"home/.ssh/agent-read"),"-o","BatchMode=yes","root@192.168.1.2","docker-logs",service,since,"500"]
        try: text=subprocess.run(cmd,capture_output=True,text=True,timeout=20).stdout[:50000]
        except Exception: continue
        for line in text.splitlines():
            if not patt.search(line): continue
            normalized=re.sub(r"[0-9a-f]{8}-[0-9a-f-]{20,}","<id>",line.lower())
            normalized=re.sub(r"\b\d{2,}\b","<n>",normalized)
            fp=hashlib.sha256((service+normalized).encode()).hexdigest()[:16]
            item=grouped.setdefault(fp,{"service":service,"severity":"warning","event":"log_pattern","count":0,"examples":[]})
            item["count"]+=1
            if len(item["examples"])<3: item["examples"].append(line[-240:])
    stamp=now()
    c.execute("insert into cursors(service,last_daily_audit,last_successful_check) values('__daily__',?,?) on conflict(service) do update set last_daily_audit=excluded.last_daily_audit,last_successful_check=excluded.last_successful_check",(stamp,stamp))
    c.commit()
    return list(grouped.values())[:50]

def call_model(tier, messages, job, run_id, max_tokens=450):
    key=os.environ.get("OPENROUTER_API_KEY")
    if not key: raise RuntimeError("OPENROUTER_API_KEY ontbreekt")
    body={"messages":messages,"temperature":0,"max_tokens":max_tokens,"response_format":{"type":"json_object"},"provider":{"allow_fallbacks":True,"data_collection":"deny"}}
    route=MODEL_ROUTES.get(tier)
    if route:
        body["models"]=route
        # Prefer the healthy Ling endpoint. OpenRouter may still use other
        # providers, and then the next model, when an endpoint is unavailable.
        body["provider"]["order"]=["novita","deepinfra"]
    else:
        body["model"]=MODELS[tier]
    if tier in ("ling", "deepseek"):
        body["reasoning"]={"enabled":False}
    elif tier == "glm":
        body["reasoning"]={"effort":"low"}
    req=urllib.request.Request("https://openrouter.ai/api/v1/chat/completions",data=json.dumps(body).encode(),headers={"Authorization":"Bearer "+key,"Content-Type":"application/json","HTTP-Referer":"http://192.168.1.2","X-Title":"Hermes Homelab"})
    started=now()
    try:
        with urllib.request.urlopen(req,timeout=75) as r: out=json.load(r)
    except urllib.error.HTTPError as e:
        try:
            detail=json.loads(e.read().decode()).get("error",{}).get("message","")
        except Exception: detail=""
        safe="".join(ch for ch in detail if ch.isalnum() or ch in " ._/-")[:180]
        raise RuntimeError("provider_http_"+str(e.code)+("_"+safe if safe else ""))
    usage=out.get("usage",{}); inp=int(usage.get("prompt_tokens",0)); cached=int(usage.get("prompt_tokens_details",{}).get("cached_tokens",0)); output=int(usage.get("completion_tokens",0))
    selected_model=out.get("model",MODELS[tier])
    price=PRICES.get(selected_model,PRICES[MODELS[tier]]); cost=(inp*price[0]+output*price[1])/1_000_000
    row={"timestamp":started,"run_id":run_id,"job":job,"model":selected_model,"requested_route":route or [MODELS[tier]],"provider":"openrouter","input_tokens":inp,"cached_input_tokens":cached,"output_tokens":output,"total_tokens":inp+output,"estimated_cost":round(cost,8),"tool_calls":len(out.get("choices",[{}])[0].get("message",{}).get("tool_calls",[]) or []),"escalation_reason":""}
    with COST_LOG.open("a",encoding="utf-8") as f: f.write(json.dumps(row,separators=(",",":"))+"\n")
    content=out.get("choices",[{}])[0].get("message",{}).get("content")
    if not isinstance(content,str) or not content.strip():
        raise RuntimeError("provider_malformed_response")
    return json.loads(content),row

def run(job, force_event=None, simulate_provider_failure=False, force_complex=False):
    run_id=str(uuid.uuid4()); compact,issues=collect() if force_event is None else ({"at":now(),"simulation":True},force_event)
    c=db(); calls=[]
    if job=="daily" and force_event is None:
        issues.extend(collect_incremental_logs(c))
    if not issues:
        c.execute("insert into runs values(?,?,?,?,?,?,?)",(run_id,now(),job,"OK",0,0,json.dumps(compact,separators=(",",":")))); c.commit()
        return {"status":"OK","run_id":run_id,"llm_calls":0,"estimated_cost":0,"summary":"Alles gezond; deterministische controle voltooid."}
    unique={hashlib.sha256(json.dumps(i,sort_keys=True).encode()).hexdigest()[:16]:i for i in issues}
    compact_events=list(unique.values())[:50]
    issue_fp=hashlib.sha256(json.dumps(compact_events,sort_keys=True).encode()).hexdigest()[:24]
    if job=="hourly" and force_event is None:
        prior=c.execute("select last_event_id,last_incident from cursors where service='__hourly__'").fetchone()
        if prior and prior[0]==issue_fp and prior[1]:
            try: age=(dt.datetime.now(dt.timezone.utc)-dt.datetime.fromisoformat(prior[1])).total_seconds()
            except Exception: age=999999
            if age < 43200:
                result={"status":"deduplicated","run_id":run_id,"llm_calls":0,"estimated_cost":0,"deduplicated_events":len(compact_events),"silent":True}
                c.execute("insert into runs values(?,?,?,?,?,?,?)",(run_id,now(),job,"deduplicated",0,0,json.dumps(result,separators=(",",":")))); c.commit(); return result
    prompt=[{"role":"system","content":"Classificeer compacte homelab-events als normal, watch of incident. Geef uitsluitend JSON met classification, confidence, summary, needs_troubleshooting en reason."},{"role":"user","content":json.dumps(compact_events,separators=(",",":"))[:12000]}]
    try:
        triage,row=call_model("ling",prompt,job,run_id); calls.append(row)
    except RuntimeError as e:
        detected=[{k:event.get(k) for k in ("service","severity","event","count") if event.get(k) is not None} for event in compact_events[:5]]
        result={"status":"watch","run_id":run_id,"llm_calls":0,"estimated_cost":0,"deduplicated_events":len(compact_events),"detected_events":detected,"summary":"Deterministische afwijking gevonden; alle triagemodellen tijdelijk niet beschikbaar.","provider_error":str(e)[:120]}
        c.execute("insert into runs values(?,?,?,?,?,?,?)",(run_id,now(),job,"watch",0,0,json.dumps(result,separators=(",",":")))); c.commit()
        return result
    result={"status":triage.get("classification","watch"),"triage":triage}
    if triage.get("needs_troubleshooting") or triage.get("classification")=="incident":
        diag_prompt=[{"role":"system","content":"Diagnoseer deze compacte homelab-events. Geef uitsluitend JSON met diagnosis, confidence, next_read_checks, proposed_fix, resolved. Geen write-acties."},{"role":"user","content":json.dumps({"events":compact_events,"metrics":compact.get("metrics",{})},separators=(",",":"))[:16000]}]
        try:
            if simulate_provider_failure: raise RuntimeError("simulated_provider_failure")
            diag,row=call_model("deepseek",diag_prompt,job,run_id,700); calls.append(row); result["diagnosis"]=diag
            diag_conf=diag.get("confidence")
            if force_complex or (diag.get("resolved") is False and diag_conf is not None and float(diag_conf)<0.55):
                luna_prompt=[{"role":"system","content":"Los een moeilijk homelab-diagnoseprobleem op. Geef alleen compacte JSON: diagnosis, confidence, discriminating_checks, proposed_fix."},{"role":"user","content":json.dumps(diag,separators=(",",":"))[:12000]}]
                deep,row=call_model("luna",luna_prompt,job,run_id,800); row["escalation_reason"]="DeepSeek inhoudelijk onzeker/vastgelopen"; calls.append(row); result["deep_analysis"]=deep
        except RuntimeError as e:
            if "provider" not in str(e): raise
            diag,row=call_model("glm",diag_prompt,job,run_id,700); row["escalation_reason"]="DeepSeek provider/API failure"; calls.append(row); result["diagnosis_fallback"]=diag
    total=round(sum(x["estimated_cost"] for x in calls),8)
    if job=="hourly" and force_event is None:
        c.execute("insert into cursors(service,last_event_id,last_incident,last_successful_check) values('__hourly__',?,?,?) on conflict(service) do update set last_event_id=excluded.last_event_id,last_incident=excluded.last_incident,last_successful_check=excluded.last_successful_check",(issue_fp,now(),now()))
    c.execute("insert into runs values(?,?,?,?,?,?,?)",(run_id,now(),job,result["status"],len(calls),total,json.dumps(result,separators=(",",":")))); c.commit()
    result.update({"run_id":run_id,"llm_calls":len(calls),"estimated_cost":total,"deduplicated_events":len(compact_events)}); return result

def simulate_pattern():
    c=db(); base=dt.datetime.now(dt.timezone.utc).replace(hour=4,minute=1,second=0,microsecond=0)
    c.execute("update adaptive_monitors set status='expired',conclusion='expired; remove or review' where status='active' and expires_at < ?",(now(),))
    times=[base-dt.timedelta(days=2),base-dt.timedelta(days=1)+dt.timedelta(minutes=2),base-dt.timedelta(minutes=2)]
    for t in times: c.execute("insert or ignore into events(ts,service,fingerprint,severity,summary) values(?,?,?,?,?)",(t.isoformat(),"demo","demo-error","warning","simulated recurring error"))
    rows=c.execute("select ts from events where fingerprint='demo-error' order by ts").fetchall(); mins=[dt.datetime.fromisoformat(x[0]).hour*60+dt.datetime.fromisoformat(x[0]).minute for x in rows]
    detected=len(rows)>=3 and max(mins)-min(mins)<=15
    active=c.execute("select count(*) from adaptive_monitors where status='active'").fetchone()[0]
    existing=c.execute("select id from adaptive_monitors where status='active' and hypothesis='tijdgebonden event rond 04:00' order by id limit 1").fetchone()
    if detected and active < 5 and not existing:
        created=dt.datetime.now(dt.timezone.utc); expires=created+dt.timedelta(days=7)
        c.execute("insert into adaptive_monitors(hypothesis,reason,created_at,expires_at,measurement_plan,result,conclusion) values(?,?,?,?,?,?,?)",("tijdgebonden event rond 04:00","3 observaties binnen 15 minuten",created.isoformat(),expires.isoformat(),"script-only snapshots 03:55, 04:05, 04:15","simulation pending","pending"))
    c.commit(); return {"pattern_detected":detected,"observations":len(rows),"script_only":True,"expires_days":7 if detected else None,"active_monitors":c.execute("select count(*) from adaptive_monitors where status='active'").fetchone()[0],"max_active":5}

if __name__=="__main__":
    p=argparse.ArgumentParser(); p.add_argument("mode",choices=["hourly","daily","test-a","test-b","test-c","test-d","test-e","test-f","simulate-pattern"]); a=p.parse_args()
    if a.mode=="simulate-pattern": result=simulate_pattern()
    elif a.mode=="test-a": result=run(a.mode,[{"service":"demo","severity":"warning","event":"single_transient_timeout"}])
    elif a.mode=="test-b": result=run(a.mode,[{"service":"plex","severity":"incident","event":"unreachable"},{"service":"storage","severity":"warning","event":"io_error"}])
    elif a.mode=="test-c": result=run(a.mode,[{"service":"plex","severity":"incident","event":"unreachable"}],True)
    elif a.mode=="test-d": result=run(a.mode,[{"service":"multi","severity":"incident","event":"contradictory_dependencies"}],False,True)
    elif a.mode=="test-e": result=run(a.mode,[])
    elif a.mode=="test-f": result=run(a.mode,[{"service":"demo","severity":"warning","event":"same_error","count":10000,"examples":["same error"]}])
    else: result=run(a.mode)
    if a.mode in ("hourly","daily") and (result.get("status")=="OK" or result.get("silent")):
        pass
    else:
        print(json.dumps(result,ensure_ascii=False,separators=(",",":")))
