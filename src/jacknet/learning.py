from __future__ import annotations
import json, re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from .db import connect, migrate
from .models import Device, Evidence


def _now(): return datetime.now(timezone.utc).isoformat()

def _norm(s): return re.sub(r"\s+", " ", str(s or "").strip().lower())

def device_features(d: Device) -> set[tuple[str,str]]:
    out=set()
    if d.manufacturer: out.add(("manufacturer", _norm(d.manufacturer)))
    if d.hostname:
        h=_norm(d.hostname).split('.')[0]
        prefix=re.match(r"[a-z][a-z_-]{1,15}", h)
        if prefix: out.add(("hostname_prefix", prefix.group(0)))
    for p in d.open_ports:
        if p.get("port"): out.add(("port", str(p["port"])))
    for rec in d.mdns:
        blob=_norm(" ".join(map(str, rec.values())))
        for marker in ("_ipp", "_printer", "_airplay", "_googlecast", "_workstation"):
            if marker in blob: out.add(("mdns", marker))
    for rec in d.ssdp:
        blob=_norm(" ".join(map(str, rec.values())))
        for marker in ("printer", "playstation", "roku", "mediarenderer"):
            if marker in blob: out.add(("ssdp", marker))
    return out


def _device_from_payload(payload: str) -> Device:
    x=json.loads(payload)
    return Device(ip=x.get("ip",""), mac=x.get("mac"), hostname=x.get("hostname"), manufacturer=x.get("manufacturer"),
                  model=x.get("model"), device_type=x.get("device_type"), os=x.get("os"), confidence=x.get("confidence",0),
                  open_ports=x.get("open_ports",[]), mdns=x.get("mdns",[]), ssdp=x.get("ssdp",[]))


def _persistent_features(con, device_id: int) -> set[tuple[str,str]]:
    """Return stable dossier features, requiring repeated passive evidence across capture sessions."""
    out=set()
    rows=con.execute("""SELECT feature_type,feature_value,COUNT(*) AS n
        FROM device_features WHERE device_id=? GROUP BY feature_type,feature_value HAVING n>=2""",(device_id,)).fetchall()
    for ft,val,_ in rows:
        ft=_norm(ft); val=_norm(val)
        if not val: continue
        if ft in {"hostname","traffic_hostname"}:
            h=val.split('.')[0]; m=re.match(r"[a-z][a-z_-]{1,15}",h)
            if m: out.add(("hostname_prefix",m.group(0)))
        elif ft in {"open_port","observed_port"}:
            out.add(("port",val))
        elif ft in {"dns","tls_sni","http_host","mdns_name","ssdp_server","service","protocol"}:
            out.add((ft,val))

    # Passive packet evidence is intentionally promoted by capture-session support,
    # not raw packet count. One noisy capture cannot manufacture certainty.
    passive=con.execute("""
        SELECT artifact_type,artifact_value,COUNT(DISTINCT session_id) AS sessions
        FROM network_artifacts
        WHERE device_id=? AND session_id IS NOT NULL
          AND artifact_type IN ('domain','tls_sni','http_host','mdns_name','hostname','service','protocol','ssdp_server')
        GROUP BY artifact_type,artifact_value
        HAVING sessions>=2
    """,(device_id,)).fetchall()
    for ft,val,_ in passive:
        ft=_norm(ft); val=_norm(val)
        if not val: continue
        if ft=="domain": out.add(("dns",val))
        elif ft=="hostname":
            h=val.split('.')[0]; m=re.match(r"[a-z][a-z_-]{1,15}",h)
            if m: out.add(("hostname_prefix",m.group(0)))
        else: out.add((ft,val))
    return out


def _device_id_for(con, device: Device) -> int | None:
    """Resolve a current scan Device to its persistent dossier without trusting IP over a known MAC."""
    if device.mac:
        row=con.execute("SELECT device_id FROM devices WHERE lower(canonical_mac)=lower(?) LIMIT 1",(device.mac,)).fetchone()
        if row: return int(row[0])
        return None
    if device.ip:
        row=con.execute("SELECT device_id FROM device_addresses WHERE ip=? ORDER BY last_seen DESC LIMIT 1",(device.ip,)).fetchone()
        if row: return int(row[0])
    return None


def find_latest(ip: str):
    migrate()
    with connect() as con:
        return con.execute("""SELECT o.id,o.device_id,o.ip,o.mac,o.hostname,o.manufacturer,o.model,o.device_type,o.confidence,o.payload
            FROM observations o WHERE o.ip=? ORDER BY o.id DESC LIMIT 1""", (ip,)).fetchone()


def confirm(ip: str, manufacturer=None, model=None, device_type=None, correction=False):
    row=find_latest(ip)
    if not row: raise LookupError(f"No stored observation for {ip}. Run `jacknet scan -ip {ip}` first.")
    obs_id, device_id, _, mac, hostname, old_man, old_model, old_type, confidence, payload=row
    if device_id is None: raise LookupError(f"The latest observation for {ip} has no durable device association yet.")
    man=manufacturer or old_man; mdl=model or old_model; typ=device_type or old_type
    with connect() as con:
        con.execute("INSERT INTO labels(device_id,created_at,manufacturer,model,device_type,source) VALUES(?,?,?,?,?,?)",
                    (device_id,_now(),man,mdl,typ,"user_correction" if correction else "user_confirm"))
        con.execute("UPDATE devices SET user_label=?,manufacturer=?,model=?,device_type=?,confidence=? WHERE device_id=?",
                    (mdl,man,mdl,typ,max(95,confidence or 0),device_id))
        if correction:
            con.execute("INSERT INTO corrections(device_id,created_at,previous_label,corrected_label,notes) VALUES(?,?,?,?,?)",
                        (device_id,_now(),old_model,mdl or typ or man or "corrected",f"observation {obs_id}"))
    return {"ip":ip,"mac":mac,"hostname":hostname,"manufacturer":man,"model":mdl,"device_type":typ,"previous":old_model,"confidence":confidence}


def learn():
    """Mine active scans, passive traffic and user labels into conservative reusable fingerprints."""
    migrate(); examples=[]
    with connect() as con:
        rows=con.execute("""SELECT o.device_id,o.payload,o.model,o.device_type,o.confidence,
            EXISTS(SELECT 1 FROM labels l WHERE l.device_id=o.device_id) AS user_confirmed
            FROM observations o WHERE o.device_id IS NOT NULL ORDER BY o.id DESC""").fetchall()
        seen=set()
        for did,payload,model,typ,conf,user in rows:
            if did in seen: continue
            seen.add(did)
            if not model or not typ: continue
            if not user and (conf or 0) < 70: continue
            try: d=_device_from_payload(payload)
            except Exception: continue
            feats=device_features(d) | _persistent_features(con,did)
            examples.append((did,model,typ,bool(user),feats))

        groups=defaultdict(list)
        for ex in examples: groups[(ex[1],ex[2])].append(ex)
        created=updated=promoted=0
        for (model,typ), exs in groups.items():
            counts=Counter(f for *_,fs in exs for f in fs)
            support=len(exs); confirmed=sum(1 for e in exs if e[3])
            threshold=1 if confirmed else 2
            common=[(ft,val,n) for (ft,val),n in counts.items() if n>=threshold]
            if not common: continue
            status="active" if (confirmed >= 1 or support >= 3) else "candidate"
            name=f"learned:{model}:{typ}"
            fp=con.execute("SELECT id,status FROM fingerprints WHERE name=?",(name,)).fetchone()
            if fp:
                fid,old_status=fp; updated+=1
                con.execute("UPDATE fingerprints SET support_count=?,precision=?,status=?,updated_at=? WHERE id=?",
                            (support,1.0 if confirmed else None,status,_now(),fid))
                con.execute("DELETE FROM fingerprint_features WHERE fingerprint_id=?",(fid,))
                if old_status != "active" and status == "active": promoted+=1
            else:
                cur=con.execute("INSERT INTO fingerprints(name,model,device_type,status,support_count,precision,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)",
                    (name,model,typ,status,support,1.0 if confirmed else None,_now(),_now()))
                fid=cur.lastrowid; created+=1
                if status=="active": promoted+=1
            for ft,val,n in common:
                weight=22.0 if confirmed else 12.0
                con.execute("INSERT INTO fingerprint_features(fingerprint_id,feature_type,pattern,weight,positive_count,negative_count) VALUES(?,?,?,?,?,0)",
                            (fid,ft,val,weight,n))
    return {"examples":len(examples),"created":created,"updated":updated,"promoted":promoted}


def apply_learned(device: Device) -> Device:
    """Apply active fingerprints using current evidence plus the device's persistent dossier."""
    try: migrate()
    except Exception: return device
    feats=device_features(device)
    with connect() as con:
        did=_device_id_for(con,device)
        if did is not None:
            feats |= _persistent_features(con,did)
        rows=con.execute("""SELECT f.id,f.model,f.device_type,ff.feature_type,ff.pattern,ff.weight
            FROM fingerprints f JOIN fingerprint_features ff ON ff.fingerprint_id=f.id WHERE f.status='active'""").fetchall()
    if not feats: return device
    scores=defaultdict(float); matches=defaultdict(list)
    for fid,model,typ,ft,pat,w in rows:
        if (ft,pat) in feats:
            scores[(fid,model,typ)] += w; matches[(fid,model,typ)].append((ft,pat,w))
    if not scores: return device
    key,score=max(scores.items(), key=lambda kv:kv[1]); _,model,typ=key
    ms=matches[key]
    if len(ms)<2 and score<20: return device
    for ft,pat,w in ms: device.evidence.append(Evidence("learned",ft,pat,int(w)))
    learned_conf=min(95, 55 + int(score))
    if learned_conf > device.confidence:
        device.model=model or device.model; device.device_type=typ or device.device_type; device.confidence=learned_conf
    return device
