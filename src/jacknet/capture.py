from __future__ import annotations

import ipaddress
import json
import os
import shutil
import subprocess
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Iterable

from .db import connect, migrate
from .evidence import ingest_full_decode
from .network_context import ensure_network, get_network

TSHARK_FIELDS=["frame.time_epoch","frame.len","eth.src","eth.dst","ip.src","ip.dst","ipv6.src","ipv6.dst","tcp.srcport","tcp.dstport","udp.srcport","udp.dstport","_ws.col.Protocol","dns.qry.name","dns.resp.name","tls.handshake.extensions_server_name","http.host","dhcp.option.hostname","bootp.option.hostname","ssdp.server","ssdp.usn","wlan.sa","wlan.da","radiotap.dbm_antsignal"]

@dataclass
class TrafficRecord:
    observed_at:str;length:int=0;src_mac:str|None=None;dst_mac:str|None=None;src_ip:str|None=None;dst_ip:str|None=None;src_port:int|None=None;dst_port:int|None=None;protocol:str|None=None;dns_name:str|None=None;tls_sni:str|None=None;http_host:str|None=None;hostname:str|None=None;mdns_name:str|None=None;ssdp_server:str|None=None;ssdp_usn:str|None=None;signal_dbm:int|None=None;metadata:dict=field(default_factory=dict)

def _now():return datetime.now(timezone.utc).isoformat()
def _find_wireshark_tool(name):
    found=shutil.which(name)
    if found:return found
    if os.name=="nt":
        exe=name if name.lower().endswith(".exe") else f"{name}.exe"
        for root in [Path(os.environ.get("ProgramFiles",r"C:\Program Files"))/"Wireshark",Path(os.environ.get("ProgramFiles(x86)",r"C:\Program Files (x86)"))/"Wireshark"]:
            candidate=root/exe
            if candidate.is_file():return str(candidate)
    return None
def tshark_path():return _find_wireshark_tool("tshark")
def dumpcap_path():return _find_wireshark_tool("dumpcap")
def capture_ready():
    x=tshark_path();return (True,x) if x else (False,"TShark was not found. Install Wireshark with TShark enabled.")
def list_interfaces():
    exe=tshark_path()
    if not exe:return []
    p=subprocess.run([exe,"-D"],capture_output=True,text=True,check=False,timeout=10);rows=[]
    for raw in p.stdout.splitlines():
        raw=raw.strip()
        if raw and "." in raw:
            num,desc=raw.split(".",1);rows.append((num.strip(),desc.strip()))
    return rows

@lru_cache(maxsize=1)
def supported_tshark_fields():
    exe=tshark_path()
    if not exe:return frozenset()
    try:p=subprocess.run([exe,"-G","fields"],capture_output=True,text=True,encoding="utf-8",errors="replace",check=False,timeout=30)
    except (OSError,subprocess.TimeoutExpired):return frozenset()
    fields=set()
    for line in p.stdout.splitlines():
        cols=line.split("\t")
        if len(cols)>=3 and cols[0]=="F":fields.add(cols[2].strip())
    return frozenset(fields)
def active_tshark_fields():
    supported=supported_tshark_fields()
    if not supported:return ["frame.time_epoch","frame.len","eth.src","eth.dst","ip.src","ip.dst","ipv6.src","ipv6.dst","tcp.srcport","tcp.dstport","udp.srcport","udp.dstport","_ws.col.Protocol"]
    return [f for f in TSHARK_FIELDS if f in supported]
def _first(*values):
    for value in values:
        value=(value or "").strip()
        if value:return value.split(",")[0].strip()
    return None
def _to_int(value):
    try:return int(float(value)) if value not in (None,"") else None
    except (TypeError,ValueError):return None
def _iso_from_epoch(value):
    try:return datetime.fromtimestamp(float(value or ""),tz=timezone.utc).isoformat()
    except (TypeError,ValueError,OSError):return _now()

def iter_capture(path:Path)->Iterable[TrafficRecord]:
    exe=tshark_path()
    if not exe:raise RuntimeError("TShark is required to analyze capture files.")
    if not path.exists():raise FileNotFoundError(path)
    fields=active_tshark_fields()
    if not fields:raise RuntimeError("TShark is installed, but Jacknet could not discover any usable fields.")
    cmd=[exe,"-n","-r",str(path),"-T","fields","-E","separator=\t","-E","quote=d","-E","occurrence=f"]
    for f in fields:cmd.extend(["-e",f])
    proc=subprocess.Popen(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,encoding="utf-8",errors="replace");assert proc.stdout is not None
    for line in proc.stdout:
        cols=line.rstrip("\r\n").split("\t");cols.extend([""]*max(0,len(fields)-len(cols)));d=dict(zip(fields,[c.strip('"') for c in cols[:len(fields)]]))
        src_ip=_first(d.get("ip.src"),d.get("ipv6.src"));dst_ip=_first(d.get("ip.dst"),d.get("ipv6.dst"));src_mac=_first(d.get("eth.src"),d.get("wlan.sa"));dst_mac=_first(d.get("eth.dst"),d.get("wlan.da"));protocol=_first(d.get("_ws.col.Protocol"));dq=_first(d.get("dns.qry.name"));dr=_first(d.get("dns.resp.name"))
        yield TrafficRecord(observed_at=_iso_from_epoch(d.get("frame.time_epoch")),length=_to_int(d.get("frame.len")) or 0,src_mac=src_mac.lower() if src_mac else None,dst_mac=dst_mac.lower() if dst_mac else None,src_ip=src_ip,dst_ip=dst_ip,src_port=_to_int(_first(d.get("tcp.srcport"),d.get("udp.srcport"))),dst_port=_to_int(_first(d.get("tcp.dstport"),d.get("udp.dstport"))),protocol=protocol,dns_name=dq or dr,tls_sni=_first(d.get("tls.handshake.extensions_server_name")),http_host=_first(d.get("http.host")),hostname=_first(d.get("dhcp.option.hostname"),d.get("bootp.option.hostname")),mdns_name=_first(dr,dq) if (protocol or "").lower()=="mdns" else None,ssdp_server=_first(d.get("ssdp.server")),ssdp_usn=_first(d.get("ssdp.usn")),signal_dbm=_to_int(d.get("radiotap.dbm_antsignal")))
    stderr=proc.stderr.read() if proc.stderr else "";rc=proc.wait()
    if rc:raise RuntimeError(stderr.strip() or f"TShark exited with status {rc}")

def _host_ip(value):
    if not value:return False
    try:
        ip=ipaddress.ip_address(value)
        return not (ip.is_multicast or ip.is_unspecified or ip.is_loopback) and str(ip)!="255.255.255.255"
    except ValueError:return False
def _is_local_ip(value):
    if not _host_ip(value):return False
    ip=ipaddress.ip_address(value);return ip.is_private or ip.is_link_local
def _usable_mac(mac):
    if not mac:return False
    try:return mac.lower()!="ff:ff:ff:ff:ff:ff" and not (int(mac.split(":")[0],16)&1)
    except (ValueError,IndexError):return False

def _find_or_create_device(con,network_id,mac,ip,observed_at):
    if _usable_mac(mac):
        row=con.execute("SELECT device_id FROM devices WHERE lower(canonical_mac)=lower(?)",(mac,)).fetchone()
        if row:
            did=int(row[0]);con.execute("UPDATE devices SET last_seen=? WHERE device_id=?",(observed_at,did));return did
        cur=con.execute("INSERT INTO devices(canonical_mac,first_seen,last_seen,confidence) VALUES(?,?,?,0)",(mac,observed_at,observed_at));return int(cur.lastrowid)
    if _is_local_ip(ip):
        row=con.execute("SELECT device_id FROM device_network_addresses WHERE network_id=? AND ip=? ORDER BY last_seen DESC LIMIT 1",(network_id,ip)).fetchone()
        if row:return int(row[0])
    return None
def _touch_address(con,network_id,did,ip,when,source):
    if not _is_local_ip(ip):return
    row=con.execute("SELECT id,observation_count FROM device_network_addresses WHERE network_id=? AND device_id=? AND ip=?",(network_id,did,ip)).fetchone()
    if row:con.execute("UPDATE device_network_addresses SET last_seen=?,observation_count=?,source=? WHERE id=?",(when,int(row[1])+1,source,row[0]))
    else:con.execute("INSERT INTO device_network_addresses(network_id,device_id,ip,first_seen,last_seen,observation_count,source) VALUES(?,?,?,?,?,1,?)",(network_id,did,ip,when,when,source))
def _touch_endpoint(con,network_id,did,endpoint,when,protocol):
    row=con.execute("SELECT id,hits FROM device_endpoints WHERE device_id=? AND endpoint=? AND network_id IS ?",(did,endpoint,network_id)).fetchone()
    if row:con.execute("UPDATE device_endpoints SET last_seen=?,hits=?,protocol=COALESCE(?,protocol) WHERE id=?",(when,int(row[1])+1,protocol,row[0]))
    else:con.execute("INSERT INTO device_endpoints(device_id,endpoint,first_seen,last_seen,hits,protocol,network_id) VALUES(?,?,?,?,1,?,?)",(did,endpoint,when,when,protocol,network_id))
def _packet_owner(rec,src_did,dst_did):
    if _is_local_ip(rec.src_ip):return src_did
    if _is_local_ip(rec.dst_ip):return dst_did
    return src_did or dst_did

def ingest_capture(path:Path,source="pcap",interface=None,network_id_override:int|None=None):
    migrate()
    if network_id_override is not None:
        network=get_network(network_id_override)
        if network is None: network_id,network=ensure_network()
        else: network_id=network_id_override
    else:
        network_id,network=ensure_network()
    path=path.expanduser().resolve();started=_now();packet_count=0;devices=set();local_ips=set();external_endpoints=set();protocol_counts=defaultdict(int);dns_names=set()
    with connect() as con:
        cur=con.execute("INSERT INTO capture_sessions(started_at,source,capture_file,interface,packet_count,network_id) VALUES(?,?,?,?,0,?)",(started,source,str(path),interface,network_id));session_id=int(cur.lastrowid)
        for rec in iter_capture(path):
            packet_count+=1
            if rec.protocol:protocol_counts[rec.protocol]+=1
            if rec.dns_name:dns_names.add(rec.dns_name)
            src_did=_find_or_create_device(con,network_id,rec.src_mac,rec.src_ip if _is_local_ip(rec.src_ip) else None,rec.observed_at)
            dst_did=_find_or_create_device(con,network_id,rec.dst_mac,rec.dst_ip if _is_local_ip(rec.dst_ip) else None,rec.observed_at)
            for did,ip in ((src_did,rec.src_ip),(dst_did,rec.dst_ip)):
                if did is not None:
                    devices.add(did)
                    if _is_local_ip(ip):local_ips.add(ip);_touch_address(con,network_id,did,ip,rec.observed_at,source)
            owner=_packet_owner(rec,src_did,dst_did)
            if owner is not None:
                remote=rec.dst_ip if _is_local_ip(rec.src_ip) else rec.src_ip
                if remote and _host_ip(remote) and not _is_local_ip(remote):external_endpoints.add(remote);_touch_endpoint(con,network_id,owner,remote,rec.observed_at,rec.protocol)
            metadata={"hostname":rec.hostname,"mdns_name":rec.mdns_name,"ssdp_server":rec.ssdp_server,"ssdp_usn":rec.ssdp_usn,"signal_dbm":rec.signal_dbm,"src_device_id":src_did,"dst_device_id":dst_did,"network_id":network_id,"network_key":network.key}
            con.execute("""INSERT INTO traffic_observations(device_id,session_id,observed_at,source,capture_file,src_ip,dst_ip,src_mac,dst_mac,protocol,src_port,dst_port,dns_name,tls_sni,http_host,bytes,metadata,network_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",(owner,session_id,rec.observed_at,source,str(path),rec.src_ip,rec.dst_ip,rec.src_mac,rec.dst_mac,rec.protocol,rec.src_port,rec.dst_port,rec.dns_name,rec.tls_sni,rec.http_host,rec.length,json.dumps(metadata),network_id))
            if owner is not None:
                features=[]
                if rec.hostname:features.append(("traffic_hostname",rec.hostname))
                if rec.dns_name:features.append(("dns",rec.dns_name))
                if rec.tls_sni:features.append(("tls_sni",rec.tls_sni))
                if rec.http_host:features.append(("http_host",rec.http_host))
                if rec.mdns_name:features.append(("mdns_name",rec.mdns_name))
                if rec.ssdp_server:features.append(("ssdp_server",rec.ssdp_server))
                if rec.dst_port and _is_local_ip(rec.src_ip):features.append(("observed_port",str(rec.dst_port)))
                for ft,val in features:con.execute("INSERT INTO device_features(device_id,observed_at,feature_type,feature_value,source) VALUES(?,?,?,?,?)",(owner,rec.observed_at,ft,val,source))
        con.execute("UPDATE capture_sessions SET ended_at=?,packet_count=? WHERE id=?",(_now(),packet_count,session_id))
    decode_stats={"decoded_packets":0,"artifacts":0,"relationships":0};exe=tshark_path()
    if exe and packet_count:
        try:decode_stats.update(ingest_full_decode(path,session_id,exe))
        except Exception as exc:decode_stats["decode_error"]=str(exc)
    return {"session_id":session_id,"network_id":network_id,"network":network.name,"network_key":network.key,"capture":str(path),"packets":packet_count,"devices":len(devices),"local_ips":len(local_ips),"external_endpoints":len(external_endpoints),"dns_names":len(dns_names),"protocols":dict(sorted(protocol_counts.items(),key=lambda kv:kv[1],reverse=True)[:20]),**decode_stats}
def live_capture(interface,output:Path,duration=60,monitor=False):
    exe=dumpcap_path() or tshark_path()
    if not exe:raise RuntimeError("Neither dumpcap nor TShark is available.")
    output=output.expanduser().resolve();output.parent.mkdir(parents=True,exist_ok=True);cmd=[exe,"-i",str(interface),"-a",f"duration:{max(1,duration)}","-w",str(output)]
    if monitor:cmd.insert(1,"-I")
    proc=subprocess.run(cmd,capture_output=True,text=True,check=False)
    if proc.returncode:raise RuntimeError(proc.stderr.strip() or proc.stdout.strip() or f"capture exited with {proc.returncode}")
    return output
