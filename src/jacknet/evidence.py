from __future__ import annotations
import ipaddress,json,subprocess
from datetime import datetime,timezone
from pathlib import Path
from typing import Any
from .db import connect

def _flatten(value:Any,prefix=""):
 out={}
 if isinstance(value,dict):
  for key,child in value.items():
   p=f"{prefix}.{key}" if prefix else str(key)
   for name,vals in _flatten(child,p).items():out.setdefault(name,[]).extend(vals)
 elif isinstance(value,list):
  for child in value:
   for name,vals in _flatten(child,prefix).items():out.setdefault(name,[]).extend(vals)
 elif value is not None:out.setdefault(prefix,[]).append(str(value))
 return out
def _values(flat,*needles):
 found=[];wanted=tuple(n.lower().replace(".","_") for n in needles)
 for key,vals in flat.items():
  normalized=key.lower().replace(".","_")
  if any(normalized==n or normalized.endswith("_"+n) for n in wanted):
   for val in vals:
    if val and val not in found:found.append(val)
 return found
def _first(flat,*needles):
 vals=_values(flat,*needles);return vals[0] if vals else None
def _iso_epoch(value):
 if not value:return None
 try:return datetime.fromtimestamp(float(value),tz=timezone.utc).isoformat()
 except (TypeError,ValueError,OSError):return value
def _usable_mac(mac):
 if not mac:return False
 try:return mac.lower()!="ff:ff:ff:ff:ff:ff" and not (int(mac.split(":")[0],16)&1)
 except (ValueError,IndexError):return False
def _usable_host_ip(value):
 if not value:return False
 try:
  ip=ipaddress.ip_address(value);return not(ip.is_multicast or ip.is_unspecified or ip.is_loopback) and str(ip)!="255.255.255.255"
 except ValueError:return False
def _local_ip(value):
 if not _usable_host_ip(value):return False
 ip=ipaddress.ip_address(value);return ip.is_private or ip.is_link_local
def _lookup_device(con,mac,ip):
 if _usable_mac(mac):
  row=con.execute("SELECT device_id FROM devices WHERE lower(canonical_mac)=lower(?) LIMIT 1",(mac,)).fetchone();return int(row[0]) if row else None
 if _local_ip(ip):
  row=con.execute("SELECT device_id FROM device_addresses WHERE ip=? ORDER BY last_seen DESC LIMIT 1",(ip,)).fetchone();return int(row[0]) if row else None
 return None
def _artifact_pairs(flat,stack):
 pairs=[];mapping={"domain_query":("dns.qry.name",),"domain_answer":("dns.resp.name",),"tls_sni":("tls.handshake.extensions_server_name",),"http_host":("http.host",),"http_method":("http.request.method",),"http_uri":("http.request.uri","http.request.full_uri"),"http_user_agent":("http.user_agent",),"http_referer":("http.referer",),"http_content_type":("http.content_type",),"hostname":("dhcp.option.hostname","bootp.option.hostname","nbns.name"),"ssdp_server":("ssdp.server",),"ssdp_usn":("ssdp.usn",),"ssdp_location":("ssdp.location",),"tls_version":("tls.record.version","tls.handshake.version"),"tls_alpn":("tls.handshake.extensions_alpn_str",),"tls_cert_subject":("x509sat.printableString","x509sat.uTF8String"),"server_name":("smb2.server_name","smb.server"),"service":("dns.srv.service","dns.ptr.domain_name")}
 for typ,fields in mapping.items():
  for value in _values(flat,*fields):pairs.append((typ,value))
 if stack and "mdns" in stack.lower():
  for value in _values(flat,"dns.qry.name","dns.resp.name"):pairs.append(("mdns_name",value))
 seen=set();return [p for p in pairs if not(p in seen or seen.add(p))]
def _touch_relationship(con,did,relation,source_type,source_value,target_type,target_value,when,protocol):
 row=con.execute("SELECT id,hits FROM network_relationships WHERE device_id IS ? AND relation=? AND source_type=? AND source_value=? AND target_type=? AND target_value=?",(did,relation,source_type,source_value,target_type,target_value)).fetchone()
 if row:con.execute("UPDATE network_relationships SET last_seen=?,hits=?,protocol=COALESCE(?,protocol) WHERE id=?",(when,int(row[1])+1,protocol,row[0]))
 else:con.execute("INSERT INTO network_relationships(device_id,relation,source_type,source_value,target_type,target_value,first_seen,last_seen,hits,protocol,metadata) VALUES(?,?,?,?,?,?,?,?,1,?,NULL)",(did,relation,source_type,source_value,target_type,target_value,when,when,protocol))
def _traffic_owner(src_ip,dst_ip,src_did,dst_did):
 if _local_ip(src_ip):return src_did
 if _local_ip(dst_ip):return dst_did
 return src_did or dst_did
def _artifact_owner(typ,src_ip,dst_ip,src_did,dst_did):
 # Queries/client hello/HTTP requests originate at the client. DNS answers, certs and server advertisements describe the receiver-facing response/server.
 if typ in {"domain_answer","tls_cert_subject"}:
  return dst_did if _local_ip(dst_ip) else src_did
 if typ in {"ssdp_server","ssdp_usn","ssdp_location","server_name"}:return src_did or dst_did
 return _traffic_owner(src_ip,dst_ip,src_did,dst_did)
def ingest_full_decode(path:Path,session_id:int,tshark:str):
 proc=subprocess.Popen([tshark,"-n","-r",str(path),"-T","ek"],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,encoding="utf-8",errors="replace");assert proc.stdout is not None
 decoded=artifacts=relationships=packet_number=0
 with connect() as con:
  for raw in proc.stdout:
   raw=raw.strip()
   if not raw:continue
   try:obj=json.loads(raw)
   except json.JSONDecodeError:continue
   if "layers" not in obj:continue
   packet_number+=1;flat=_flatten(obj.get("layers",{}));observed_at=_iso_epoch(_first(flat,"frame.time_epoch"));stack=_first(flat,"frame.protocols");src_mac=_first(flat,"eth.src","wlan.sa");dst_mac=_first(flat,"eth.dst","wlan.da");src_ip=_first(flat,"ip.src","ipv6.src");dst_ip=_first(flat,"ip.dst","ipv6.dst");src_did=_lookup_device(con,src_mac,src_ip);dst_did=_lookup_device(con,dst_mac,dst_ip)
   con.execute("INSERT OR REPLACE INTO packet_decodes(session_id,packet_number,observed_at,protocol_stack,raw_json) VALUES(?,?,?,?,?)",(session_id,packet_number,observed_at,stack,json.dumps(obj,separators=(",",":"))));decoded+=1;when=observed_at or datetime.now(timezone.utc).isoformat();proto=stack.split(":")[-1] if stack else None
   for typ,value in _artifact_pairs(flat,stack):
    owner=_artifact_owner(typ,src_ip,dst_ip,src_did,dst_did);con.execute("INSERT INTO network_artifacts(session_id,device_id,observed_at,artifact_type,artifact_value,source,protocol,metadata) VALUES(?,?,?,?,?,'tshark-decode',?,NULL)",(session_id,owner,when,typ,value,proto));artifacts+=1
    if owner is not None and typ in {"domain_query","domain_answer","tls_sni","http_host","mdns_name","service"}:
     target="domain" if typ in {"domain_query","domain_answer"} else typ;_touch_relationship(con,owner,"uses" if typ=="service" else "contacts","device",str(owner),target,value,when,proto);relationships+=1
   owner=_traffic_owner(src_ip,dst_ip,src_did,dst_did)
   if owner is not None:
    remote=dst_ip if _local_ip(src_ip) else src_ip
    if _usable_host_ip(remote) and not _local_ip(remote):_touch_relationship(con,owner,"connects_to","device",str(owner),"ip",remote,when,proto);relationships+=1
 stderr=proc.stderr.read() if proc.stderr else "";rc=proc.wait()
 if rc:raise RuntimeError(stderr.strip() or f"TShark full decode exited with status {rc}")
 return {"decoded_packets":decoded,"artifacts":artifacts,"relationships":relationships}
