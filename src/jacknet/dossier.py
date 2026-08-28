from __future__ import annotations

from .db import connect, migrate
from .network_context import ensure_network


def _mac_type(mac: str | None) -> str:
    if not mac:return "unknown"
    try:first=int(mac.split(":")[0],16)
    except (ValueError,IndexError):return "unknown"
    if first & 1:return "multicast"
    if first & 2:return "private/local"
    return "global"


def dossier_for_ip(ip: str) -> dict | None:
    migrate(); current_network_id,current_network=ensure_network()
    with connect() as con:
        row=con.execute("""SELECT d.device_id,d.canonical_mac,d.first_seen,d.last_seen,d.user_label,d.manufacturer,d.model,d.device_type,d.confidence
            FROM devices d JOIN device_network_addresses a ON a.device_id=d.device_id
            WHERE a.network_id=? AND a.ip=? ORDER BY a.last_seen DESC LIMIT 1""",(current_network_id,ip)).fetchone()
        resolved_network_id=current_network_id
        if not row:
            candidate=con.execute("""SELECT d.device_id,d.canonical_mac,d.first_seen,d.last_seen,d.user_label,d.manufacturer,d.model,d.device_type,d.confidence,a.network_id
                FROM devices d JOIN device_network_addresses a ON a.device_id=d.device_id WHERE a.ip=? ORDER BY a.last_seen DESC LIMIT 1""",(ip,)).fetchone()
            if not candidate:return None
            row=candidate[:9];resolved_network_id=int(candidate[9])
        did=row[0]
        addresses=con.execute("""SELECT a.ip,a.first_seen,a.last_seen,a.observation_count,a.source,n.network_id,n.name,n.network_key,n.cidr,n.ssid
            FROM device_network_addresses a JOIN networks n ON n.network_id=a.network_id WHERE a.device_id=? ORDER BY a.last_seen DESC""",(did,)).fetchall()
        endpoints=con.execute("""SELECT e.endpoint,e.first_seen,e.last_seen,e.hits,e.protocol,n.name FROM device_endpoints e LEFT JOIN networks n ON n.network_id=e.network_id WHERE e.device_id=? ORDER BY e.hits DESC,e.last_seen DESC LIMIT 100""",(did,)).fetchall()
        features=con.execute("SELECT feature_type,feature_value,source,COUNT(*),MAX(observed_at) FROM device_features WHERE device_id=? GROUP BY feature_type,feature_value,source ORDER BY COUNT(*) DESC LIMIT 200",(did,)).fetchall()
        traffic=con.execute("SELECT COUNT(*),COALESCE(SUM(bytes),0),MIN(observed_at),MAX(observed_at) FROM traffic_observations WHERE device_id=?",(did,)).fetchone()
        protocols=con.execute("SELECT protocol,COUNT(*) FROM traffic_observations WHERE device_id=? AND protocol IS NOT NULL GROUP BY protocol ORDER BY COUNT(*) DESC LIMIT 20",(did,)).fetchall()
        resolved=con.execute("SELECT name,network_key,cidr,ssid FROM networks WHERE network_id=?",(resolved_network_id,)).fetchone()
        return {"device_id":did,"canonical_mac":row[1],"mac_type":_mac_type(row[1]),"first_seen":row[2],"last_seen":row[3],"user_label":row[4],"manufacturer":row[5],"model":row[6],"device_type":row[7],"confidence":row[8],"queried_ip":ip,"current_network":{"network_id":current_network_id,"name":current_network.name,"key":current_network.key,"cidr":current_network.cidr,"ssid":current_network.ssid},"resolved_network":{"network_id":resolved_network_id,"name":resolved[0] if resolved else None,"key":resolved[1] if resolved else None,"cidr":resolved[2] if resolved else None,"ssid":resolved[3] if resolved else None},"addresses":[{"ip":x[0],"first_seen":x[1],"last_seen":x[2],"observations":x[3],"source":x[4],"network_id":x[5],"network":x[6],"network_key":x[7],"cidr":x[8],"ssid":x[9]} for x in addresses],"endpoints":[{"endpoint":x[0],"first_seen":x[1],"last_seen":x[2],"hits":x[3],"protocol":x[4],"network":x[5]} for x in endpoints],"features":[{"type":x[0],"value":x[1],"source":x[2],"count":x[3],"last_seen":x[4]} for x in features],"traffic":{"packets":traffic[0],"bytes":traffic[1],"first_seen":traffic[2],"last_seen":traffic[3],"protocols":[{"protocol":x[0],"count":x[1]} for x in protocols]}}


def all_devices() -> list[dict]:
    migrate();current_network_id,current_network=ensure_network()
    with connect() as con:
        rows=con.execute("""SELECT d.device_id,d.canonical_mac,d.user_label,d.manufacturer,d.model,d.device_type,d.confidence,d.first_seen,d.last_seen,
            (SELECT ip FROM device_network_addresses a WHERE a.device_id=d.device_id AND a.network_id=? ORDER BY a.last_seen DESC LIMIT 1),
            (SELECT COUNT(*) FROM device_network_addresses a WHERE a.device_id=d.device_id),
            (SELECT COUNT(DISTINCT network_id) FROM device_network_addresses a WHERE a.device_id=d.device_id),
            (SELECT COUNT(*) FROM traffic_observations t WHERE t.device_id=d.device_id),
            (SELECT n.name FROM device_network_addresses a JOIN networks n ON n.network_id=a.network_id WHERE a.device_id=d.device_id ORDER BY a.last_seen DESC LIMIT 1)
            FROM devices d ORDER BY d.last_seen DESC""",(current_network_id,)).fetchall()
    return [{"device_id":r[0],"mac":r[1],"mac_type":_mac_type(r[1]),"label":r[2],"manufacturer":r[3],"model":r[4],"device_type":r[5],"confidence":r[6],"first_seen":r[7],"last_seen":r[8],"current_ip":r[9],"address_count":r[10],"network_count":r[11],"traffic_packets":r[12],"last_network":r[13],"current_network":current_network.name,"current_network_id":current_network_id,"on_current_network":r[9] is not None} for r in rows]
