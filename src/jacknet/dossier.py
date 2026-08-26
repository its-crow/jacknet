from __future__ import annotations

from .db import connect, migrate


def dossier_for_ip(ip: str) -> dict | None:
    migrate()
    with connect() as con:
        row = con.execute(
            """SELECT d.device_id,d.canonical_mac,d.first_seen,d.last_seen,d.user_label,d.manufacturer,d.model,d.device_type,d.confidence
               FROM devices d
               LEFT JOIN device_addresses a ON a.device_id=d.device_id
               WHERE a.ip=? OR EXISTS(SELECT 1 FROM observations o WHERE o.device_id=d.device_id AND o.ip=?)
               ORDER BY d.last_seen DESC LIMIT 1""", (ip, ip)).fetchone()
        if not row:
            return None
        did=row[0]
        addresses=con.execute("SELECT ip,first_seen,last_seen,observation_count,source FROM device_addresses WHERE device_id=? ORDER BY last_seen DESC",(did,)).fetchall()
        endpoints=con.execute("SELECT endpoint,first_seen,last_seen,hits,protocol FROM device_endpoints WHERE device_id=? ORDER BY hits DESC,last_seen DESC LIMIT 100",(did,)).fetchall()
        features=con.execute("SELECT feature_type,feature_value,source,COUNT(*),MAX(observed_at) FROM device_features WHERE device_id=? GROUP BY feature_type,feature_value,source ORDER BY COUNT(*) DESC LIMIT 200",(did,)).fetchall()
        traffic=con.execute("SELECT COUNT(*),COALESCE(SUM(bytes),0),MIN(observed_at),MAX(observed_at) FROM traffic_observations WHERE device_id=?",(did,)).fetchone()
        protocols=con.execute("SELECT protocol,COUNT(*) FROM traffic_observations WHERE device_id=? AND protocol IS NOT NULL GROUP BY protocol ORDER BY COUNT(*) DESC LIMIT 20",(did,)).fetchall()
        return {
            "device_id":did,"canonical_mac":row[1],"first_seen":row[2],"last_seen":row[3],"user_label":row[4],
            "manufacturer":row[5],"model":row[6],"device_type":row[7],"confidence":row[8],"queried_ip":ip,
            "addresses":[{"ip":x[0],"first_seen":x[1],"last_seen":x[2],"observations":x[3],"source":x[4]} for x in addresses],
            "endpoints":[{"endpoint":x[0],"first_seen":x[1],"last_seen":x[2],"hits":x[3],"protocol":x[4]} for x in endpoints],
            "features":[{"type":x[0],"value":x[1],"source":x[2],"count":x[3],"last_seen":x[4]} for x in features],
            "traffic":{"packets":traffic[0],"bytes":traffic[1],"first_seen":traffic[2],"last_seen":traffic[3],"protocols":[{"protocol":x[0],"count":x[1]} for x in protocols]},
        }


def all_devices() -> list[dict]:
    migrate()
    with connect() as con:
        rows=con.execute("""SELECT d.device_id,d.canonical_mac,d.user_label,d.manufacturer,d.model,d.device_type,d.confidence,d.first_seen,d.last_seen,
            (SELECT GROUP_CONCAT(ip, ', ') FROM device_addresses a WHERE a.device_id=d.device_id),
            (SELECT COUNT(*) FROM traffic_observations t WHERE t.device_id=d.device_id)
            FROM devices d ORDER BY d.last_seen DESC""").fetchall()
    return [{"device_id":r[0],"mac":r[1],"label":r[2],"manufacturer":r[3],"model":r[4],"device_type":r[5],"confidence":r[6],"first_seen":r[7],"last_seen":r[8],"ips":r[9],"traffic_packets":r[10]} for r in rows]
