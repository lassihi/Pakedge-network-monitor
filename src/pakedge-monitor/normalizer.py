from datetime import datetime, timedelta


def normalize_leases(leases):
    now = datetime.now()
    ts = now.isoformat()
    normalized = []

    for l in leases:
        expires_seconds = l.get("expires", 0)

        end_dt = now + timedelta(seconds=expires_seconds)
        end_time = end_dt.isoformat()

        normalized.append({
            "ts": ts,
            "ip": l.get("ipaddr"),
            "mac": l.get("macaddr"),
            "hostname": l.get("hostname"),
            "expires": end_time
        })

    return normalized


def normalize_connections(connections):
    ts = datetime.now().isoformat
    normalized = []
    for c in connections:
        src = c.get("src") or ""
        dst = c.get("dst") or ""

        try:
            src_prt = int(c.get("sport") or 0)
        except ValueError:
            src_prt = 0

        try:
            dst_prt = int(c.get("dport") or 0)
        except ValueError:
            dst_prt = 0

        normalized.append({
            "ts": ts,
            "protocol": c.get("layer4"),
            "source": src,
            "source_port": src_prt,
            "destination": dst,
            "destination_port": dst_prt,
            "bytes": int(c.get("bytes", 0)),
            "packets": int(c.get("packets", 0))
        })

    return normalized


def normalize_static(static_devices):
    ts = datetime.now().isoformat()
    normalized = []

    for d in static_devices:
        normalized.append({
            "ts": ts,
            "mac": d.get("mac"),
            "ip": d.get("ip")
        })

    return normalized
