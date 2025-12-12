from datetime import datetime


class Detector:
    def __init__(self) -> None:
        self.last_scan_alerts = {}
        self.old_macs = []
        self.first_run = True

    def connect_scans(self, current_connections: list, targets: list, min_distinct_targets: int) -> list:
        now = datetime.now()
        cooldown_seconds = 300

        if not targets or not current_connections:
            return []

        threshold = {(dst, port): min_dupes for (
            dst, port, min_dupes) in targets}

        counts = {}
        for c in current_connections:
            key_dp = (c["destination"], c["destination_port"])
            if key_dp in threshold:
                key = (c["source"], c["destination"], c["destination_port"])
                counts[key] = counts.get(key, 0) + 1

        per_src_hits = {}
        for (src, dst, port), cnt in counts.items():
            required = threshold[(dst, port)]
            if cnt >= required:
                per_src_hits.setdefault(src, []).append(
                    (dst, port, cnt, required))

        alerts = []
        for src, hits in per_src_hits.items():
            distinct = {(dst, port) for (dst, port, _, _) in hits}
            if len(distinct) >= min_distinct_targets:
                last_alert_time = self.last_scan_alerts.get(src)

                if last_alert_time and (now - last_alert_time).total_seconds() < cooldown_seconds:
                    continue

                self.last_scan_alerts[src] = now
                alerts.append({
                    "type": "network_scan",
                    "source": src,
                    "details": [{"destination": d, "port": p, "connections": c, "threshold": r} for (d, p, c, r) in hits],
                    "time": now.isoformat()
                })

        return alerts

    def new_macs(self, leases: list, static_devices: list) -> list:
        alerts = []
        for l in leases:
            if l["mac"] not in self.old_macs:
                if not self.first_run:
                    alerts.append({
                        "type": "new_mac_address",
                        "source": l["ip"],
                        "details": ["lease", l["mac"], l["hostname"], l["expires"]],
                        "time": l["ts"]
                    })
                self.old_macs.append(l["mac"])

        for s in static_devices:
            if s["mac"] not in self.old_macs:
                if not self.first_run:
                    alerts.append({
                        "type": "new_mac_address",
                        "source": s["ip"],
                        "details": ["static_device", s["mac"]],
                        "time": s["ts"]
                    })
                self.old_macs.append(s["mac"])

        self.first_run = False

        return alerts
