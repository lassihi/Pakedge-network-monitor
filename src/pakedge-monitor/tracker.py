from datetime import datetime, timedelta


class Session:
    def __init__(self, source: str, source_port: int, destination: str, destination_port: int, start_time: str, bytes: int, packets: int, protocol: str, end_time=None, active=True) -> None:
        self.source = source
        self.source_port = source_port
        self.destination = destination
        self.destination_port = destination_port
        self.start_time = start_time
        self.end_time = end_time
        self.bytes = bytes
        self.packets = packets
        self.protocol = protocol
        self.active = active


class Device:
    def __init__(self, mac: str) -> None:
        self.mac = mac
        self.ip = None
        self.hostname = None
        self.first_seen = None
        self.last_seen = None
        self.active = False

    def set_active(self, dev: list) -> None:
        timestamp = dev["ts"]
        timestamp_dt = datetime.fromisoformat(timestamp)

        if self.first_seen is None:
            self.first_seen = timestamp
        else:
            first_seen_dt = datetime.fromisoformat(self.first_seen)
            if timestamp_dt < first_seen_dt:
                self.first_seen = timestamp

        if self.last_seen is None:
            self.last_seen = timestamp
            self.ip = dev["ip"]
            try:
                self.hostname = dev["hostname"]
            except KeyError:
                self.hostname = None
        else:
            last_seen_dt = datetime.fromisoformat(self.last_seen)
            if timestamp_dt > last_seen_dt:
                self.last_seen = timestamp
                self.ip = dev["ip"]
                try:
                    self.hostname = dev["hostname"]
                except KeyError:
                    self.hostname = None

        self.active = True

    def set_inactive(self) -> None:
        self.active = False

    def update_static(self, record: dict) -> None:
        ts = record.get("ts") or datetime.now().isoformat()
        ip = record.get("ip")

        if self.first_seen is None:
            self.first_seen = ts

        if self.last_seen is None:
            self.last_seen = ts
        else:
            try:
                current_last = datetime.fromisoformat(self.last_seen)
                static_ts = datetime.fromisoformat(ts)
                if static_ts > current_last:
                    self.last_seen = ts
            except ValueError:
                pass

        if ip:
            self.ip = ip

        self.active = False


class Tracker:
    def __init__(self) -> None:
        self.active_leases = {}
        self.active_sessions = {}
        self.devices = {}

    def update_connections(self, current_connections: list) -> list:
        now = datetime.now().isoformat()
        current_keys = set()
        new_or_updated = []

        for c in current_connections:
            key = (c["source"], c["source_port"],
                   c["destination"], c["destination_port"])
            current_keys.add(key)

            if key not in self.active_sessions:
                sess = Session(
                    c["source"], c["source_port"], c["destination"], c["destination_port"],
                    start_time=now,
                    bytes=c.get("bytes", 0),
                    packets=c.get("packets", 0),
                    protocol=c["protocol"],
                    end_time=None
                )
                self.active_sessions[key] = sess
                new_or_updated.append(sess)
            else:
                sess = self.active_sessions[key]
                sess.bytes = c.get("bytes", sess.bytes)
                sess.packets = c.get("packets", sess.packets)
                sess.active = True
                sess.end_time = None
                new_or_updated.append(sess)

        ended = []
        for key, sess in list(self.active_sessions.items()):
            if key not in current_keys:
                sess.active = False
                sess.end_time = now
                ended.append(sess)
                del self.active_sessions[key]

        return new_or_updated, ended

    def update_leases(self, leases: list) -> list:
        now_dt = datetime.now()
        now = now_dt.isoformat()

        def lease_key(l):
            return (l["mac"], l["ip"])

        current_keys = {lease_key(l) for l in leases}
        new_or_updated = []
        ended = []

        for l in leases:
            key = lease_key(l)
            prev = self.active_leases.get(key)

            if prev is None:
                lease = {**l, "end_time": None, "active": True}
                self.active_leases[key] = lease
                new_or_updated.append(lease)

            else:
                prev_exp = prev.get("expires")
                new_exp = l.get("expires")
                if prev_exp and new_exp:
                    try:
                        prev_dt = datetime.fromisoformat(prev_exp)
                        new_dt = datetime.fromisoformat(new_exp)
                    except ValueError:
                        prev_dt = new_dt = None
                else:
                    prev_dt = new_dt = None

                # Always refresh expiry when it moves forward significantly
                if prev_dt and new_dt and new_dt > prev_dt + timedelta(seconds=5):
                    lease = {**l, "end_time": None, "active": True}
                    self.active_leases[key] = lease
                    new_or_updated.append(lease)
                # Only update for countdown if drift is meaningful
                elif prev_dt and new_dt and prev_dt - new_dt >= timedelta(seconds=20):
                    lease = {**prev, "expires": new_exp, "end_time": None, "active": True}
                    self.active_leases[key] = lease
                    new_or_updated.append(lease)

        grace = timedelta(minutes=2)
        for key, prev in list(self.active_leases.items()):
            if key in current_keys:
                continue
            expires_at = prev.get("expires")
            if expires_at:
                try:
                    expires_dt = datetime.fromisoformat(expires_at)
                except ValueError:
                    expires_dt = None
            else:
                expires_dt = None

            if expires_dt and now_dt < expires_dt + grace:
                continue

            ended_lease = {
                **prev,
                "end_time": now,
                "active": False
            }
            ended.append(ended_lease)
            del self.active_leases[key]

        return new_or_updated, ended

    def update_devices(self, leases: list, statics: list) -> None:
        for device in self.devices.values():
            device.set_inactive()

        lease_macs = {lease["mac"] for lease in leases}

        for lease in leases:
            mac = lease["mac"]
            if mac not in self.devices:
                self.devices[mac] = Device(mac)

            self.devices[mac].set_active(lease)

        for static in statics:
            mac = static["mac"]
            if mac in lease_macs:
                continue

            if mac not in self.devices:
                self.devices[mac] = Device(mac)

            static_snapshot = {
                "ts": static.get("ts") or datetime.now().isoformat(),
                "ip": static.get("ip"),
            }
            self.devices[mac].update_static(static_snapshot)

    def get_all_devices(self) -> list:
        return list(self.devices.values())
