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
                sess.packets = c.get("packets", sess.bytes)
                sess.active = True
                sess.end_time = None
                new_or_updated.append(sess)

        ended = []
        for key, sess in list(self.active_sessions.items()):
            if key not in current_keys:
                sess = self.active_sessions[key]
                sess.active = False
                sess.end_time = now
                ended.append(sess)
                del self.active_sessions[key]

        return new_or_updated, ended

    def update_leases(self, leases: list) -> list:
        now = datetime.now().isoformat()

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
            elif l.get("expires") != prev.get("expires"):
                difference = abs(datetime.fromisoformat(
                    l.get("expires")) - datetime.fromisoformat(prev.get("expires")))
                if difference >= timedelta(seconds=60):
                    ended.append({**prev, "active": False,"end_time": now})
                    lease = {**l, "end_time": None, "active": True}
                    self.active_leases[key] = lease
                    new_or_updated.append(lease)

        for mac, prev in list(self.active_leases.items()):
            if mac not in current_keys:
                ended_lease = {
                    **prev,
                    "active": False,
                    "end_time": now
                }
                ended.append(ended_lease)
                del self.active_leases[key]

        return new_or_updated, ended

    def update_devices(self, leases: list, statics: list) -> None:
        for device in self.devices.values():
            device.set_inactive()

        for lease in leases:
            mac = lease["mac"]
            if mac not in self.devices:
                self.devices[mac] = Device(mac)

            self.devices[mac].set_active(lease)

        for static in statics:
            mac = static["mac"]
            if mac not in self.devices:
                self.devices[mac] = Device(mac)

    def get_all_devices(self) -> list:
        return list(self.devices.values())
