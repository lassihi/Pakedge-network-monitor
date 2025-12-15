import socket
import sys
from storage import Storage
from app_paths import database_path

def print_alerts(storage: Storage, only_unchecked: bool = False) -> None:
    if only_unchecked:
        alerts = storage.get_unchecked_alerts()
        if not alerts:
            print("\nNo unchecked alerts\n")
            return
    else:
        alerts = storage.get_alerts()
        if not alerts:
            print("\nNo alerts\n")
            return
        
    print("\nAlerts:\n")
    display_rows = []
    for id, alert_type, source_ip, details, when in alerts:
        mac_display = "Unknown"
        hostname_display = None
        source_device = None

        if source_ip and when:
            source_device = storage.get_device_for_ip(
                source_ip, when)
            if source_device:
                if source_device.get("mac"):
                    mac_display = source_device["mac"]
                hostname_display = source_device.get("hostname")

        if alert_type == "new_mac_address":
            origin = details[0]
            mac_display = details[1]

            if origin == "lease":
                lease_hostname = details[2]
                hostname_display = lease_hostname
            elif origin == "static_device":
                if not hostname_display:
                    hostname_display = "Unknown (static)"
            else:
                if not hostname_display:
                    hostname_display = "Unknown"
        else:
            if not source_device or not source_device.get("mac"):
                mac_display = "Unknown"
            if not hostname_display:
                hostname_display = "Unknown"

        display_rows.append(
            (
                id,
                alert_type,
                source_ip,
                when,
                mac_display,
                hostname_display,
            )
        )

    id_w = max(len(str(row[0])) for row in display_rows)
    id_w = max(id_w, len("ID"))
    type_w = max(len(row[1]) for row in display_rows)
    type_w = max(type_w, len("TYPE"))
    src_w = max(len(row[2]) for row in display_rows)
    src_w = max(src_w, len("SOURCE"))
    print(
        f"  {'ID':<{id_w}}  {'TYPE':<{type_w}}  {'SOURCE':<{src_w}}  {'TIME':<26}  {'MAC':<17}  HOSTNAME")
    for row in display_rows:
        alert_id, alert_type, source_ip, when, mac_display, hostname_display = row
        print(
            f"  {alert_id:<{id_w}}  {alert_type:<{type_w}}  {source_ip:<{src_w}}  {when}  {mac_display}  {hostname_display}")
    print()

def run_console(storage: Storage) -> None:
    print("Type 'help' for a list of commands\n")
    while True:
        try:
            cmd = input("> ").strip().lower()

            if cmd == "schema":
                schema = storage.get_schema()
                print("\nDatabase Schema:\n")
                for table_name, columns in schema:
                    print(f"{table_name}:")
                    for col in columns:
                        _, name, col_type, *_ = col
                        print(f"  {name} ({col_type})")
                    print()
                continue

            elif cmd == "leases":
                leases = storage.get_leases()
                if not leases:
                    print("\nNo active leases\n")
                    continue
                print("\nActive leases:\n")
                host_w = max((len(r[0]) for r in leases))
                host_w = max(host_w, len("HOSTNAME"))
                ip_w = max(len(r[1]) for r in leases)
                ip_w = max(ip_w, len("IP"))
                mac_w = max(len(r[2]) for r in leases)
                mac_w = max(mac_w, len("MAC"))
                print(
                    f"  {'HOSTNAME':<{host_w}}  {'IP':<{ip_w}}  {'MAC':<{mac_w}}  EXPIRES")
                for hostname, ip, mac, expires in leases:
                    hostname = hostname or "Unknown"
                    print(
                        f"  {hostname:<{host_w}}  {ip:<{ip_w}}  {mac:<{mac_w}}  {expires}")
                print()
                continue

            elif cmd == "devices":
                devices = storage.get_devices()
                if not devices:
                    print("\nNo devices\n")
                    continue

                print("\nAll devices:\n")
                processed = []
                for hostname, ip, mac, active_value, _, _ in devices:
                    display_hostname = hostname

                    if not display_hostname:
                        try:
                            # Current data, resolve from DNS
                            display_hostname = socket.gethostbyaddr(ip)[0]
                        except Exception:
                            display_hostname = "Unknown"
                    processed.append((display_hostname, ip, mac, active_value))

                host_w = max((len(row[0]) for row in processed))
                host_w = max(host_w, len("HOSTNAME"))
                ip_w = max(len(row[1]) for row in processed)
                ip_w = max(ip_w, len("IP"))
                mac_w = max(len(row[2]) for row in processed)
                mac_w = max(mac_w, len("MAC"))
                print(
                    f"  {'HOSTNAME':<{host_w}}  {'IP':<{ip_w}}  {'MAC':<{mac_w}}  {'ACTIVE'}")
                for display_hostname, ip, mac, active_value in processed:
                    active = "True" if active_value == "1" else "False"
                    print(
                        f"  {display_hostname:<{host_w}}  {ip:<{ip_w}}  {mac:<{mac_w}}  {active}")
                print()
                continue

            elif cmd == "alerts":
                print_alerts(storage, only_unchecked=True)

            elif cmd == "alerts all":
                print_alerts(storage, only_unchecked=False)

            elif cmd.startswith("alerts check "):
                parts = cmd.split()
                if len(parts) == 3 and parts[2].isdigit():
                    alert_id = int(parts[2])
                    storage.mark_alert_as_checked(alert_id)
                    print(f"\nAlert {alert_id} marked as checked\n")
                else:
                    print("\nUse: alerts check <alert_id>\n")
                continue

            elif cmd.startswith("connections "):
                parts = cmd.split()
                ip = parts[1]
                rows_from = storage.get_active_connections_from_ip(ip)
                rows_to = storage.get_active_connections_to_ip(ip)

                if not rows_from and not rows_to:
                    print(f"\nNo active connections FROM or TO {ip}\n")
                    continue

                if rows_from:
                    print(f"\nActive connections FROM {ip}:\n")
                    dests = [f"{r[0]}:{r[1]}" for r in rows_from]
                    dest_w = max(len(d) for d in dests)
                    hostnames = []
                    for dest_ip, _, start_time, _ in rows_from:
                        hostname = None
                        if start_time:
                            device_info = storage.get_device_for_ip(
                                dest_ip, start_time)
                            if device_info:
                                hostname = device_info.get("hostname")
                        if not hostname:
                            try:
                                hostname = socket.gethostbyaddr(dest_ip)[0]
                            except Exception:
                                hostname = "Unknown"
                        hostnames.append(hostname)
                    host_w = max(len(h) for h in hostnames)
                    host_w = max(host_w, len("HOSTNAME"))
                    print(
                        f"  {'DESTINATION':<{dest_w}}  {'HOSTNAME':<{host_w}}  {'START_TIME':<26}  PROTOCOL")
                    for (dest, port, start_time, protocol), hostname in zip(rows_from, hostnames):
                        dest_text = f"{dest}:{port}"
                        print(
                            f"  {dest_text:<{dest_w}}  {hostname:<{host_w}}  {start_time}  {protocol.upper()}")
                    print()
                else:
                    print(f"\nNo active connections FROM {ip}\n")

                if rows_to:
                    print(f"Active connections TO {ip}:\n")
                    sources = [f"{r[0]}:{r[1]}" for r in rows_to]
                    source_w = max(len(s) for s in sources)
                    hostnames = []
                    for source_ip, _, start_time, _ in rows_to:
                        hostname = None
                        if start_time:
                            device_info = storage.get_device_for_ip(
                                source_ip, start_time)
                            if device_info:
                                hostname = device_info.get("hostname")
                        if not hostname:
                            try:
                                hostname = socket.gethostbyaddr(source_ip)[0]
                            except Exception:
                                hostname = "Unknown"
                        hostnames.append(hostname)
                    host_w = max(len(h) for h in hostnames)
                    host_w = max(host_w, len("HOSTNAME"))
                    print(
                        f"  {'SOURCE':<{source_w}}  {'HOSTNAME':<{host_w}}  {'START_TIME':<26}  PROTOCOL")
                    for (source, port, start_time, protocol), hostname in zip(rows_to, hostnames):
                        source_text = f"{source}:{port}"
                        print(
                            f"  {source_text:<{source_w}}  {hostname:<{host_w}}  {start_time}  {protocol.upper()}")
                    print()
                else:
                    print(f"No active connections TO {ip}\n")
                continue

            elif cmd.startswith("select "):
                sql = cmd[7:]
                try:
                    rows = storage.query_select("SELECT " + sql)
                    for r in rows:
                        print(r)
                except Exception as e:
                    print("\nQuery error:", e, "\n")
                continue

            elif cmd == "help":
                print("\nCommands:")
                print("  devices                                          # List all devices")
                print("  leases                                           # List active leases")
                print("  alerts                                           # List unchecked alerts")
                print("  alerts all                                       # List all alerts")
                print("  alerts check <alert_id>                          # Mark alert as checked")
                print("  connections <source_ip>                          # List active connections from/to IP")
                print("  schema                                           # Show database schema")
                print("  SELECT <columns> FROM <table> WHERE <condition>  # Run custom SELECT query")
                print("\nExit with Ctrl+C\n")
                continue

            else:
                print("\nUnknown command. Type 'help'.\n")

        except Exception as e:
            print("\nConsole error:", e, "\n")


def main() -> None:
    db_path = database_path()
    storage = Storage(str(db_path))
    try:
        if sys.stdin is not None and sys.stdin.isatty():
            run_console(storage)
        else:
            print("No TTY, console disabled.")
    except KeyboardInterrupt:
        print("\nQuit")
    finally:
        storage.close_connection()


if __name__ == "__main__":
    main()
