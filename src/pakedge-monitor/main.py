import os
import sys
import yaml
import time
import threading
import socket
from datetime import datetime, timedelta
from pathlib import Path
from normalizer import normalize_connections, normalize_leases, normalize_static
from scraper import RouterScraper
from tracker import Tracker
from detector import Detector
from storage import Storage


def console(storage: Storage) -> None:
    print("Type 'help' for a list of commands")
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
                print(f"\nActive leases:\n")
                for hostname, ip, mac, expires in leases:
                    if hostname is None:
                        hostname = "Unknown"
                    print(f"  {hostname} | {ip} | {mac} | {expires}")
                print()
                continue

            elif cmd == "devices":
                devices = storage.get_devices()
                if not devices:
                    print("\nNo devices\n")
                    continue
                print(f"\nAll devices:\n")
                for hostname, ip, mac in devices:
                    if hostname is None:
                        hostname = "Unknown"
                    print(f"  {hostname} | {ip} | {mac}")
                print()
                continue

            elif cmd == "alerts":
                alerts = storage.get_alerts()
                if not alerts:
                    print("\nNo alerts\n")
                    continue
                print(f"\nAlerts:\n")
                for type, source, mac in alerts:
                    print(f"  {type} | {source} | {mac}")
                print()
                continue

            elif cmd.startswith("connections "):
                parts = cmd.split()
                source_ip = parts[1]
                rows = storage.get_active_connections_from_ip(source_ip)
                if not rows:
                    print(f"\nNo active connections from {source_ip}\n")
                    continue
                print(f"\nActive connections from {source_ip}:\n")
                for dest, port, start_time, protocol in rows:
                    try:
                        hostname = socket.gethostbyaddr(dest)[0]
                    except Exception:
                        hostname = "Unknown"
                    print(
                        f"  {dest}:{port} | {hostname} | {start_time} | {protocol}")
                print()
                continue

            elif cmd.startswith("select "):
                sql = cmd[7:]
                try:
                    rows = storage.query_select("SELECT " + sql)
                    for r in rows:
                        print(r)
                except Exception as e:
                    print("Query error:", e)
                continue

            elif cmd == "help":
                print("\nCommands:")
                print("  alerts")
                print("  devices")
                print("  leases")
                print("  connections <source_ip>")
                print("  schema")
                print("  SELECT <columns> FROM <table> WHERE <condition>")
                print("\nExit with Ctrl+C\n")
                continue

            else:
                print("Unknown command. Type 'help'.")

        except Exception as e:
            print("Console error:", e)


def main() -> None:

    BASE_DIR = Path(__file__).resolve().parent
    CONFIG_PATH = BASE_DIR / "config.yaml"
    DATABASE_PATH = BASE_DIR / "network.db"

    last_mtime = os.path.getmtime(CONFIG_PATH)

    with open(CONFIG_PATH) as f:
        config = yaml.load(f, Loader=yaml.FullLoader)

    router_url = config["router_url"]
    router_ui_username = os.environ.get("PAKEDGE_USER")
    router_ui_password = os.environ.get("PAKEDGE_PASS")
    alert_interval = config["alert_detection_interval_seconds"]
    db_update_interval = config["database_update_interval_seconds"]
    targets = [tuple(t) for t in config["targets"]]
    scan_alerts_on = config["alert_on_connect_scans"]
    new_mac_alerts_on = config["alert_on_new_devices"]

    pakedge = RouterScraper(router_url, router_ui_username, router_ui_password)
    tracker = Tracker()
    detector = Detector()
    storage = Storage(DATABASE_PATH)

    next_cleanup = datetime.now() + timedelta(days=1)
    last_update = 0

    try:
        pakedge.login()
        pakedge.parse_cookies()

        # Only run console if stdin is a TTY
        if sys.stdin is not None and sys.stdin.isatty():
            threading.Thread(target=console, args=(storage,), daemon=True).start()
        else:
            print("No TTY, console disabled.")

        while True:
            # Update config variables if config.yaml is modified
            mtime = os.path.getmtime(CONFIG_PATH)
            if mtime != last_mtime:
                with open(CONFIG_PATH) as f:
                    config = yaml.load(f, Loader=yaml.FullLoader)
                alert_interval = config["alert_detection_interval_seconds"]
                db_update_interval = config["database_update_interval_seconds"]
                targets = [tuple(t) for t in config["targets"]]
                scan_alerts_on = config["alert_on_connect_scans"]
                new_mac_alerts_on = config["alert_on_new_devices"]
                last_mtime = mtime

            try:
                scraped_leases = pakedge.scrape_leases()
                static_devices = pakedge.scrape_static_devices()
                scraped_connections = pakedge.scrape_connections()

                if not scraped_connections and not scraped_leases and not static_devices:
                    raise ValueError("Scrape failed")
            except Exception:
                try:
                    pakedge.login()
                    pakedge.parse_cookies()

                    scraped_leases = pakedge.scrape_leases()
                    scraped_connections = pakedge.scrape_connections()
                    static_devices = pakedge.scrape_static_devices()
                except Exception:
                    time.sleep(alert_interval)
                    continue

            connections = normalize_connections(scraped_connections)
            statics = normalize_static(static_devices)
            leases = normalize_leases(scraped_leases)

            if scan_alerts_on:
                scans = detector.connect_scans(
                    connections, targets, min_distinct_targets=2)
                storage.insert_alerts(scans)
            if new_mac_alerts_on:
                new_macs = detector.new_macs(leases, statics)
                storage.insert_alerts(new_macs)

            # Only update database if db_update_interval seconds have passed
            now = time.time()
            if now - last_update >= db_update_interval:

                leases_new_or_updated, leases_ended = tracker.update_leases(
                    leases)
                connections_new_or_updated, connections_ended = tracker.update_connections(
                    connections)
                tracker.update_devices(leases, statics)

                storage.insert_leases(leases_new_or_updated)
                storage.insert_leases(leases_ended)
                storage.insert_connections(connections_new_or_updated)
                storage.insert_connections(connections_ended)
                for device in tracker.get_all_devices():
                    storage.upsert_devices(
                        mac=device.mac,
                        ip=device.ip,
                        hostname=device.hostname,
                        first_seen=device.first_seen,
                        last_seen=device.last_seen,
                        active=device.active,
                    )
                last_update = time.time()

            if datetime.now() >= next_cleanup:
                storage.cleanup_connections(days=9)
                next_cleanup = datetime.now() + timedelta(days=1)

            time.sleep(alert_interval)
    except KeyboardInterrupt:
        print("\nQuit")
    finally:
        storage.close_connection()


if __name__ == "__main__":
    main()
