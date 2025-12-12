import os
import yaml
import time
from datetime import datetime, timedelta
from normalizer import normalize_connections, normalize_leases, normalize_static
from scraper import RouterScraper
from tracker import Tracker
from detector import Detector
from storage import Storage
from app_paths import config_path, database_path


def main() -> None:

    CONFIG_PATH = config_path()
    DATABASE_PATH = database_path()

    last_mtime = os.path.getmtime(CONFIG_PATH)

    with open(CONFIG_PATH) as f:
        config = yaml.load(f, Loader=yaml.FullLoader)

    router_url = config["router_url"]
    router_ui_username = os.environ.get("PAKEDGE_USER")
    router_ui_password = os.environ.get("PAKEDGE_PASS")
    alert_interval = config["alert_detection_interval_seconds"]
    db_update_interval = config["database_update_interval_seconds"]
    scan_targets = [tuple(t) for t in config["targets"]]
    scan_alerts_on = config["alert_on_network_scans"]
    new_mac_alerts_on = config["alert_on_new_devices"]

    pakedge = RouterScraper(router_url, router_ui_username, router_ui_password)
    tracker = Tracker()
    detector = Detector()
    storage = Storage(str(DATABASE_PATH))

    next_cleanup = datetime.now() + timedelta(days=1)
    last_update = 0

    try:
        pakedge.login()
        pakedge.parse_cookies()

        while True:
            # Update config variables if config.yaml is modified
            mtime = os.path.getmtime(CONFIG_PATH)
            if mtime != last_mtime:
                with open(CONFIG_PATH) as f:
                    config = yaml.load(f, Loader=yaml.FullLoader)
                alert_interval = config["alert_detection_interval_seconds"]
                db_update_interval = config["database_update_interval_seconds"]
                scan_targets = [tuple(t) for t in config["targets"]]
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
                    connections, scan_targets, min_distinct_targets=2)
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
        storage.set_all_inactive("leases")
        storage.set_all_inactive("connections")

        storage.close_connection()


if __name__ == "__main__":
    main()
