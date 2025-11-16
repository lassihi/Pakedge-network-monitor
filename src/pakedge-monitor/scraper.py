import requests
import re
from bs4 import BeautifulSoup


class RouterScraper:
    def __init__(self, base_url: str, username: str, password: str) -> None:
        self.base_url = base_url
        self.username = username
        self.password = password
        self.session = requests.session()
        self.headers = None
        self.path_cookie = None
        self.auth_cookie = None

    def login(self):
        s = self.session
        url = self.base_url + "/cgi-bin/router?transaction.redirect=1"

        payload = {
            "username": self.username,
            "password": self.password
        }

        headers = {
            "Host": self.base_url,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Origin": self.base_url,
            "Content-Type": "application/x-www-form-urlencoded",
            "Upgrade-Insecure-Requests": "1",
            "User-Agent": "Mozilla/5.0",
            "Referer": url
        }

        self.headers = s.post(url, data=payload, headers=headers).headers

    def parse_cookies(self):
        login_cookie = self.headers.get("Set-Cookie", "")
        match = re.search(r'path=([^;]+;stok=[^;]+)', login_cookie)

        if match:
            self.path_cookie = match.group(1)
        else:
            raise ValueError("Failed to extract path from response headers")

        self.auth_cookie = self.session.cookies.get('sysauth')

    def scrape_leases(self) -> list:

        s = self.session
        url = self.base_url + self.path_cookie + "/admin/status/overview?status=1"

        headers = {
            "Host": self.base_url,
            "Accept": "*/*",
            "Accept-Encoding": "gzip",
            "Accept-Language": "en-US,en;q=0.9",
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "Cookie": "sysauth=" + self.auth_cookie,
            "Pragma": "no-cache",
            "Priority": "u=3, i",
            "User-Agent": "Mozilla/5.0",
        }

        response = s.get(url, headers=headers).json()
        leases = response["leases"]
        return leases

    def scrape_connections(self) -> list:

        s = self.session
        url = self.base_url + self.path_cookie + \
            "/admin/status/realtime/connections_status"

        headers = {
            "Accept": "*/*",
            "Accept-Encoding": "gzip",
            "Accept-Language": "en-US,en;q=0.9",
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "Cookie": "sysauth=" + self.auth_cookie,
            "Pragma": "no-cache",
            "Priority": "u=3, i",
            "User-Agent": "Mozilla/5.0",
        }

        response = s.get(url, headers=headers).json()
        connections = response["connections"]
        return connections

    def scrape_static_devices(self):

        s = self.session
        url = self.base_url + self.path_cookie + "/admin/status/overview"

        headers = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "Cookie": "sysauth=" + self.auth_cookie,
            "Pragma": "no-cache",
            "Priority": "u=3, i",
            "User-Agent": "Mozilla/5.0",
        }

        response = s.get(url, headers=headers).text
        soup = BeautifulSoup(response, "html.parser")
        records = soup.find_all("td")

        i = -1
        devices = []
        for record in records:
            if i > -1 and i % 3 == 0 and record.text == "LAN":
                ip = str(records[i+2].text)
                mac = str(records[i+3].text)
                devices.append({
                    "mac": mac,
                    "ip": ip
                })
            i += 1
        return devices
