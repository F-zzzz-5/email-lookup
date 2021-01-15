import requests

from ctypes import windll
from termcolor import cprint
from colorama import init
from hashlib import sha1
from re import findall

class Application:
    def __init__(self, title):
        self.title = title
        self.colours = {"success": "green", "system": "yellow", "information": "blue"}
        windll.kernel32.SetConsoleTitleW(title)
        init()

    @staticmethod
    def Error(**kwargz):
        cprint("\n".join([f"[ {k.upper()} ]: {v}" for k,v in kwargz.items()]), "red")

    def Message(self, ctype, data):
        cprint(data, self.colours.get(ctype))

class Firefox:
    def __init__(self, application):
        self.App = application
        self.session = requests.Session()
        self.page = self.session.get("https://monitor.firefox.com/", headers={"User-Agent": "Firefox"})
        self.page_text = self.page.text
        self.SID_COOKIE = self.page.cookies.get("connect.sid")

    def CSRFToken(self):
        if "_csrf" in self.page_text:
            csrf_matches = findall("\"[a-zA-Z0-9_-]{36}\"", self.page_text)
            if len(csrf_matches) > 0:
                return csrf_matches[0][1:len(csrf_matches[0])-1]
            else:
                return self.App.Error(error="No CSRF token could be obtained.")
        return self.App.Error(error="Page did not contain CSRF token.")

class Lookup(Firefox):
    def __init__(self, app, email):
        super().__init__(app)

        self.raw_email = email
        self.hash_email = sha1(email.encode()).hexdigest()

    def Execute(self):
        lookup_request = self.session.post("https://monitor.firefox.com/scan", headers={
            "Cookies": f"connect.sid={self.SID_COOKIE}",
            "Content-Type": "application/x-www-form-urlencoded",
        }, data={
            "_csrf": self.CSRFToken(),
            "emailHash": self.hash_email,
        })

        if lookup_request.status_code == 200:
            found_breaches = findall("breach-details/[\w]*", lookup_request.text)
            if len(found_breaches) > 0:
                sites = [breach.split("/")[1] for breach in found_breaches]
                for site in sites:
                    self.App.Message("success", site)
                self.App.Message("system", f"FOUND {len(sites)} RESULTS.")
            else:
                self.App.Message("information", "FOUND NO RESULTS.")
        else:
            return self.App.Error(error=f"RESPONSE CODE {lookup_request.status_code}")

App = Application("monitor.firefox.com | Email-Lookup")

while True:
    Lookup(App, input("Email: ").strip().lower()).Execute()