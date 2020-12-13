#!/usr/bin/env python
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.ssl_ import create_urllib3_context
from hashlib import sha256
import contextlib
import requests
import argparse
import sqlite3
import socket
import ssl
import os


def upgrade(host, port, username, password, filename, trustdb=None):
    cert = get_server_cert(host, port, trustdb)

    session = requests.Session()
    session.verify = False  # SelfSignedAdapter should take care of that for us
    session.mount('https://', SelfSignedAdapter(cert))

    base_url = 'https://%s:%d' % (host, port)
    r = session.get(base_url)
    print(r)


def get_server_cert(host, port, trustdb=None):
    if not trustdb:
        trustdb = os.getenv("IDRAC_TRUSTDB")
    if not trustdb:
        trustdb = os.path.join(os.getenv("HOME"), ".idrac_trustdb")

    with contextlib.closing(sqlite3.connect(trustdb)) as con:
        cur = con.cursor()
        cur.execute(
            "CREATE TABLE IF NOT EXISTS certs (host TEXT PRIMARY KEY, cert BLOB)")
        
        cur.execute("SELECT cert FROM certs WHERE host = ?", (host, ))
        row = cur.fetchone()
        if row:
            return row[0]

        sock = socket.socket()
        client = ssl.wrap_socket(sock)
        client.connect((host, port))
        cert = client.getpeercert(binary_form=True)
        cur.execute(
            "INSERT INTO certs (host, cert) VALUES (?, ?)", (host, cert))
        con.commit()
        return cert


class SelfSignedAdapter(HTTPAdapter):
    def __init__(self, cert):
        self.cert = cert
        super().__init__()

    def init_poolmanager(self, *args, **kwargs):
        kwargs['assert_fingerprint'] = sha256(self.cert).hexdigest()
        return super().init_poolmanager(*args, **kwargs)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--username", help="iDRAC username")
    parser.add_argument("--password", help="iDRAC password")
    parser.add_argument("--trustdb", help="db containing host certificates")
    parser.add_argument("--port", default=443, type=int)
    parser.add_argument("host", help="iDRAC host")
    parser.add_argument("filename", help="upgrade to apply")
    args = parser.parse_args()

    if not args.username:
        args.username = os.getenv("IDRAC_USERNAME")
    if not args.password:
        args.password = os.getenv("IDRAC_PASSWORD")

    upgrade(args.host, args.port, args.username, args.password,
            args.filename, trustdb=args.trustdb)


if __name__ == "__main__":
    main()
