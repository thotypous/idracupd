#!/usr/bin/env python
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.ssl_ import create_urllib3_context
from requests_toolbelt import MultipartEncoder, MultipartEncoderMonitor
from hashlib import sha256
import contextlib
import requests
import argparse
import sqlite3
import socket
import time
import ssl
import sys
import os
import re


def upgrade(host, port, username, password, filename, trustdb=None):
    cert = get_server_cert(host, port, trustdb)

    session = requests.Session()
    session.verify = False  # SelfSignedAdapter should take care of that for us
    session.mount('https://', SelfSignedAdapter(cert))

    base_url = 'https://%s:%d' % (host, port)

    try:
        while True:
            r = session.post(base_url + '/data/login',
                             data={'user': username, 'password': password})
            r.raise_for_status()

            if '<authResult>0</authResult>' in r.text:
                break

            if not '<authResult>1</authResult>' in r.text:
                raise RuntimeError('Incorrect username or password')
            blockingTime, = re.search(
                r'<blockingTime>(\d+)</blockingTime>', r.text).groups()
            blockingTime = int(blockingTime)

            sys.stderr.write('login blocked, waiting %d seconds\n' % blockingTime)
            time.sleep(blockingTime)

        st1, st2 = re.search(
            r'ST1=([0-9a-f]+),ST2=([0-9a-f]+)', r.text).groups()

        r = session.get(base_url + '/cemgui/fwupdate.html')
        r.raise_for_status()
        scratch_pad, = re.search(
            r'dupScratchPadURI = "(.*?)"', r.text).groups()
        apply_path, = re.search(r'applyURI = "(.*?)"', r.text).groups()

        # a GET with side-effects, oh my
        r = session.get(base_url + scratch_pad + '?splock=1')
        r.raise_for_status()

        e = MultipartEncoder(fields={
            'firmwareUpdate': (
                os.path.basename(filename),
                open(filename, 'rb'),
                'application/x-ms-dos-executable'
            )
        })
        m = MultipartEncoderMonitor(e, status_callback)
        r = session.post(base_url + scratch_pad + '?ST1=' + st1,
                         data=m,
                         headers={'Content-Type': m.content_type})
        sys.stderr.write('\n')
        r.raise_for_status()
        target, = re.search(r'target="(.*?)"', r.text).groups()

        xml = '<Repository><target>%s</target><rebootType>1</rebootType></Repository>' % target
        r = session.put(base_url + apply_path, data=xml, headers={'ST2': st2})
        r.raise_for_status()
    finally:
        session.get(base_url + '/data/logout')


def status_callback(monitor):
    sys.stderr.write('\r%6.2f%%' % (100. * monitor.bytes_read / monitor.len))
    sys.stderr.flush()


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
