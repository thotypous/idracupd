#!/usr/bin/env python
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.ssl_ import create_urllib3_context
from requests_toolbelt import MultipartEncoder, MultipartEncoderMonitor
from requests_toolbelt.adapters.fingerprint import FingerprintAdapter
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


def upgrade(host, port, username, password, filenames, trustdb=None):
    cert = get_server_cert(host, port, trustdb)
    fingerprint = sha256(cert).hexdigest()

    session = requests.Session()
    # self-signed verification fails, count on FingerprintAdapter for validation
    session.verify = False
    session.mount('https://', FingerprintAdapter(fingerprint))

    session.headers.update(
        {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:85.0) Gecko/20100101 Firefox/85.0'})

    base_url = 'https://%s:%d' % (host, port)

    r = session.get(
        base_url + '/session?aimGetProp=hostname,gui_str_title_bar,OEMHostName,fwVersion,sysDesc')
    r.raise_for_status()
    print(host, r.json()['aimGetProp']['hostname'])

    try:
        for retry in range(3):
            login_url = base_url + '/login.html'
            r = session.get(login_url)
            r.raise_for_status()
            session.post(base_url + '/data/logout')

            r = session.post(base_url + '/data/login',
                             data={'user': username, 'password': password},
                             headers={'Referer': login_url})
            r.raise_for_status()

            if '<authResult>0</authResult>' in r.text:
                break
            elif '<authResult>1</authResult>' in r.text:
                blockingTime, = re.search(
                    r'<blockingTime>(\d+)</blockingTime>', r.text).groups()
                blockingTime = int(blockingTime)
                if blockingTime == 0:
                    raise RuntimeError('Incorrect username or password')
                print('login blocked, waiting %d seconds' %
                      blockingTime, file=sys.stderr)
                time.sleep(blockingTime)
            else:
                raise RuntimeError('Login failure: ' + r.text)
        else:
            raise RuntimeError('Login retries exceeded')

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

        for filename in filenames:
            print(filename, file=sys.stderr)
            e = MultipartEncoder(fields={
                'firmwareUpdate': (
                    os.path.basename(filename),
                    open(filename, 'rb'),
                    'application/x-ms-dos-executable'
                )
            })
            m = MultipartEncoderMonitor(e, status_callback)
            r = session.post(base_url + scratch_pad,
                             params={'ST1': st1},
                             data=m,
                             headers={'Content-Type': m.content_type})
            print(file=sys.stderr)
            r.raise_for_status()

        # response is cumulative, and contains all files sent until now
        targets = [m.group(1) for m in re.finditer(r'target="(.*?)"', r.text)]

        xml = '<Repository><target>%s</target><rebootType>1</rebootType></Repository>' % ','.join(
            target for target in targets if target != '')
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


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--username", help="iDRAC username")
    parser.add_argument("--password", help="iDRAC password")
    parser.add_argument("--trustdb", help="db containing host certificates")
    parser.add_argument("--port", default=443, type=int)
    parser.add_argument("host", help="iDRAC host")
    parser.add_argument("filename", help="upgrade(s) to apply", nargs='+')
    args = parser.parse_args()

    if not args.username:
        args.username = os.getenv("IDRAC_USERNAME")
    if not args.password:
        args.password = os.getenv("IDRAC_PASSWORD")

    upgrade(args.host, args.port, args.username, args.password,
            args.filename, trustdb=args.trustdb)


if __name__ == "__main__":
    main()
