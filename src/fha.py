#!/usr/bin/env python3

#   This program is free software: you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation, either version 3 of the License, or
#   (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program.  If not, see <https://www.gnu.org/licenses/>.

#   fha.py (Forensic HSTS Analyzer)
# © Copyright 2021 Florian Bausch

import json
import sys
import os
import argparse
import datetime
import sqlite3
import hashlib
import base64
import magic
from contextlib import closing
import requests


fx_security_policies = ["unset", "set", "knockout", "negative"]


def parse_firefox(args):
    file = args.file
    check = args.check_hsts
    oc = OnlineChecker()
    uncertainty = str(24 * 60 * 60)
    if not args.no_header:
        header = "domain,accessed_via,type,number_days_with_visit,last_visit,last_visit_human_readable_utc,last_visit_uncertainty,expiry,expiry_human_readable_utc,security_policy,include_subdomains,hpkp_fingerprint"
        if check:
            header += ",actual_hsts"
        print(header)
    with open(file, 'r') as f:
        for line in f:
            pline = parse_firefox_line(line.strip())
            sys.stdout.write(pline["domain"])
            sys.stdout.write(",")
            sys.stdout.write(pline["accessed_via"])
            sys.stdout.write(",")
            sys.stdout.write(pline["type"])
            sys.stdout.write(",")
            sys.stdout.write(str(pline["number_visits"]))
            sys.stdout.write(",")
            sys.stdout.write(str(pline["last_visit"]))
            sys.stdout.write(",")
            sys.stdout.write(utc_timestring(pline["last_visit"]))
            sys.stdout.write(",")
            sys.stdout.write(uncertainty)
            sys.stdout.write(",")
            sys.stdout.write(str(pline["msecs_exp"]))
            sys.stdout.write(",")
            sys.stdout.write(utc_timestring(pline["msecs_exp"]))
            sys.stdout.write(",")
            sys.stdout.write(pline["sec_pol"])
            sys.stdout.write(",")
            sys.stdout.write(str(pline["include_subdom"]).lower())
            sys.stdout.write(",")
            sys.stdout.write(pline["hpkp_fingerprint"])
            if check:
                sys.stdout.write(",")
                sys.stdout.write(oc.online_check(pline["domain"]))
            sys.stdout.write('\n')


def parse_firefox_line(line):
    global fx_security_policies
    chunks = line.split('\t')
    domain_access, typ = chunks[0].split(':')
    try:
        domain, accessed_via = domain_access.split('^')
        accessed_via = accessed_via.replace("partitionKey=%28", "")\
            .replace("%29", "").replace("http%2C", "")
    except ValueError:
        domain = domain_access
        accessed_via = ""
    number_visits = int(chunks[1], 10)
    last_visit_days_since_epoch = int(chunks[2], 10)
    last_visit = last_visit_days_since_epoch * 24 * 60 * 60
    rest = chunks[3].split(",")
    msecs_exp = int(rest[0], 10) / 1000
    sec_pol = fx_security_policies[int(rest[1], 10)]
    include_subdom = rest[2] == "1"
    hpkp_fingerprint = rest[3]
    return {"type": typ,
            "domain": domain,
            "accessed_via": accessed_via,
            "number_visits": number_visits,
            "last_visit": last_visit,
            "msecs_exp": msecs_exp,
            "sec_pol": sec_pol,
            "include_subdom": include_subdom,
            "hpkp_fingerprint": hpkp_fingerprint}


def parse_chrome(args):
    file = args.file
    check = args.check_hsts
    oc = OnlineChecker()
    maps = args.chrome_map
    histories = args.chrome_history
    urlmap = {}
    if histories is None:
        histories = []
    defaultmap = os.path.abspath(os.path.join(
        __file__, '..', '..', 'lists', 'default.map'))
    if maps is None:
        maps = [defaultmap]
    else:
        maps.append(defaultmap)
    for h in histories:
        try:
            load_url_map_from_chrome_history(h, urlmap)
        except sqlite3.OperationalError:
            pass
        try:
            load_url_map_from_firefox_history(h, urlmap)
        except sqlite3.OperationalError:
            pass
    for m in maps:
        load_url_map_from_mapfile(m, urlmap)

    with open(file, 'r') as f:
        fcontent = f.read()
    j = json.loads(fcontent)
    sts = []

    if "version" not in j.keys():
        for enc_domain in j.keys():
            data = j[enc_domain]
            data["host"] = enc_domain
            sts.append(data)
    elif j["version"] == 2:
        sts = j["sts"]
    elif j["version"] != 2:
        print("Error: unsupported version (%d)" % j["version"])
        sys.exit(1)
    if "expect_ct" in j.keys() and len(j["expect_ct"]) > 0:
        print("expect_ct set")

    if not args.no_header:
        header = "domain,encoded_domain,mode,observed,observed_human_readable_utc,expiry,expiry_human_readable_utc,include_subdomains"
        if check:
            header += ",actual_hsts"
        print(header)
    kurls = urlmap.keys()
    for entry in sts:
        if entry["host"] in kurls:
            domain = urlmap[entry["host"]][0]
        else:
            domain = ""
        sys.stdout.write(domain)
        sys.stdout.write(",")
        sys.stdout.write(entry["host"])
        sys.stdout.write(",")
        sys.stdout.write(entry["mode"])
        sys.stdout.write(",")
        sys.stdout.write(str(entry["sts_observed"]))
        sys.stdout.write(",")
        sys.stdout.write(utc_timestring(entry["sts_observed"]))
        sys.stdout.write(",")
        sys.stdout.write(str(entry["expiry"]))
        sys.stdout.write(",")
        sys.stdout.write(utc_timestring(entry["expiry"]))
        sys.stdout.write(",")
        sys.stdout.write(str(entry["sts_include_subdomains"]).lower())
        if check:
            sys.stdout.write(",")
            if len(domain) > 0:
                sys.stdout.write(oc.online_check(domain))
        sys.stdout.write('\n')


def load_url_map_from_chrome_history(history, urlmap):
    if history is None:
        return
    if not os.path.isfile(history):
        print("Error: File does not exist: %s" % history)
        sys.exit(1)
        return
    with closing(sqlite3.connect(history)) as hist, hist, \
            closing(hist.cursor()) as histcur:
        for url in histcur.execute('SELECT url FROM urls'):
            url = url[0].replace("https://", "").replace("http://", "")
            url = url.split('/')[0]
            domain_to_hash(url, urlmap)


def load_url_map_from_firefox_history(history, urlmap):
    if history is None:
        return
    if not os.path.isfile(history):
        print("Error: File does not exist: %s" % history)
        sys.exit(1)
        return
    with closing(sqlite3.connect(history)) as hist, hist, \
            closing(hist.cursor()) as histcur:
        for url in histcur.execute('SELECT host FROM moz_origins'):
            url = url[0]
            domain_to_hash(url, urlmap)


def load_url_map_from_mapfile(mapfile, urlmap):
    if mapfile is None:
        return
    if not os.path.isfile(mapfile):
        print("Error: File does not exist: %s" % mapfile)
        sys.exit(1)
        return
    with open(mapfile, 'r') as f:
        for line in f:
            chunks = line.split(",")
            if len(chunks) < 2:
                continue
            b64 = chunks[0].strip()
            domain = chunks[1].strip()
            if len(b64) != 44:
                continue
            urlmap[b64] = (domain, None)


def domain_to_hash(domain, urlmap):
    split_domain = domain.split('.')
    while len(split_domain) > 0:
        domain_enc = ''
        for c in split_domain:
            domain_enc += chr(len(c))
            domain_enc += c
        domain_enc += chr(0)
        digest = hashlib.sha256(domain_enc.encode()).digest()
        b64 = base64.b64encode(digest).decode('utf-8')
        if b64 in urlmap:
            break
        urlmap[b64] = (".".join(split_domain), domain_enc)
        split_domain = split_domain[1:]


def create_chrome_map(file):
    urlmap = {}
    if magic.from_file(file, mime=True) == 'application/x-sqlite3':
        try:
            load_url_map_from_chrome_history(file, urlmap)
        except sqlite3.OperationalError:
            pass
        try:
            load_url_map_from_firefox_history(file, urlmap)
        except sqlite3.OperationalError:
            pass
    else:
        load_urls_from_text_file(file, urlmap)
    for kurl in urlmap.keys():
        print("%s,%s" % (kurl, urlmap[kurl][0]))


def load_urls_from_text_file(textfile, urlmap):
    if textfile is None:
        return
    if not os.path.isfile(textfile):
        print("Error: File does not exist")
        sys.exit(1)
        return
    with open(textfile, 'r') as f:
        for line in f:
            line = line.strip()
            domain_to_hash(line, urlmap)


def parse_wget(args):
    wgetfile = args.file
    check = args.check_hsts
    oc = OnlineChecker()
    if not args.no_header:
        header = "domain,port,include_subdomains,created,created_human_readable_utc,expiry,expiry_human_readable_utc,max_age,max_age_days"
        if check:
            header += ",actual_hsts"
        print(header)
    with open(wgetfile, 'r') as f:
        for line in f:
            line = line.strip()
            if len(line) == 0 or line[0] == "#":
                continue
            chunks = line.split("\t")
            if len(chunks) != 5:
                continue
            expiry = int(chunks[3], 10) + int(chunks[4], 10)
            domain = chunks[0]
            sys.stdout.write(domain)
            sys.stdout.write(",")
            sys.stdout.write(chunks[1])
            sys.stdout.write(",")
            sys.stdout.write(str(chunks[2] == 1).lower())
            sys.stdout.write(",")
            sys.stdout.write(chunks[3])
            sys.stdout.write(",")
            sys.stdout.write(utc_timestring(int(chunks[3], 10)))
            sys.stdout.write(",")
            sys.stdout.write(str(expiry))
            sys.stdout.write(",")
            sys.stdout.write(utc_timestring(expiry))
            sys.stdout.write(",")
            sys.stdout.write(chunks[4])
            sys.stdout.write(",")
            sys.stdout.write(str(int(chunks[4], 10) / (24 * 60 * 60)))
            if check:
                sys.stdout.write(",")
                sys.stdout.write(oc.online_check(domain))
            sys.stdout.write("\n")


def parse_soup(args):
    soupfile = args.file
    check = args.check_hsts
    oc = OnlineChecker()
    if not args.no_header:
        header = "domain,include_subdomains,created,created_human_readable_utc,expiry,expiry_human_readable_utc,max_age,max_age_days"
        if check:
            header += ",actual_hsts"
        print(header)
    with closing(sqlite3.connect(soupfile)) as hsts, hsts, \
            closing(hsts.cursor()) as hstscur:
        for row in hstscur.execute('SELECT host, max_age, expiry, include_subdomains FROM soup_hsts_policies'):
            created = row[2] - row[1]
            domain = row[0]
            sys.stdout.write(domain)
            sys.stdout.write(",")
            sys.stdout.write(str(row[3] == 1).lower())
            sys.stdout.write(",")
            sys.stdout.write(str(created))
            sys.stdout.write(",")
            sys.stdout.write(utc_timestring(created))
            sys.stdout.write(",")
            sys.stdout.write(str(row[2]))
            sys.stdout.write(",")
            sys.stdout.write(utc_timestring(row[2]))
            sys.stdout.write(",")
            sys.stdout.write(str(row[1]))
            sys.stdout.write(",")
            sys.stdout.write(str(row[1] / (24 * 60 * 60)))
            if check:
                sys.stdout.write(",")
                sys.stdout.write(oc.online_check(domain))
            sys.stdout.write("\n")


def parse_safari(args):
    import plistlib
    plistfile = args.file
    check = args.check_hsts
    oc = OnlineChecker()
    if not args.no_header:
        header = "domain,include_subdomains,created,created_human_readable_utc,expiry,expiry_human_readable_utc"
        if check:
            header += ",actual_hsts"
        print(header)
    with open(plistfile, 'rb') as pf:
        content = plistlib.load(pf)
    schema = content['HSTS Store Schema Version']
    if schema != 3:
        print("Error: Unsupported Schema Version %d" % schema)
    # contentversion = content['HSTS Content Version']
    # signatur = content['HSTS Preload Entries Signature']
    hsts = content['com.apple.CFNetwork.defaultStorageSession']
    # For some reason the timstamps are 11323 days off.
    offset = 60 * 60 * 24 * 11323
    for u in hsts:
        e = hsts[u]
        sys.stdout.write(u)
        sys.stdout.write(',')
        if 'Include Subdomains' in e.keys():
            sys.stdout.write(str(e['Include Subdomains']).lower())
        else:
            sys.stdout.write('false')
        sys.stdout.write(',')
        sys.stdout.write(str(e['Create Time'] + offset))
        sys.stdout.write(',')
        sys.stdout.write(utc_timestring(e['Create Time'] + offset))
        sys.stdout.write(',')
        expiry = str(e['Expiry'])
        if expiry != "inf":
            sys.stdout.write(str(e['Expiry'] + offset))
        sys.stdout.write(',')
        if expiry != "inf":
            sys.stdout.write(utc_timestring(e['Expiry'] + offset))
        if check:
            sys.stdout.write(",")
            if expiry != "inf":
                # we only check domains that were actually visited
                # but not preloaded / unvisited domains
                sys.stdout.write(oc.online_check(u))
        sys.stdout.write('\n')


def parse_curl(args):
    # https://curl.se/libcurl/c/CURLOPT_HSTS.html
    curlfile = args.file
    check = args.check_hsts
    oc = OnlineChecker()
    if not args.no_header:
        header = "domain,include_subdomains,expiry,expiry_human_readable_utc"
        if check:
            header += ",actual_hsts"
        print(header)
    with open(curlfile, 'r') as f:
        for line in f:
            line = line.strip()
            if len(line) == 0 or line[0] == "#":
                continue
            chunks = line.split(" ")
            if len(chunks) != 2:
                continue
            domain = chunks[0]
            if domain[0] == ".":
                subdoms = "true"
                domain = domain[1:]
            else:
                subdoms = "false"
            expiry = datetime.datetime.strptime(
                chunks[1] + " UTC", "%Y%m%d %H:%M:%S %Z")
            sys.stdout.write(domain)
            sys.stdout.write(",")
            sys.stdout.write(subdoms)
            sys.stdout.write(",")
            sys.stdout.write(utc_timestring(expiry.timestamp()))
            if check:
                sys.stdout.write(",")
                sys.stdout.write(oc.online_check(domain))
            sys.stdout.write("\n")


def get_preload_list(file):
    from urllib.request import urlopen
    url = "https://github.com/chromium/chromium/blob/master/net/http/transport_security_state_static.json?raw=true"
    print("Retrieving HSTS preload list from %s." % url)
    content = []
    with urlopen(url) as conn, open(file, 'w') as outfile:
        for line in conn:
            line = line.decode('utf-8').strip()
            if line[0:2] == "//":
                continue
            else:
                content.append(line)
        print("Parsing JSON")
        j = json.loads("\n".join(content))
        content = None
        entries = j["entries"]
        urlmap = {}
        for e in entries:
            domain_to_hash(e["name"], urlmap)
        for kurl in urlmap.keys():
            outfile.write("%s,%s\n" % (kurl, urlmap[kurl][0]))


def utc_timestring(unixts):
    return datetime.datetime.utcfromtimestamp(unixts).isoformat()


class OnlineChecker(object):
    def __init__(self):
        self._checked = {}

    def online_check(self, domain):
        url = "https://%s/" % domain
        if domain not in self._checked:
            try:
                s = requests.Session()
                response = s.head(url,
                                  timeout=30,
                                  allow_redirects=False)
                while response.is_redirect \
                        and response.next.url.startswith(url):
                    response = s.send(response.next,
                                      timeout=30,
                                      allow_redirects=False)
                headers = response.headers
                header = None
                for k in headers.keys():
                    if k.lower() == 'strict-transport-security':
                        header = k
                        break
                if header is not None:
                    self._checked[domain] = \
                        headers[header].replace(",", " -")
                else:
                    self._checked[domain] = ""
            except requests.ConnectionError:
                self._checked[domain] = "ERR:error"
            except requests.exceptions.ReadTimeout:
                self._checked[domain] = "ERR:timeout"
            except requests.exceptions.TooManyRedirects:
                self._checked[domain] = "ERR:too many redirects"
            except requests.exceptions.SSLError:
                self._checked[domain] = "ERR:SSL error"
        return self._checked[domain]


if __name__ == "__main__":
    supported_formats = {"firefox": parse_firefox, "chrome": parse_chrome,
                         "wget": parse_wget, "soup": parse_soup,
                         "safari": parse_safari, "curl": parse_curl}
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--format",
                        help="Tells which format is to be analyzed: %s" %
                        ", ".join(supported_formats.keys()))

    parser.add_argument("-m", "--chrome-map", action='append',
                        help="A file that maps clear-text domains to the hashed Chrome-representation. (See also --create-chrome-map.) Can be used multiple times to provide more than one file.")
    parser.add_argument("-u", "--chrome-history", action='append',
                        help="A Chrome History database or Firefox places.sqlite database that contains URLs to translate into the hashed Chrome-representation. Can be used multiple times to provide more than one file.")

    parser.add_argument("--create-chrome-map", action='store_true',
                        help="Create a mapping (see -m) from clear-text domains to the hashed Chrome-representation. The provided file can be a Chrome History, Firefox places.sqlite, or a simple text file with a newline-separated list of domains. Used without further parameters.")
    parser.add_argument("--get-preload-list", action='store_true',
                        help="Download the HSTS preload list from Chromium's Github repository and translate it into a chrome map.")
    parser.add_argument("--no-header", action='store_true',
                        help="Do not print the CSV header line.")
    parser.add_argument("--check-hsts", action='store_true',
                        help="Connect to every detected domain, retrieve the HSTS header and add it to an \"actual_hsts\" column. Depending on the contents of the HSTS cache, this might cause connections to malicious domains. If multiple HSTS headers are detected, they are separated by \"-\".")

    parser.add_argument("file", help="The file to analyze.")
    args = parser.parse_args()

    if args.create_chrome_map:
        if args.format:
            print("Error: Use --create-chrome-map without other parameters.")
            sys.exit(1)
        create_chrome_map(args.file)
        sys.exit(0)

    if args.get_preload_list:
        if args.format:
            print("Error: Use --get-preload-list without other parameters.")
            sys.exit(1)
        get_preload_list(args.file)
        sys.exit(0)

    if args.format is None:
        print("Error: Please choose an HSTS cache file format.")
        sys.exit(1)
    if args.format not in supported_formats:
        print("Error: Please choose a valid HSTS cache file format.")
        sys.exit(1)
    if not os.path.isfile(args.file):
        print("Error: File does not exist (%s)." % args.file)
        sys.exit(1)

    supported_formats[args.format](args)
