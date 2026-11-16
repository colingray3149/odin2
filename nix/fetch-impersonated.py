#!/usr/bin/env python3
"""odin-fetch-impersonated <url>: the page as Chrome asks for it (its TLS and HTTP/2 fingerprint,
via curl_cffi), for a site that refuses a plain client. Prints "<status> <final url>" on the first
line, then the body. Exit 0 for a 2xx page, 67 when the site refused or challenged it, 66 for any
other status, 1 when it could not be fetched. Every hop must resolve to public addresses."""
import ipaddress
import re
import socket
import sys
from urllib.parse import urljoin, urlsplit

from curl_cffi import requests

MAX_BYTES = 8 << 20
TIMEOUT = 12
HOPS = 8
REFUSED = {401, 403, 407, 429, 451, 503}
CHALLENGE = re.compile(rb"cf-challenge|cf-browser-verification|challenge-platform|just a moment|"
                       rb"attention required|verify you are human|captcha-delivery|px-captcha", re.I)


def public(url):
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return False
    try:
        addresses = {info[4][0] for info in socket.getaddrinfo(parts.hostname, None)}
    except OSError:
        return False
    return bool(addresses) and all(ipaddress.ip_address(a.split("%")[0]).is_global for a in addresses)


def main():
    url = sys.argv[1]
    for _ in range(HOPS):
        if not public(url):
            print(f"{url} does not resolve to public addresses", file=sys.stderr)
            return 1
        response = requests.get(url, impersonate="chrome", timeout=TIMEOUT, allow_redirects=False,
                                stream=True)
        if response.status_code in (301, 302, 303, 307, 308) and response.headers.get("location"):
            url = urljoin(url, response.headers["location"])
            continue
        body = b""
        for chunk in response.iter_content():
            body += chunk
            if len(body) > MAX_BYTES:
                print("the page is larger than 8 MiB", file=sys.stderr)
                return 1
        sys.stdout.buffer.write(f"{response.status_code} {url}\n".encode() + body)
        if response.status_code in REFUSED or CHALLENGE.search(body[:200_000]):
            return 67
        return 0 if 200 <= response.status_code < 300 else 66
    print("too many redirects", file=sys.stderr)
    return 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as error:  # the bridge reads only the exit code and stdout
        print(f"fetch failed: {error}", file=sys.stderr)
        sys.exit(1)
