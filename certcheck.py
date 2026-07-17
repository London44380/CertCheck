#!/usr/bin/env python3
"""CertCheck - a small SSL/TLS certificate scanner.

Connects to one or more hosts, retrieves the server's SSL certificate and
prints the useful fields (subject, issuer, validity, SAN list, etc.).

Usage:
    python3 certcheck.py example.com
    python3 certcheck.py example.com:8443 github.com
    python3 certcheck.py -t 4 example.com          # 4s connect timeout
"""

import argparse
import socket
import ssl
import sys
from datetime import datetime, timezone

BANNER = r"""
  ____          _    ____ _               _
 / ___|___ _ __| |_ / ___| |__   ___  ___| | __
| |   / _ \ '__| __| |   | '_ \ / _ \/ __| |/ /
| |__|  __/ |  | |_| |___| | | |  __/ (__|   <
 \____\___|_|   \__|\____|_| |_|\___|\___|_|\_\

        SSL / TLS certificate scanner
"""

# ANSI colours (fall back to plain if not a TTY)
if sys.stdout.isatty():
    C_OK, C_WARN, C_ERR, C_KEY, C_RST = (
        "\033[32m", "\033[33m", "\033[31m", "\033[36m", "\033[0m",
    )
else:
    C_OK = C_WARN = C_ERR = C_KEY = C_RST = ""


def parse_host_port(target, default_port=443):
    """Split 'host' or 'host:port' into (host, port)."""
    if target.count(":") == 1:
        host, port = target.rsplit(":", 1)
        try:
            return host, int(port)
        except ValueError:
            return target, default_port
    return target, default_port


def parse_cert_time(value):
    """Parse an OpenSSL 'notBefore'/'notAfter' string to an aware datetime."""
    # Format looks like: 'Jun  1 12:00:00 2025 GMT'
    dt = datetime.strptime(value, "%b %d %H:%M:%S %Y %Z")
    return dt.replace(tzinfo=timezone.utc)


def flatten_name(name_tuples):
    """Turn the nested subject/issuer tuple structure into a flat dict."""
    out = {}
    for rdn in name_tuples:
        for key, val in rdn:
            out[key] = val
    return out


def fetch_cert(host, port, timeout):
    """Open a TLS connection and return the peer certificate dict."""
    ctx = ssl.create_default_context()
    # We want to inspect certs even when they don't validate, so don't verify.
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            # getpeercert() returns {} when verify_mode is CERT_NONE, so grab
            # the DER form and re-decode it into a readable dict.
            der = ssock.getpeercert(binary_form=True)
            cert = ssock.getpeercert()
            tls_version = ssock.version()
            cipher = ssock.cipher()

    if not cert:
        cert = _decode_der(der)
    return cert, tls_version, cipher


def _decode_der(der_bytes):
    """Decode a DER certificate into the same dict shape as getpeercert()."""
    try:
        pem = ssl.DER_cert_to_PEM_cert(der_bytes)
        # _test_decode_cert needs a file path.
        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as fh:
            fh.write(pem)
            path = fh.name
        return ssl._ssl._test_decode_cert(path)
    except Exception:
        return {}


def print_cert(target, cert, tls_version, cipher):
    print(f"{C_KEY}== {target} =={C_RST}")

    subject = flatten_name(cert.get("subject", ()))
    issuer = flatten_name(cert.get("issuer", ()))

    print(f"  {C_KEY}Common Name :{C_RST} {subject.get('commonName', '-')}")
    print(f"  {C_KEY}Organization:{C_RST} {subject.get('organizationName', '-')}")
    print(f"  {C_KEY}Issuer      :{C_RST} {issuer.get('commonName', '-')}"
          f" ({issuer.get('organizationName', '-')})")
    print(f"  {C_KEY}TLS Version :{C_RST} {tls_version}")
    if cipher:
        print(f"  {C_KEY}Cipher      :{C_RST} {cipher[0]}")

    not_before = cert.get("notBefore")
    not_after = cert.get("notAfter")
    if not_before:
        print(f"  {C_KEY}Valid From  :{C_RST} {not_before}")
    if not_after:
        expires = parse_cert_time(not_after)
        days_left = (expires - datetime.now(timezone.utc)).days
        if days_left < 0:
            status = f"{C_ERR}EXPIRED ({-days_left} days ago){C_RST}"
        elif days_left < 15:
            status = f"{C_WARN}{days_left} days left{C_RST}"
        else:
            status = f"{C_OK}{days_left} days left{C_RST}"
        print(f"  {C_KEY}Valid Until :{C_RST} {not_after}  [{status}]")

    sans = [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"]
    if sans:
        print(f"  {C_KEY}SAN ({len(sans)}) :{C_RST} {', '.join(sans)}")
    print()


def scan(target, timeout):
    host, port = parse_host_port(target)
    try:
        cert, tls_version, cipher = fetch_cert(host, port, timeout)
    except socket.timeout:
        print(f"{C_ERR}[timeout]{C_RST} {target} (no response in {timeout}s)\n")
        return False
    except (socket.gaierror, ConnectionRefusedError, OSError) as exc:
        print(f"{C_ERR}[error]{C_RST} {target}: {exc}\n")
        return False
    except ssl.SSLError as exc:
        print(f"{C_ERR}[ssl error]{C_RST} {target}: {exc}\n")
        return False

    if not cert:
        print(f"{C_ERR}[error]{C_RST} {target}: no certificate returned\n")
        return False

    print_cert(f"{host}:{port}", cert, tls_version, cipher)
    return True


def main():
    parser = argparse.ArgumentParser(
        prog="CertCheck",
        description="Scan websites for their SSL/TLS certificate details.",
    )
    parser.add_argument("hosts", nargs="+",
                        help="host or host:port targets (default port 443)")
    parser.add_argument("-t", "--timeout", type=float, default=4.0,
                        help="connection timeout in seconds (default: 4)")
    parser.add_argument("--no-banner", action="store_true",
                        help="suppress the ASCII banner")
    args = parser.parse_args()

    if not args.no_banner:
        print(BANNER)

    ok = 0
    for target in args.hosts:
        if scan(target, args.timeout):
            ok += 1

    total = len(args.hosts)
    print(f"{C_KEY}Done:{C_RST} {ok}/{total} certificate(s) retrieved.")
    sys.exit(0 if ok == total else 1)


if __name__ == "__main__":
    main()
