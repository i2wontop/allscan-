"""Port & service scanning.

Primary path wraps the ``nmap`` binary (top-ports by default, full 65535 with
``full_ports``, ``-sV`` service/version detection, optional ``-O`` OS
detection, optional safe default scripts ``-sC`` and a top-UDP sweep). nmap
output is parsed from its XML so results are structured, including CPEs and
hostscript/script output.

When nmap is unavailable or ``skip_nmap`` is set, a pure-Python connect-scan +
protocol-aware banner grabber covers a broad high-value port list so the tool
still produces useful service/version hints. In ``aggressive`` intensity it
probes more ports, sends service-specific identification probes, and inspects
TLS (negotiated version, cipher, ALPN, certificate subject/SAN).

Everything here is detection-only: it observes banners and negotiates TLS, but
never sends credentials or data-mutating commands.

Detected service/version strings (and CPEs) are stashed in
``ctx.state['services']`` for the CVE correlation module to consume.
"""

from __future__ import annotations

import concurrent.futures
import datetime
import re
import shutil
import socket
import ssl
import subprocess
import xml.etree.ElementTree as ET
from typing import Optional

from allscan.base import Module, ModuleContext
from allscan.models import Category, Finding, Severity

# Broad high-value TCP port list probed by the fallback scanner (service hints).
COMMON_PORTS: dict[int, str] = {
    7: "echo", 13: "daytime", 19: "chargen", 21: "ftp", 22: "ssh",
    23: "telnet", 25: "smtp", 37: "time", 43: "whois", 49: "tacacs",
    53: "dns", 69: "tftp", 70: "gopher", 79: "finger", 80: "http",
    81: "http-alt", 88: "kerberos", 102: "iso-tsap", 110: "pop3",
    111: "rpcbind", 113: "ident", 119: "nntp", 123: "ntp", 135: "msrpc",
    137: "netbios-ns", 139: "netbios-ssn", 143: "imap", 161: "snmp",
    179: "bgp", 199: "smux", 389: "ldap", 427: "svrloc", 443: "https",
    444: "snpp", 445: "smb", 465: "smtps", 500: "isakmp", 502: "modbus",
    512: "exec", 513: "login", 514: "shell", 515: "printer", 520: "rip",
    523: "db2", 540: "uucp", 548: "afp", 554: "rtsp", 587: "submission",
    593: "http-rpc-epmap", 623: "ipmi", 626: "serialnumberd", 631: "ipp",
    636: "ldaps", 647: "dhcp-failover", 666: "doom", 873: "rsync",
    902: "vmware", 989: "ftps-data", 990: "ftps", 992: "telnets",
    993: "imaps", 995: "pop3s", 1026: "win-rpc", 1080: "socks",
    1099: "java-rmi", 1194: "openvpn", 1200: "scol", 1241: "nessus",
    1337: "waste", 1352: "lotusnotes", 1433: "mssql", 1434: "mssql-m",
    1521: "oracle", 1604: "citrix-ica", 1723: "pptp", 1883: "mqtt",
    1900: "upnp", 2000: "cisco-sccp", 2049: "nfs", 2082: "cpanel",
    2083: "cpanel-ssl", 2086: "whm", 2087: "whm-ssl", 2095: "webmail",
    2096: "webmail-ssl", 2121: "ftp-alt", 2181: "zookeeper",
    2222: "ssh-alt", 2375: "docker", 2376: "docker-tls", 2379: "etcd",
    2404: "iec-104", 2483: "oracle-db", 2484: "oracle-db-ssl",
    2638: "sybase", 3000: "http-alt", 3128: "squid-proxy", 3268: "globalcat",
    3269: "globalcat-ssl", 3299: "sap", 3306: "mysql", 3307: "mysql-alt",
    3389: "rdp", 3478: "stun", 3632: "distcc", 3690: "svn", 4000: "http-alt",
    4369: "epmd", 4443: "https-alt", 4444: "metasploit", 4505: "saltstack",
    4506: "saltstack", 4567: "galera", 4711: "mcafee", 4786: "cisco-smi",
    4848: "glassfish", 5000: "http-alt", 5001: "http-alt", 5005: "jdwp",
    5044: "logstash", 5060: "sip", 5061: "sip-tls", 5222: "xmpp",
    5269: "xmpp-server", 5353: "mdns", 5355: "llmnr", 5432: "postgres",
    5555: "adb", 5601: "kibana", 5672: "amqp", 5900: "vnc", 5901: "vnc-1",
    5984: "couchdb", 5985: "winrm", 5986: "winrm-ssl", 6000: "x11",
    6379: "redis", 6443: "kubernetes", 6666: "irc", 6667: "irc",
    7000: "cassandra", 7001: "weblogic", 7077: "spark", 7199: "cassandra-jmx",
    7474: "neo4j", 7547: "cwmp", 7687: "neo4j-bolt", 8000: "http-alt",
    8008: "http-alt", 8009: "ajp", 8010: "http-alt", 8020: "hadoop",
    8025: "http-alt", 8080: "http-proxy", 8081: "http-alt", 8086: "influxdb",
    8088: "hadoop-yarn", 8089: "splunkd", 8090: "http-alt",
    8140: "puppet", 8161: "activemq", 8180: "http-alt", 8200: "vault",
    8443: "https-alt", 8500: "consul", 8530: "wsus", 8531: "wsus-ssl",
    8600: "consul-dns", 8686: "jmx", 8787: "http-alt", 8834: "nessus-web",
    8880: "http-alt", 8888: "http-alt", 9000: "http-alt", 9001: "tor",
    9002: "http-alt", 9042: "cassandra-cql", 9043: "websphere-ssl",
    9060: "websphere", 9080: "http-alt", 9090: "http-alt", 9092: "kafka",
    9100: "jetdirect", 9200: "elasticsearch", 9300: "elasticsearch-node",
    9389: "adws", 9418: "git", 9443: "https-alt", 9999: "http-alt",
    10000: "webmin", 10250: "kubelet", 10255: "kubelet-ro", 11211: "memcached",
    15672: "rabbitmq-mgmt", 16379: "redis-cluster", 18080: "http-alt",
    27017: "mongodb", 27018: "mongodb", 27019: "mongodb", 28017: "mongodb-web",
    50000: "sap", 50070: "hadoop-nn", 50075: "hadoop-dn", 61616: "activemq",
}

# Ports whose exposure is itself worth flagging at elevated severity.
SENSITIVE_PORTS: dict[int, tuple[str, str]] = {
    23: ("Telnet exposed (cleartext)", Severity.MEDIUM),
    21: ("FTP exposed (often cleartext)", Severity.LOW),
    69: ("TFTP exposed (no auth)", Severity.MEDIUM),
    111: ("rpcbind/portmapper exposed", Severity.LOW),
    135: ("MSRPC endpoint mapper exposed", Severity.LOW),
    137: ("NetBIOS name service exposed", Severity.MEDIUM),
    139: ("NetBIOS session service exposed", Severity.MEDIUM),
    161: ("SNMP exposed (often weak community strings)", Severity.MEDIUM),
    389: ("LDAP exposed (often anonymous bind)", Severity.MEDIUM),
    445: ("SMB exposed", Severity.MEDIUM),
    512: ("rexec exposed (cleartext)", Severity.MEDIUM),
    513: ("rlogin exposed (cleartext)", Severity.MEDIUM),
    514: ("rsh exposed (cleartext)", Severity.MEDIUM),
    623: ("IPMI exposed (common auth bypass)", Severity.HIGH),
    873: ("rsync exposed (often unauthenticated)", Severity.MEDIUM),
    1433: ("MSSQL exposed to network", Severity.MEDIUM),
    1521: ("Oracle DB exposed to network", Severity.MEDIUM),
    2049: ("NFS exposed (check exports)", Severity.MEDIUM),
    2181: ("ZooKeeper exposed (often unauthenticated)", Severity.HIGH),
    2375: ("Docker API exposed (potential RCE)", Severity.HIGH),
    2379: ("etcd exposed (often unauthenticated)", Severity.HIGH),
    3306: ("MySQL exposed to network", Severity.MEDIUM),
    3389: ("RDP exposed", Severity.MEDIUM),
    3632: ("distcc exposed (historic RCE)", Severity.HIGH),
    4505: ("SaltStack master exposed", Severity.HIGH),
    4506: ("SaltStack master exposed", Severity.HIGH),
    5432: ("PostgreSQL exposed to network", Severity.MEDIUM),
    5555: ("Android ADB exposed (RCE)", Severity.HIGH),
    5601: ("Kibana exposed", Severity.MEDIUM),
    5672: ("AMQP/RabbitMQ exposed", Severity.MEDIUM),
    5900: ("VNC exposed (often weak/no auth)", Severity.HIGH),
    5984: ("CouchDB exposed (often unauthenticated)", Severity.HIGH),
    6379: ("Redis exposed (often unauthenticated)", Severity.HIGH),
    6443: ("Kubernetes API exposed", Severity.HIGH),
    7687: ("Neo4j Bolt exposed", Severity.MEDIUM),
    8020: ("Hadoop exposed", Severity.MEDIUM),
    8086: ("InfluxDB exposed (often unauthenticated)", Severity.HIGH),
    8089: ("Splunk management exposed", Severity.MEDIUM),
    8161: ("ActiveMQ console exposed", Severity.MEDIUM),
    8200: ("HashiCorp Vault exposed", Severity.MEDIUM),
    8500: ("Consul exposed (often unauthenticated)", Severity.HIGH),
    9042: ("Cassandra CQL exposed", Severity.MEDIUM),
    9092: ("Kafka exposed (often unauthenticated)", Severity.HIGH),
    9200: ("Elasticsearch exposed (often unauthenticated)", Severity.HIGH),
    10000: ("Webmin exposed", Severity.MEDIUM),
    10250: ("Kubelet API exposed (potential RCE)", Severity.HIGH),
    11211: ("Memcached exposed (often unauthenticated)", Severity.HIGH),
    15672: ("RabbitMQ management exposed", Severity.MEDIUM),
    27017: ("MongoDB exposed (often unauthenticated)", Severity.HIGH),
    50070: ("Hadoop NameNode exposed", Severity.MEDIUM),
    61616: ("ActiveMQ exposed", Severity.MEDIUM),
}

# Ports where the server speaks first (grab what it sends on connect).
_SERVER_FIRST = {
    21, 22, 25, 110, 143, 465, 587, 993, 995, 1723, 2121, 3306, 5432,
    6667, 7, 13, 19, 79, 119, 5900, 5901, 11211,
}

# Weak TLS cipher substrings (checked case-insensitively after upper()).
_WEAK_CIPHERS = frozenset(["RC4", "3DES", "DES-", "NULL", "EXPORT", "ANON", "EXP-"])

# Minimal MongoDB OP_QUERY isMaster probe (detection-only; no data reads).
_MONGODB_PROBE = (
    b"\x3a\x00\x00\x00"   # messageLength = 58 (LE)
    b"\x01\x00\x00\x00"   # requestID
    b"\x00\x00\x00\x00"   # responseTo
    b"\xd4\x07\x00\x00"   # opCode = 2004 (OP_QUERY)
    b"\x00\x00\x00\x00"   # flags
    b"admin.$cmd\x00"     # fullCollectionName
    b"\x00\x00\x00\x00"   # numberToSkip
    b"\x01\x00\x00\x00"   # numberToReturn
    b"\x13\x00\x00\x00"   # BSON doc length = 19
    b"\x10"               # element type: int32
    b"isMaster\x00"       # key
    b"\x01\x00\x00\x00"   # value = 1
    b"\x00"               # document terminator
)

# Per-port identification probes (benign; version/handshake only, no data reads).
_PROBES: dict[int, bytes] = {
    6379:  b"PING\r\n",        # Redis       → +PONG (or -NOAUTH when protected)
    11211: b"version\r\n",    # Memcached   → VERSION x.y.z
    2181:  b"ruok",            # ZooKeeper   → imok (Are You OK?)
    27017: _MONGODB_PROBE,     # MongoDB     → OP_REPLY if accessible
    80:    b"",                # filled per-host as HTTP HEAD probe below
}

# HTTP-based API endpoints to probe with a plain GET (unauthenticated 2xx = misconfig).
# (path, service_label, response_body_substring_indicator, severity_string)
_HTTP_APIS: dict[int, tuple[str, str, str, str]] = {
    9200:  ("/",                 "Elasticsearch",    "cluster_name",     "high"),
    5601:  ("/api/status",       "Kibana",           "version",          "medium"),
    2375:  ("/version",          "Docker API",       "Version",          "high"),
    8500:  ("/v1/status/leader", "Consul",           "",                 "high"),
    2379:  ("/health",           "etcd",             "health",           "high"),
    5984:  ("/_all_dbs",         "CouchDB",          "",                 "high"),
    15672: ("/api/overview",     "RabbitMQ Mgmt",    "rabbitmq_version", "medium"),
    8086:  ("/ping",             "InfluxDB",         "",                 "medium"),
    8200:  ("/v1/sys/health",    "HashiCorp Vault",  "initialized",      "medium"),
    6443:  ("/api",              "Kubernetes API",   "kind",             "high"),
    10250: ("/runningpods/",     "Kubelet",          "items",            "high"),
    28017: ("/",                 "MongoDB HTTP I/F", "version",          "high"),
    50070: ("/dfshealth.html",   "Hadoop NameNode",  "NameNode",         "medium"),
    9090:  ("/api/v1/targets",   "Prometheus",       "activeTargets",    "medium"),
    7474:  ("/",                 "Neo4j HTTP",       "neo4j_version",    "medium"),
    4848:  ("/",                 "GlassFish Admin",  "GlassFish",        "high"),
}

_HTTP_PORTS = {80, 81, 591, 2082, 2086, 2095, 2375, 3000, 4000, 4848, 5000,
               5601, 7001, 7474, 8000, 8008, 8010, 8080, 8081, 8086, 8088,
               8090, 8161, 8180, 8443, 8787, 8880, 8888, 9000, 9001, 9080,
               9090, 9200, 9443, 9999, 10000, 15672, 28017, 50070}
_TLS_PORTS = {443, 465, 563, 636, 989, 990, 992, 993, 995, 2083, 2087, 2096,
              2376, 2484, 3269, 4443, 5061, 5986, 6443, 8443, 9443, 8834,
              8531, 9043, 10250}


class ScanModule(Module):
    name = "scan"
    label = "Port/Service Scan"

    def run(self, ctx: ModuleContext) -> list[Finding]:
        findings: list[Finding] = []
        hosts = self._targets(ctx)
        ctx.state.setdefault("services", [])

        use_nmap = (not ctx.config.skip_nmap) and shutil.which("nmap") is not None
        if not use_nmap and not ctx.config.skip_nmap:
            ctx.log("nmap not found on PATH; using built-in connect scanner.")

        for host in hosts:
            ctx.cancel.raise_if_cancelled()
            ctx.log(f"Scanning {host}…")
            if use_nmap:
                findings.extend(self._nmap_scan(ctx, host))
            else:
                findings.extend(self._fallback_scan(ctx, host))
        return findings

    # ------------------------------------------------------------------ #
    def _targets(self, ctx: ModuleContext) -> list[str]:
        hosts = ctx.state.get("hosts")
        if hosts:
            # unique resolved hostnames; cap to keep runs bounded
            return list(hosts.keys())[:50]
        return [ctx.target]

    def _aggressive(self, ctx: ModuleContext) -> bool:
        return getattr(ctx.config, "scan_intensity", "normal") == "aggressive"

    # ------------------------------------------------------------------ #
    # nmap path
    # ------------------------------------------------------------------ #
    def _nmap_scan(self, ctx: ModuleContext, host: str) -> list[Finding]:
        cmd = ["nmap", "-sV", "-T4", "-oX", "-"]
        if ctx.config.full_ports:
            cmd += ["-p-"]
        else:
            top = max(1, min(int(getattr(ctx.config, "top_ports", 1000)), 65535))
            cmd += ["--top-ports", str(top)]
        if self._aggressive(ctx):
            cmd += ["--version-all", "--version-intensity", "9"]
        if getattr(ctx.config, "scan_scripts", False):
            cmd += ["-sC"]           # nmap's "safe"/"default" script category
        if getattr(ctx.config, "udp_scan", False):
            cmd += ["-sU"]  # UDP sweep alongside TCP; shares --top-ports count with TCP
        if ctx.config.os_detection:
            cmd += ["-O"]
        # keep nmap's own timing reasonable; rate limit the invocation itself
        cmd += ["--host-timeout", "15m", host]

        ctx.rate()
        ctx.audit.record("nmap", host, cmd=" ".join(cmd))
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60 * 20,
                check=False,
            )
        except subprocess.TimeoutExpired:
            ctx.log(f"nmap timed out on {host}.")
            return []
        except Exception as exc:  # pragma: no cover - environment dependent
            ctx.log(f"nmap failed on {host}: {exc}")
            return []

        if not proc.stdout.strip():
            if "requires root" in (proc.stderr or "").lower():
                ctx.log("nmap needs root for some options (e.g. -O/-sU); run with sudo.")
            return []
        return self._parse_nmap_xml(ctx, host, proc.stdout)

    def _parse_nmap_xml(self, ctx: ModuleContext, host: str, xml_text: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError:
            ctx.log("Could not parse nmap XML output.")
            return findings
        for host_el in root.findall("host"):
            # OS detection
            for osmatch in host_el.findall("./os/osmatch"):
                findings.append(
                    ctx.emit(
                        Finding(
                            category=Category.SERVICE,
                            title=f"OS guess: {osmatch.get('name')}",
                            severity=Severity.INFO,
                            target=host,
                            description="nmap OS fingerprint.",
                            evidence={"accuracy": osmatch.get("accuracy")},
                            module=self.name,
                        )
                    )
                )
            # host-level scripts (e.g. smb-os-discovery)
            for scr in host_el.findall("./hostscript/script"):
                out = (scr.get("output") or "").strip()
                if out:
                    findings.append(
                        ctx.emit(
                            Finding(
                                category=Category.SERVICE,
                                title=f"{host}: nmap {scr.get('id')} script",
                                severity=Severity.INFO,
                                target=host,
                                description="nmap host script output.",
                                evidence={"script": scr.get("id"), "output": out[:800]},
                                module=self.name,
                            )
                        )
                    )
            for port_el in host_el.findall("./ports/port"):
                state_el = port_el.find("state")
                if state_el is None or state_el.get("state") != "open":
                    continue
                portid = int(port_el.get("portid"))
                proto = port_el.get("protocol", "tcp")
                svc_el = port_el.find("service")
                svc = svc_el.get("name", "") if svc_el is not None else ""
                product = svc_el.get("product", "") if svc_el is not None else ""
                version = svc_el.get("version", "") if svc_el is not None else ""
                extrainfo = svc_el.get("extrainfo", "") if svc_el is not None else ""
                tunnel = svc_el.get("tunnel", "") if svc_el is not None else ""
                cpes = [c.text for c in (svc_el.findall("cpe") if svc_el is not None else []) if c.text]
                # per-port script output (banner, http-title, ssl-cert, ...)
                scripts = {}
                for scr in port_el.findall("script"):
                    sid = scr.get("id")
                    out = (scr.get("output") or "").strip()
                    if sid and out:
                        scripts[sid] = out[:500]
                findings.extend(
                    self._record_port(
                        ctx, host, portid, proto, svc, product, version,
                        extrainfo=extrainfo, tunnel=tunnel, cpes=cpes, scripts=scripts,
                    )
                )
        return findings

    # ------------------------------------------------------------------ #
    # fallback path
    # ------------------------------------------------------------------ #
    def _port_list(self, ctx: ModuleContext) -> list[int]:
        if ctx.config.full_ports:
            return list(range(1, 65536))
        ports = set(COMMON_PORTS.keys())
        ports.update(int(p) for p in (getattr(ctx.config, "extra_ports", None) or []))
        return sorted(ports)

    def _fallback_scan(self, ctx: ModuleContext, host: str) -> list[Finding]:
        findings: list[Finding] = []
        ports = self._port_list(ctx)
        open_ports: list[int] = []
        filtered = 0

        def probe(port: int) -> Optional[tuple[int, str]]:
            if ctx.cancel.cancelled():
                return None
            ctx.rate()
            try:
                sock = socket.create_connection((host, port), timeout=ctx.config.timeout)
                sock.close()
                return (port, "open")
            except ConnectionRefusedError:
                return (port, "closed")
            except (socket.timeout, TimeoutError):
                return (port, "filtered")
            except OSError:
                return (port, "closed")

        with concurrent.futures.ThreadPoolExecutor(max_workers=ctx.config.threads) as ex:
            for result in ex.map(probe, ports):
                if ctx.cancel.cancelled():
                    break
                if result is None:
                    continue
                port, state = result
                if state == "open":
                    open_ports.append(port)
                elif state == "filtered":
                    filtered += 1

        for port in sorted(open_ports):
            ctx.cancel.raise_if_cancelled()
            banner, product, version, tls = self._grab_banner(ctx, host, port)
            svc = COMMON_PORTS.get(port, "unknown")
            findings.extend(
                self._record_port(
                    ctx, host, port, "tcp", svc, product, version,
                    banner=banner, tls=tls,
                )
            )
        if filtered and self._aggressive(ctx):
            ctx.log(f"{host}: {filtered} filtered port(s) (no response).")
        return findings

    def _grab_banner(self, ctx: ModuleContext, host: str, port: int):
        """Best-effort banner grab; returns (banner, product, version, tls_info)."""
        ctx.rate()
        ctx.audit.record("banner", host, port=port)
        data = b""
        tls_info: dict = {}
        try:
            sock = socket.create_connection((host, port), timeout=ctx.config.timeout)
            if port in _TLS_PORTS:
                tls_info = self._tls_inspect(host, sock)
                sock = tls_info.pop("_sock", sock)
            sock.settimeout(ctx.config.timeout)
            probe = self._probe_for(host, port)
            if probe:
                try:
                    sock.sendall(probe)
                except Exception:
                    pass
            try:
                data = sock.recv(4096)
            except Exception:
                pass
            try:
                sock.close()
            except Exception:
                pass
        except Exception:
            return "", "", "", tls_info
        banner = data.decode("latin-1", "replace").strip()
        product, version = _guess_version(banner)
        return banner[:600], product, version, tls_info

    def _probe_for(self, host: str, port: int) -> bytes:
        if port in _HTTP_PORTS:
            return f"HEAD / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: allscan\r\n\r\n".encode()
        if port in _PROBES:
            return _PROBES[port]
        if port in _SERVER_FIRST:
            return b""            # let the server greet us
        # generic nudge for unknown text protocols
        return b"\r\n"

    def _tls_inspect(self, host: str, sock) -> dict:
        """Negotiate TLS (no verification) and record version/cipher/ALPN/cert.
        Returns a dict; the live socket is handed back under ``_sock``."""
        info: dict = {}
        try:
            sctx = ssl._create_unverified_context()
            try:
                sctx.set_alpn_protocols(["h2", "http/1.1"])
            except Exception:
                pass
            wrapped = sctx.wrap_socket(sock, server_hostname=host)
            info["_sock"] = wrapped
            info["tls_version"] = wrapped.version() or ""
            cipher = wrapped.cipher()
            if cipher:
                info["cipher"] = cipher[0]
            try:
                info["alpn"] = wrapped.selected_alpn_protocol() or ""
            except Exception:
                pass
            cert = wrapped.getpeercert()
            if cert:
                subj_pairs = cert.get("subject", ())
                issuer_pairs = cert.get("issuer", ())
                subj = {k: v for t in subj_pairs for (k, v) in t}
                issuer = {k: v for t in issuer_pairs for (k, v) in t}
                info["cert_cn"] = subj.get("commonName", "")
                sans = [v for (t, v) in cert.get("subjectAltName", ()) if t == "DNS"]
                if sans:
                    info["cert_sans"] = sans[:20]
                not_after_str = cert.get("notAfter", "")
                info["cert_not_after"] = not_after_str
                # Self-signed: subject dict equals issuer dict (and both non-empty).
                if subj and subj == issuer:
                    info["self_signed"] = True
                # Days remaining until expiry (negative = already expired).
                if not_after_str:
                    try:
                        na = datetime.datetime.strptime(
                            not_after_str, "%b %d %H:%M:%S %Y %Z"
                        )
                        info["cert_days_remaining"] = (
                            na - datetime.datetime.utcnow()
                        ).days
                    except Exception:
                        pass
        except Exception:
            pass
        return info

    # ------------------------------------------------------------------ #
    def _record_port(
        self,
        ctx: ModuleContext,
        host: str,
        port: int,
        proto: str,
        svc: str,
        product: str,
        version: str,
        banner: str = "",
        *,
        extrainfo: str = "",
        tunnel: str = "",
        cpes: Optional[list] = None,
        scripts: Optional[dict] = None,
        tls: Optional[dict] = None,
    ) -> list[Finding]:
        svc_desc = " ".join(p for p in (product, version) if p) or svc or "unknown"
        evidence: dict = {
            "port": port,
            "protocol": proto,
            "service": svc,
            "product": product,
            "version": version,
        }
        if extrainfo:
            evidence["extrainfo"] = extrainfo
        if tunnel:
            evidence["tunnel"] = tunnel
        if banner:
            evidence["banner"] = banner
        if cpes:
            evidence["cpe"] = cpes
        if scripts:
            evidence["scripts"] = scripts
        if tls:
            evidence.update({k: v for k, v in tls.items() if not k.startswith("_")})

        # stash for CVE correlation (include CPEs so the vuln module can match)
        if product or cpes:
            ctx.state.setdefault("services", []).append(
                {"host": host, "port": port, "product": product,
                 "version": version, "cpe": cpes or []}
            )

        findings = [
            ctx.emit(
                Finding(
                    category=Category.PORT,
                    title=f"{host}:{port}/{proto} open ({svc_desc})",
                    severity=Severity.INFO,
                    target=host,
                    description="Open port / detected service.",
                    evidence=evidence,
                    module=self.name,
                )
            )
        ]
        if port in SENSITIVE_PORTS:
            title, sev = SENSITIVE_PORTS[port]
            findings.append(
                ctx.emit(
                    Finding(
                        category=Category.MISCONFIG,
                        title=f"{host}: {title}",
                        severity=sev,
                        target=host,
                        description=(
                            "A sensitive service is reachable over the network. "
                            "Confirm it requires authentication and is firewalled "
                            "to trusted sources."
                        ),
                        evidence=evidence,
                        module=self.name,
                    )
                )
            )
        # Unauthenticated-service confirmation from benign probes (detection only).
        findings.extend(self._probe_findings(ctx, host, port, banner, evidence))
        # Weak TLS flagging from the negotiated connection.
        if tls and tls.get("tls_version") in ("SSLv3", "TLSv1", "TLSv1.1"):
            findings.append(
                ctx.emit(
                    Finding(
                        category=Category.TLS,
                        title=f"{host}:{port} negotiated obsolete {tls['tls_version']}",
                        severity=Severity.MEDIUM,
                        target=host,
                        description="Server accepts an obsolete TLS protocol version.",
                        evidence=evidence,
                        module=self.name,
                    )
                )
            )
        # Self-signed certificate.
        if tls and tls.get("self_signed"):
            findings.append(
                ctx.emit(
                    Finding(
                        category=Category.TLS,
                        title=f"{host}:{port} uses a self-signed TLS certificate",
                        severity=Severity.MEDIUM,
                        target=host,
                        description=(
                            "The TLS certificate is self-signed (issuer equals subject). "
                            "Replace with a certificate issued by a trusted CA."
                        ),
                        evidence=evidence,
                        module=self.name,
                    )
                )
            )
        # Certificate expiry (negative days = already expired).
        days = (tls or {}).get("cert_days_remaining")
        if isinstance(days, int):
            if days < 0:
                findings.append(
                    ctx.emit(
                        Finding(
                            category=Category.TLS,
                            title=f"{host}:{port} TLS certificate EXPIRED {abs(days)} days ago",
                            severity=Severity.HIGH,
                            target=host,
                            description=(
                                "The TLS certificate has expired. Clients will reject "
                                "this connection. Renew the certificate immediately."
                            ),
                            evidence=evidence,
                            module=self.name,
                        )
                    )
                )
            elif days < 14:
                findings.append(
                    ctx.emit(
                        Finding(
                            category=Category.TLS,
                            title=f"{host}:{port} TLS certificate expires in {days} days",
                            severity=Severity.HIGH,
                            target=host,
                            description="Certificate expires very soon. Renew immediately.",
                            evidence=evidence,
                            module=self.name,
                        )
                    )
                )
            elif days < 30:
                findings.append(
                    ctx.emit(
                        Finding(
                            category=Category.TLS,
                            title=f"{host}:{port} TLS certificate expires in {days} days",
                            severity=Severity.MEDIUM,
                            target=host,
                            description="Certificate expires within 30 days. Plan renewal.",
                            evidence=evidence,
                            module=self.name,
                        )
                    )
                )
        # Weak cipher suite.
        cipher_name = (tls or {}).get("cipher") or ""
        if cipher_name and any(w in cipher_name.upper() for w in _WEAK_CIPHERS):
            findings.append(
                ctx.emit(
                    Finding(
                        category=Category.TLS,
                        title=f"{host}:{port} weak TLS cipher negotiated: {cipher_name}",
                        severity=Severity.HIGH,
                        target=host,
                        description=(
                            "A weak cipher suite was negotiated. Disable RC4, 3DES, "
                            "NULL, EXPORT and anonymous cipher suites in the server config."
                        ),
                        evidence=evidence,
                        module=self.name,
                    )
                )
            )
        # HTTP-based API unauthenticated-access check.
        findings.extend(self._http_api_probe_findings(ctx, host, port, evidence))
        ctx.log(f"{host}:{port} open — {svc_desc}")
        return findings

    def _probe_findings(self, ctx: ModuleContext, host: str, port: int,
                        banner: str, evidence: dict) -> list[Finding]:
        """Turn benign identification-probe responses into findings."""
        out: list[Finding] = []
        low = (banner or "").lower()
        if port == 6379 and "+pong" in low:
            out.append(ctx.emit(Finding(
                category=Category.MISCONFIG,
                title=f"{host}:6379 Redis responds to PING without auth",
                severity=Severity.HIGH, target=host,
                description="Redis answered PING with +PONG, indicating no "
                            "authentication is required. Enable requirepass/ACLs.",
                evidence=evidence, module=self.name)))
        elif port == 6379 and "noauth" in low:
            out.append(ctx.emit(Finding(
                category=Category.SERVICE,
                title=f"{host}:6379 Redis requires authentication",
                severity=Severity.INFO, target=host,
                description="Redis is password-protected (returned NOAUTH).",
                evidence=evidence, module=self.name)))
        if port == 11211 and low.startswith("version"):
            out.append(ctx.emit(Finding(
                category=Category.MISCONFIG,
                title=f"{host}:11211 Memcached answers without auth",
                severity=Severity.HIGH, target=host,
                description="Memcached returned its version banner with no "
                            "authentication. Bind to localhost or enable SASL.",
                evidence=evidence, module=self.name)))
        # ZooKeeper: "ruok" admin probe returns "imok" when accessible.
        if port == 2181 and "imok" in low:
            out.append(ctx.emit(Finding(
                category=Category.MISCONFIG,
                title=f"{host}:2181 ZooKeeper responds to unauthenticated 'ruok' probe",
                severity=Severity.HIGH, target=host,
                description=(
                    "ZooKeeper answered the 'ruok' (Are You OK?) admin command without "
                    "authentication. Restrict access to trusted clients or enable "
                    "ZooKeeper admin server auth (4lw.commands.whitelist)."
                ),
                evidence=evidence, module=self.name)))
        # MongoDB: a valid OP_REPLY has opCode=1 at bytes 12-15 (little-endian).
        if port == 27017:
            raw = (banner or "").encode("latin-1", "ignore")
            if len(raw) >= 16 and raw[12:16] == b"\x01\x00\x00\x00":
                out.append(ctx.emit(Finding(
                    category=Category.MISCONFIG,
                    title=f"{host}:27017 MongoDB accepts unauthenticated connections",
                    severity=Severity.HIGH, target=host,
                    description=(
                        "MongoDB responded to an isMaster wire-protocol probe without "
                        "authentication. Enable --auth in mongod.conf and restrict "
                        "network access to trusted clients."
                    ),
                    evidence=evidence, module=self.name)))
        return out

    def _http_api_probe_findings(
        self,
        ctx: ModuleContext,
        host: str,
        port: int,
        evidence: dict,
    ) -> list[Finding]:
        """Probe HTTP-based service APIs for unauthenticated access (GET only)."""
        spec = _HTTP_APIS.get(port)
        if spec is None:
            return []
        path, service_label, body_indicator, sev_str = spec
        proto = "https" if port in _TLS_PORTS else "http"
        url = f"{proto}://{host}:{port}{path}"
        try:
            resp = ctx.http_get(
                url,
                timeout=ctx.config.timeout,
                action="http_api_probe",
                service=service_label,
            )
        except Exception:
            return []
        if resp.status_code not in (200, 204):
            return []
        if body_indicator:
            try:
                body = resp.text[:500]
            except Exception:
                body = ""
            if body_indicator.lower() not in body.lower():
                return []
        return [
            ctx.emit(
                Finding(
                    category=Category.MISCONFIG,
                    title=f"{host}:{port} {service_label} accessible without authentication",
                    severity=Severity(sev_str),
                    target=host,
                    description=(
                        f"{service_label} responded to an unauthenticated HTTP GET "
                        f"({path}). Restrict network access or enable authentication."
                    ),
                    evidence={**evidence, "url": url, "http_status": resp.status_code},
                    module=self.name,
                )
            )
        ]


def _guess_version(banner: str) -> tuple[str, str]:
    """Extract a rough (product, version) from a raw banner string."""
    if not banner:
        return "", ""
    # SSH-2.0-OpenSSH_8.9p1 ; Server: nginx/1.18.0 ; etc.
    m = re.search(r"(OpenSSH|nginx|Apache|lighttpd|Microsoft-IIS|Exim|Postfix|"
                  r"vsftpd|ProFTPD|Pure-FTPd|MySQL|MariaDB|PostgreSQL|Redis|"
                  r"MongoDB|memcached|Dovecot|Sendmail|Jetty|Tomcat|Gunicorn|"
                  r"Werkzeug|Node\.js|OpenSSL|Microsoft FTP|CouchDB|RabbitMQ|"
                  r"Elasticsearch|HAProxy|Varnish|Kestrel|Caddy|"
                  r"OpenResty|Tengine|Envoy|Traefik|Consul|etcd|"
                  r"InfluxDB|Prometheus|Grafana|Kibana|Splunk|"
                  r"WebSphere|WebLogic|JBoss|WildFly|GlassFish|"
                  r"ProxySQL|PgBouncer|Gitea|GitLab|Jenkins|Nexus|Artifactory|"
                  r"Flask|FastAPI|Django|Tornado|uvicorn|hypercorn|Starlette|"
                  r"Drupal|WordPress|Joomla|Magento|Confluence|Jira|Bitbucket)[/_ ]?"
                  r"([0-9]+(?:\.[0-9]+){0,3}[a-z0-9\-]*)", banner, re.IGNORECASE)
    if m:
        return m.group(1), m.group(2)
    m = re.search(r"Server:\s*([^\r\n/]+)/([0-9][0-9A-Za-z.\-]*)", banner, re.IGNORECASE)
    if m:
        return m.group(1).strip(), m.group(2)
    return "", ""
