"""Integrazione Nmap: validazione bersagli, esecuzione controllata, parsing XML, finding di rischio.

Principi di sicurezza:
- di default si scansiona SOLO il sistema locale (loopback + indirizzi delle proprie interfacce);
- bersagli esterni richiedono autorizzazione esplicita (gestita da scan.py / cli.py);
- i bersagli sono validati (IPv4, CIDR <= /24, hostname) prima di arrivare a nmap: niente opzioni iniettabili;
- nessuno script NSE intrusivo/vuln e nessun invio di dati a servizi terzi (solo script 'default' in modalità full);
- la presenza di un servizio non è una vulnerabilità: nessuna correlazione CVE viene dichiarata.
"""
from __future__ import annotations

import ipaddress
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field

from .models import Finding
from .runner import Runner

MAX_NETWORK_HOSTS = 256
NMAP_TIMEOUT = 1800
_HOST_RE = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$")


class TargetError(ValueError):
    pass


@dataclass(frozen=True)
class Target:
    raw: str
    kind: str       # ip | network | hostname
    is_self: bool
    count: int = 1


def validate_target(raw: str, local_addrs=()) -> Target:
    t = (raw or "").strip()
    if not t or t.startswith("-") or any(c.isspace() for c in t) or len(t) > 253:
        raise TargetError(f"Bersaglio non valido: {raw!r}")
    if t.lower() == "localhost":
        return Target("127.0.0.1", "ip", True)
    ip = None
    try:
        ip = ipaddress.ip_address(t)
    except ValueError:
        pass
    if ip is not None:
        if ip.version != 4:
            raise TargetError("Per ora è supportato solo IPv4.")
        return Target(str(ip), "ip", ip.is_loopback or str(ip) in set(local_addrs))
    if "/" in t:
        try:
            net = ipaddress.ip_network(t, strict=False)
        except ValueError as exc:
            raise TargetError(f"Intervallo di rete non valido: {raw!r}") from exc
        if net.version != 4:
            raise TargetError("Per ora è supportato solo IPv4.")
        if net.num_addresses > MAX_NETWORK_HOSTS:
            raise TargetError(f"Intervallo troppo ampio ({net.num_addresses} indirizzi): massimo /24.")
        return Target(str(net), "network", net.is_loopback, net.num_addresses)
    if _HOST_RE.match(t):
        return Target(t.lower(), "hostname", False)
    raise TargetError(f"Bersaglio non valido: {raw!r}")


def local_addresses(runner: Runner) -> list[str]:
    r = runner.run(["ip", "-o", "-4", "addr", "show", "scope", "global"], timeout=5)
    addrs = re.findall(r"\binet (\d{1,3}(?:\.\d{1,3}){3})/", r.out) if r.ok else []
    return list(dict.fromkeys(addrs))[:8]


# --------------------------------------------------------------------------- comando
def build_command(nmap: str, targets: list[Target], *, mode: str, root: bool, udp: bool = False) -> list[str]:
    cmd = [nmap, "-oX", "-", "-n", "--open", "-T3", "--max-retries", "2"]
    if udp:
        cmd += ["-sU", "--top-ports", "50", "--host-timeout", "10m"]
    else:
        cmd += ["-sS" if root else "-sT", "-sV", "--version-light", "--host-timeout", "20m"]
        cmd += ["--top-ports", "1000"] if mode == "quick" else ["-p-"]
        if mode == "full":
            cmd += ["--script", "default"]
    if all(t.kind == "ip" for t in targets):
        cmd.append("-Pn")
    cmd += [t.raw for t in targets]
    return cmd


# --------------------------------------------------------------------------- parsing
@dataclass
class OpenPort:
    host: str
    proto: str
    port: int
    service: str = ""
    product: str = ""
    version: str = ""
    extrainfo: str = ""
    tunnel: str = ""
    scripts: dict = field(default_factory=dict)

    def banner(self) -> str:
        parts = [self.tunnel + "/" if self.tunnel else "", self.service, self.product, self.version, f"({self.extrainfo})" if self.extrainfo else ""]
        return " ".join(p for p in parts if p).replace("/ ", "/") or "sconosciuto"


@dataclass
class NmapResult:
    version: str = ""
    hosts_up: int = 0
    hosts_total: int = 0
    elapsed: float = 0.0
    ports: list = field(default_factory=list)


def parse_xml(text: str) -> NmapResult:
    if "<!ENTITY" in text:
        raise ValueError("XML con entità non ammesso")
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        raise ValueError(f"XML nmap non valido: {exc}") from exc
    res = NmapResult(version=root.get("version", ""))
    fin = root.find("runstats/finished")
    if fin is not None:
        try:
            res.elapsed = float(fin.get("elapsed", "0"))
        except ValueError:
            pass
    hs = root.find("runstats/hosts")
    if hs is not None:
        res.hosts_up = int(hs.get("up", "0") or 0)
        res.hosts_total = int(hs.get("total", "0") or 0)
    for host in root.findall("host"):
        addr = next((a.get("addr", "") for a in host.findall("address") if a.get("addrtype") in ("ipv4", "ipv6")), "")
        for p in host.findall("ports/port"):
            st = p.find("state")
            if st is None or st.get("state") != "open":
                continue
            svc = p.find("service")
            op = OpenPort(addr, p.get("protocol", "tcp"), int(p.get("portid", "0")))
            if svc is not None:
                op.service, op.product = svc.get("name", ""), svc.get("product", "")
                op.version, op.extrainfo, op.tunnel = svc.get("version", ""), svc.get("extrainfo", ""), svc.get("tunnel", "")
            for sc in p.findall("script"):
                op.scripts[sc.get("id", "")] = (sc.get("output", "") or "")[:600]
            res.ports.append(op)
    return res


# --------------------------------------------------------------------------- regole di rischio
@dataclass(frozen=True)
class Rule:
    name: str
    severity: str
    why: str
    fix: str


def _rules() -> dict:
    r: dict = {}
    def add(proto, ports, *a):
        for p in (ports if isinstance(ports, (list, range, tuple)) else [ports]):
            r[(proto, p)] = Rule(*a)
    add("tcp", 23, "Telnet", "critical", "accesso remoto senza cifratura: credenziali e sessione in chiaro", "Disabilitare Telnet e usare SSH.")
    add("tcp", [512, 513, 514], "r-services", "critical", "servizi r* (rexec/rlogin/rsh) legacy, autenticazione debole e in chiaro", "Disabilitare e sostituire con SSH.")
    add("tcp", 2375, "Docker API non cifrata", "critical", "API Docker senza TLS/autenticazione: equivale a root sull'host", "Non esporre l'API; usare socket locale o TLS con autenticazione client.")
    add("tcp", 21, "FTP", "high", "credenziali e dati in chiaro", "Sostituire con SFTP/FTPS o limitare con firewall.")
    add("udp", 69, "TFTP", "high", "nessuna autenticazione", "Disabilitare o limitare a reti di gestione.")
    add("tcp", [139, 445], "SMB/NetBIOS", "high", "condivisioni file spesso bersaglio di attacchi (ransomware, movimento laterale)", "Limitare a reti fidate, disabilitare SMBv1, richiedere firma SMB.")
    add("tcp", 3389, "RDP", "high", "desktop remoto frequentemente attaccato (brute force, exploit)", "Esporre solo via VPN/gateway con MFA.")
    add("tcp", range(5900, 5910), "VNC", "high", "desktop remoto con autenticazione debole/senza cifratura", "Tunnel SSH/VPN e password robuste.")
    add("tcp", range(6000, 6010), "X11", "high", "server grafico X esposto in rete", "Disabilitare l'ascolto TCP di X (-nolisten tcp).")
    add("tcp", 1433, "Microsoft SQL Server", "high", "database esposto in rete", "Limitare l'accesso con firewall e applicare TLS.")
    add("tcp", 1521, "Oracle DB", "high", "database esposto in rete", "Limitare l'accesso con firewall e applicare TLS.")
    add("tcp", 3306, "MySQL/MariaDB", "high", "database esposto in rete", "Mettere in ascolto su loopback o su rete di servizio, con firewall e TLS.")
    add("tcp", 5432, "PostgreSQL", "high", "database esposto in rete", "Limitare listen_addresses/pg_hba.conf e firewall.")
    add("tcp", 5984, "CouchDB", "high", "database esposto in rete", "Limitare accesso e abilitare autenticazione.")
    add("tcp", 6379, "Redis", "high", "spesso senza autenticazione: rischio di compromissione dell'host", "Bind su loopback, requirepass/ACL, firewall.")
    add("tcp", [9200, 9300], "Elasticsearch", "high", "dati e API esposti, spesso senza autenticazione", "Abilitare sicurezza integrata e limitare con firewall.")
    add("tcp", 11211, "Memcached", "high", "senza autenticazione, usato anche per amplificazione DDoS", "Bind su loopback e firewall.")
    add("tcp", 27017, "MongoDB", "high", "database esposto in rete, storicamente senza autenticazione", "Abilitare auth, bind su rete di servizio, firewall.")
    add("tcp", 2379, "etcd", "high", "store di configurazione/segreti esposto", "Richiedere TLS client e limitare l'accesso.")
    add("tcp", 10250, "Kubelet", "high", "API del nodo Kubernetes esposta", "Disabilitare accesso anonimo e limitare con firewall.")
    add("tcp", [110, 143], "POP3/IMAP", "medium", "posta in chiaro se senza TLS", "Usare POP3S/IMAPS o STARTTLS obbligatorio.")
    add("tcp", [111], "rpcbind", "medium", "espone servizi RPC (NFS/NIS), utile alla ricognizione", "Disabilitare se non necessario.")
    add("udp", [111], "rpcbind", "medium", "espone servizi RPC (NFS/NIS), utile alla ricognizione", "Disabilitare se non necessario.")
    add("tcp", 135, "MS-RPC", "medium", "superficie di attacco Windows/RPC", "Limitare con firewall.")
    add("udp", 161, "SNMP", "medium", "community di default/SNMPv1-2c in chiaro", "Usare SNMPv3 e limitare le sorgenti.")
    add("tcp", 389, "LDAP", "medium", "directory in chiaro senza TLS", "Usare LDAPS/StartTLS.")
    add("tcp", 873, "rsync", "medium", "sincronizzazione file spesso senza autenticazione", "Richiedere autenticazione e limitare le sorgenti.")
    add("tcp", 2049, "NFS", "medium", "condivisione file di rete", "Limitare client/export e usare Kerberos dove possibile.")
    add("udp", 2049, "NFS", "medium", "condivisione file di rete", "Limitare client/export e usare Kerberos dove possibile.")
    add("tcp", 2376, "Docker API (TLS)", "medium", "API Docker esposta (protetta da TLS)", "Verificare autenticazione client e limitare con firewall.")
    add("tcp", 80, "HTTP", "low", "traffico non cifrato", "Reindirizzare a HTTPS e verificare la configurazione.")
    add("tcp", 25, "SMTP", "low", "relay aperto/enumerazione utenti possibili", "Verificare che non sia un open relay; usare TLS.")
    add("udp", 5353, "mDNS", "low", "annuncio di servizi in rete locale", "Disabilitare Avahi se non necessario.")
    add("tcp", 22, "SSH", "info", "accesso amministrativo remoto", "Verificare hardening (chiavi, no root, MFA) e limitare le sorgenti.")
    add("tcp", 443, "HTTPS", "info", "servizio web cifrato", "Verificare protocolli/cifrari, certificato e patch del server web.")
    add("udp", 123, "NTP", "info", "servizio orario", "Verificare che non risponda a query di monitoraggio (amplificazione).")
    add("udp", 53, "DNS", "info", "servizio DNS", "Verificare che non sia un resolver aperto.")
    add("tcp", 53, "DNS", "info", "servizio DNS", "Verificare che non sia un resolver aperto.")
    return r


RULES = _rules()


def _is_loop(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _script_flags(scripts: dict) -> list[tuple[str, str]]:
    flags = []
    if "login allowed" in scripts.get("ftp-anon", "").lower():
        flags.append(("high", "FTP anonimo consentito"))
    sslv2 = scripts.get("sslv2", "")
    if "sslv2" in sslv2.lower() and "supported" in sslv2.lower() and "not" not in sslv2.lower()[:40]:
        flags.append(("high", "SSLv2 supportato"))
    return flags


def build_findings(res: NmapResult, *, self_scan: bool, mode: str, targets_desc: str, udp_ran: bool) -> list[Finding]:
    out: list[Finding] = []
    groups: dict = {}
    for p in res.ports:
        key = (p.proto, p.port) if self_scan else (p.host, p.proto, p.port)
        groups.setdefault(key, []).append(p)
    exposed_count = 0
    for key, plist in sorted(groups.items(), key=lambda kv: str(kv[0])):
        proto, port = key[-2], key[-1]
        hosts = sorted({p.host for p in plist})
        exposed = (not self_scan) or any(not _is_loop(h) for h in hosts)
        rule = RULES.get((proto, port))
        first = plist[0]
        svc = first.banner()
        scripts = {k: v for p in plist for k, v in p.scripts.items()}
        sid = f"NMAP-{proto.upper()}-{port}" if self_scan else f"NMAP-{key[0].replace(':', '_')}-{proto.upper()}-{port}"
        ev = f"Porta {proto}/{port} aperta su {', '.join(hosts)}; servizio rilevato: {svc}."
        if scripts:
            ev += " Script NSE: " + "; ".join(f"{k}: {v[:200]}" for k, v in list(scripts.items())[:4])
        refs = ["https://nmap.org/book/man.html"]
        if not exposed:
            out.append(Finding(sid, f"Servizio locale {proto}/{port} ({rule.name if rule else svc})", "info", "info", "network",
                               ev + " In ascolto solo su loopback: non raggiungibile da altri sistemi.",
                               "Nessuna azione se il servizio è necessario.", "high", source="nmap", references=refs))
            continue
        exposed_count += 1
        name = rule.name if rule else svc
        flags = _script_flags(scripts)
        if rule:
            sev, why, fix = rule.severity, rule.why, rule.fix
            if rule.severity == "info":
                status = "info"
            else:
                status = "fail" if rule.severity == "critical" else "warn"
            if flags:
                sev, status = "high", "fail"
                ev += " Rilevato: " + ", ".join(t for _, t in flags) + "."
            lik = 4 if sev == "critical" else 3
            note = ("Porta aperta sull'interfaccia di rete: raggiungibile da altri sistemi, salvo filtri a monte (firewall/NAT)."
                    if self_scan else "Porta raggiungibile dal punto di scansione.")
            out.append(Finding(sid, f"Porta {proto}/{port} esposta: {name}", sev, status, "network",
                               f"{ev} {note} Rischio: {why}.", f"{fix} Verificare inoltre che versione e patch del software siano aggiornate.",
                               "high", source="nmap", likelihood=lik if status in ("warn", "fail") else 0, references=refs))
        else:
            out.append(Finding(sid, f"Servizio non classificato esposto su {proto}/{port}", "low", "manual", "network",
                               ev + " Servizio non presente nella tabella di rischio di LSTK.",
                               "Identificare il servizio e il suo proprietario; chiudere o filtrare la porta se non necessaria.",
                               "medium", source="nmap", references=refs))
    if res.hosts_up == 0 and res.hosts_total >= 0 and not res.ports:
        status, sev = "unknown", "medium"
        ev = f"Nessun host risultato raggiungibile ({targets_desc}). Un host che non risponde NON è per questo sicuro."
    elif exposed_count == 0:
        status, sev = "pass", "info"
        ev = f"Nessuna porta aperta raggiungibile su {targets_desc}."
    else:
        status, sev = "info", "info"
        ev = f"{exposed_count} porte/servizi esposti su {targets_desc}."
    ev += f" Modalità {mode}; Nmap {res.version}; durata {res.elapsed:.0f}s; UDP top-50 {'eseguito' if udp_ran else 'non eseguito (richiede root e modalità full)'}."
    out.insert(0, Finding("NMAP-001", "Scansione porte (Nmap)", sev, status, "network", ev,
                          "La scansione è un'istantanea; ripeterla periodicamente e dopo ogni modifica di rete.", "high", source="nmap"))
    return out


# --------------------------------------------------------------------------- orchestrazione
@dataclass
class NmapOutcome:
    findings: list
    status: str     # ok | skipped | failed
    detail: str


def run_nmap(runner: Runner, targets: list[Target], *, mode: str, root: bool) -> NmapOutcome:
    nmap = runner.which("nmap")
    if not nmap:
        f = Finding("NMAP-000", "Scansione porte non eseguita", "medium", "manual", "network",
                    "nmap non è installato (ricerca solo in directory di sistema).",
                    "Installare nmap dai repository ufficiali (apt/dnf install nmap) e rieseguire /scan.", "high", source="nmap")
        return NmapOutcome([f], "skipped", "nmap non installato")
    desc = ", ".join(t.raw for t in targets)
    self_scan = all(t.is_self for t in targets)
    r = runner.run(build_command(nmap, targets, mode=mode, root=root), timeout=NMAP_TIMEOUT)

    def fail(msg):
        f = Finding("NMAP-000", "Scansione porte non completata", "medium", "unknown", "network", msg,
                    "Verificare permessi, raggiungibilità e rieseguire.", "low", source="nmap")
        return NmapOutcome([f], "failed", msg)
    if r.timed_out:
        return fail(f"Timeout dopo {NMAP_TIMEOUT}s su {desc}.")
    if not r.out.lstrip().startswith("<"):
        return fail((r.err or "Nessun output XML da nmap")[:500])
    try:
        res = parse_xml(r.out)
    except ValueError as exc:
        return fail(str(exc))
    udp_ran = False
    if mode == "full" and root:
        ru = runner.run(build_command(nmap, targets, mode=mode, root=root, udp=True), timeout=NMAP_TIMEOUT)
        if ru.out.lstrip().startswith("<"):
            try:
                res.ports += parse_xml(ru.out).ports
                udp_ran = True
            except ValueError:
                pass
    findings = build_findings(res, self_scan=self_scan, mode=mode, targets_desc=desc, udp_ran=udp_ran)
    return NmapOutcome(findings, "ok", f"{len(res.ports)} porte aperte su {desc}")
