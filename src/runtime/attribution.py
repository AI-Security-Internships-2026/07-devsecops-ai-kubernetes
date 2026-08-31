"""
Attribute a Falco alert to the package(s) it implicates (issue #17).

Why
---
Falco reports *behaviour* ("a non-trusted program read /etc/shadow"), while Trivy
reports *packages* ("libnghttp2-14 is vulnerable"). Without a link between them the
runtime signal can only be applied to a whole image, so one alert escalates every
borderline finding on that image regardless of relevance.

The link is in the alert itself. A real Falco 0.44 alert carries:

    proc.exepath  /usr/bin/cat        <- the binary that acted; the strongest signal
    proc.name     cat
    proc.cmdline  cat /etc/shadow
    proc.pname    sh
    fd.name       /etc/shadow         <- the file touched

`/usr/bin/cat` belongs to `coreutils`. If a finding affects `coreutils`, the alert is
evidence about *that* finding. If it affects `libnghttp2-14`, the alert says nothing
about it and must not escalate it.

Method and its limits
---------------------
We do not resolve paths through the image's package database (that needs the image
filesystem, and Trivy has already discarded it by the time we score). Instead we
generate *candidate* package names from the alert's paths and match them against the
packages the findings actually name — a much smaller problem than universal path
resolution, because we only ever ask "does this alert implicate package P?" for the
P's already in scope.

The consequence is that attribution can FAIL, and failure is reported rather than
guessed around: an unattributable alert annotates a finding but never escalates it.
`attribution_rate()` exists so the evaluation can state how often the link was
actually established instead of implying it always is.

This is package-level, not function-level. Whether the vulnerable *symbol* is mapped
into the process needs /proc/<pid>/maps or call-graph analysis; that stays future work.
"""

import re

# Binaries whose owning package cannot be guessed from the name, because the package
# ships many differently-named tools. Keyed binary -> package names to consider.
# Deliberately conservative: a wrong entry here invents a causal link that is not
# there, which is worse than admitting we could not attribute the alert.
_BINARY_TO_PACKAGES = {
    # GNU coreutils
    **{b: ("coreutils",) for b in (
        "cat", "ls", "cp", "mv", "rm", "mkdir", "rmdir", "chmod", "chown", "ln",
        "touch", "head", "tail", "wc", "sort", "uniq", "cut", "tr", "dd", "df",
        "du", "echo", "printf", "id", "whoami", "env", "date", "sleep", "base64",
        "md5sum", "sha1sum", "sha256sum", "stat", "readlink", "dirname", "basename",
        "seq", "tee", "yes", "nohup", "nice", "timeout", "truncate", "split")},
    # util-linux
    **{b: ("util-linux",) for b in (
        "mount", "umount", "dmesg", "lsblk", "more", "su", "login", "hexdump",
        "script", "fdisk", "blkid", "findmnt", "nsenter", "unshare", "taskset",
        "flock", "rev", "col", "ionice", "chrt", "setarch", "lscpu", "hwclock")},
    # process tools
    **{b: ("procps", "procps-ng") for b in (
        "ps", "top", "free", "pkill", "pgrep", "uptime", "vmstat", "sysctl", "kill")},
    # shells
    "sh": ("dash", "busybox", "bash"),
    "ash": ("busybox",),
    "bash": ("bash",),
    "busybox": ("busybox",),
    # text processing
    **{b: ("grep",) for b in ("grep", "egrep", "fgrep")},
    **{b: ("findutils",) for b in ("find", "xargs")},
    "awk": ("gawk", "mawk", "busybox"),
    "sed": ("sed",),
    **{b: ("diffutils",) for b in ("diff", "cmp")},
    # archives / compression
    "tar": ("tar",),
    **{b: ("gzip",) for b in ("gzip", "gunzip", "zcat")},
    "xz": ("xz-utils",),
    "bzip2": ("bzip2",),
    "unzip": ("unzip",),
    # networking
    **{b: ("iproute2",) for b in ("ip", "ss")},
    **{b: ("net-tools",) for b in ("ifconfig", "netstat", "route", "arp")},
    "ping": ("iputils-ping", "iputils"),
    # accounts
    **{b: ("shadow", "passwd") for b in (
        "passwd", "useradd", "usermod", "userdel", "groupadd", "chpasswd", "chage")},
    # package managers
    "dpkg": ("dpkg",),
    **{b: ("apt",) for b in ("apt", "apt-get", "apt-cache")},
    "apk": ("apk-tools",),
    # language runtimes: the interpreter binary maps to its own package family
    **{b: ("python3", "python") for b in ("python", "python3")},
    **{b: ("nodejs", "node") for b in ("node", "npm", "npx")},
    "perl": ("perl",),
    "ruby": ("ruby",),
    "java": ("openjdk", "java"),
    # common services
    "nginx": ("nginx",),
    **{b: ("apache2", "httpd") for b in ("httpd", "apache2")},
    **{b: ("redis",) for b in ("redis-server", "redis-cli")},
    **{b: ("postgresql", "postgres") for b in ("postgres", "psql")},
    **{b: ("mysql", "mariadb") for b in ("mysqld", "mysql")},
    # misc
    "curl": ("curl",),
    "wget": ("wget",),
    "openssl": ("openssl",),
    "git": ("git",),
    "ssh": ("openssh-client", "openssh"),
    "sshd": ("openssh-server", "openssh"),
    "sudo": ("sudo",),
}

# A shared library path names its own package: libssl.so.3 -> libssl / libssl3.
_SO_RE = re.compile(r"/(lib[\w.+-]*?)\.so(?:\.(\d+))?", re.IGNORECASE)

# Language package managers lay packages out predictably, which is how a runtime
# event gets linked to a language-level CVE (where much of the CVE volume lives).
_LANG_DIR_RE = re.compile(
    r"/(?:site-packages|dist-packages|node_modules|gems/[^/]+/gems)/([\w.@+-]+)")


def _basename(path: str) -> str:
    return path.rsplit("/", 1)[-1] if path else ""


def candidate_packages(alert: dict) -> set[str]:
    """
    Package names an alert could plausibly be about, from its process and file paths.

    Candidates are hypotheses, not conclusions — `implicated_packages` keeps only the
    ones that match a package actually named by a finding.
    """
    cands: set[str] = set()
    paths = [alert.get("exepath") or "", alert.get("file") or ""]
    names = [alert.get("process") or "", _basename(alert.get("exepath") or "")]

    # The command line's argv[0] catches interpreters invoked by a wrapper script.
    argv = (alert.get("cmdline") or "").split()
    if argv:
        names.append(_basename(argv[0]))

    for name in names:
        if not name:
            continue
        cands.add(name)
        cands.update(_BINARY_TO_PACKAGES.get(name, ()))
        # python3.9 also stands in for python3 / python
        stem = re.sub(r"[\d.]+$", "", name)
        if stem and stem != name:
            cands.add(stem)
            cands.update(_BINARY_TO_PACKAGES.get(stem, ()))

    for path in paths:
        if not path:
            continue
        for m in _SO_RE.finditer(path):
            lib, ver = m.group(1), m.group(2)
            cands.add(lib)
            if ver:
                cands.add(f"{lib}{ver}")           # libssl.so.3 -> libssl3
            if lib.lower().startswith("lib"):
                cands.add(lib[3:])                 # libssl -> ssl
        for m in _LANG_DIR_RE.finditer(path):
            cands.add(m.group(1))
        # A binary under a local prefix names itself: /usr/local/bin/foo -> foo
        if "/bin/" in path or "/sbin/" in path:
            base = _basename(path)
            if base:
                cands.add(base)
                cands.update(_BINARY_TO_PACKAGES.get(base, ()))

    return {c.lower() for c in cands if c and len(c) > 1}


def _names_match(candidate: str, package: str) -> bool:
    """
    Whether a candidate name refers to the same package as a Trivy package name.

    Distro packages carry suffixes Trivy reports verbatim (`libnghttp2-14`,
    `python3.11`), so prefix matching is needed — but only where the remainder starts
    with a digit or separator. Without that guard `sh` would match `shadow`, which is
    exactly the kind of invented link this module exists to avoid.
    """
    a, b = candidate.lower(), package.lower()
    if a == b:
        return True
    for long, short in ((a, b), (b, a)):
        if long.startswith(short) and len(long) > len(short):
            rest = long[len(short):]
            if not rest[0].isalpha():
                return True
    return False


def match_packages(candidates: set[str], packages) -> set[str]:
    """
    Which of `packages` any candidate name refers to.

    Split out from `implicated_packages` so a caller scoring many findings against the
    same few alerts can derive each alert's candidates once and reuse them.
    """
    if not candidates:
        return set()
    return {p for p in packages if p and any(_names_match(c, p) for c in candidates)}


def implicated_packages(alert: dict, packages) -> set[str]:
    """Which of `packages` this alert is evidence about (possibly none)."""
    return match_packages(candidate_packages(alert), packages)


def attribute_alerts(alerts: list[dict], packages) -> list[dict]:
    """
    Annotate each alert with the subset of `packages` it implicates.

    `packages` is the set of package names appearing across an image's findings, so
    attribution is scoped to what is actually being triaged.
    """
    pkgs = sorted({str(p) for p in (packages or []) if p})
    out = []
    for a in alerts:
        hit = implicated_packages(a, pkgs)
        out.append({**a, "packages": sorted(hit)})
    return out


def attribution_rate(attributed_alerts: list[dict]) -> float:
    """
    Fraction of alerts linked to at least one package.

    Reported alongside the results so the evaluation can state how often the runtime
    signal could be tied to a package, rather than implying it always can.
    """
    if not attributed_alerts:
        return 0.0
    linked = sum(1 for a in attributed_alerts if a.get("packages"))
    return linked / len(attributed_alerts)
