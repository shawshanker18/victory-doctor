#!/usr/bin/env python3
"""victory-doctor: diagnose VIctory runs, match their failures with known GitHub
issues and pull requests, and keep a shared record of runs.

  python victory_doctor.py run -- victory.exe run <title exe> --execute
  python victory_doctor.py scan <log> [--crashes <crashes.log>]
  python victory_doctor.py open|draft|post|comment <signature number> ...
  python victory_doctor.py compare <log or run A> <log or run B>
  python victory_doctor.py record|submit|stats ...
  python victory_doctor.py selftest

Python 3.9+, standard library only. Nothing is sent anywhere unless you run
`post`, `comment` or `submit` and confirm; GitHub searches send only the
failure's search terms (offsets, error codes, message text).
"""

import argparse
import datetime
import hashlib
import json
import os
import platform
import re
import statistics
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from pathlib import Path

VERSION = "0.1.0"
DEFAULT_REPOS = ["Marvisak/VIctory", "fxceless/victory-fork"]
RUNS_REPO = os.environ.get("VICTORY_DOCTOR_RUNS_REPO", "shawshanker18/victory-runs")
HOME = Path(os.environ.get("LOCALAPPDATA") or Path.home() / ".local" / "share") / "victory-doctor"
CACHE_HOURS = 12

# ---------------------------------------------------------------------------
# Reading logs
# ---------------------------------------------------------------------------

ANSI = re.compile(r"\x1b\[[0-9;]*m")
LINE = re.compile(r"^\S+Z\s+(TRACE|DEBUG|INFO|WARN|ERROR)\s+([\w:]+):\s?(.*)$")
CRASH = re.compile(
    r"unhandled exception (0x[0-9a-fA-F]+) at ([\w.\-]+)\+(0x[0-9a-fA-F]+)"
    r"(?: \((read|write|execute) (0x[0-9a-fA-F]+)(?::\s*([^)]*))?\))?"
)
FRAME = re.compile(r"#\d+\s+([\w.\-]+)\+(0x[0-9a-fA-F]+)")
FPS = re.compile(
    r"([\d.]+) fps, ([\d.]+) ms/frame \(([\d.]+) preparing.*?; ([\d.]+) on the GPU; "
    r"([\d.]+) copying back.*?\), (\d+) draws/frame"
)
FPS_SIMPLE = re.compile(r"([\d.]+) fps, ([\d.]+) ms/frame.*?(\d+) draws/frame")
DEVICE = re.compile(r"(0x887A000[1-7]|DXGI_ERROR_[A-Z_]+)", re.I)
HASH16 = re.compile(r"\b[0-9a-f]{16}\b")
# A shader named in a message: `hash=<16 hex>` or `[compute <16 hex>, pixel ...]`.
SHADER = re.compile(r"(?:hash=|\b(?:compute|mesh|pixel|vertex|geometry|hull|domain|amplification) )\"?([0-9a-f]{16})\b")
# Fields that tell two messages of one kind apart.
KEY_FIELDS = re.compile(r"\b(slot|format|stage|dimension|kind|dll)=(\"?[\w.]+\"?)")
POOL = re.compile(r"^\s*-\s*([A-Z_]+):\s*(\d+)/(\d+)\s*$")
IMAGE = re.compile(r"victory-image-[0-9a-f]{16}\.dll", re.I)

NAMES = {
    "0xc0000005": "access violation",
    "0x80000003": "breakpoint (the title stopped itself)",
    "0xc000001d": "illegal instruction (CPU lacks an instruction the title uses)",
    "0xc0000409": "stack buffer overrun",
    "0xc00000fd": "stack overflow",
    "0x887a0001": "DXGI_ERROR_INVALID_CALL (device removed)",
    "0x887a0004": "DXGI_ERROR_UNSUPPORTED",
    "0x887a0005": "DXGI_ERROR_DEVICE_REMOVED",
    "0x887a0006": "DXGI_ERROR_DEVICE_HUNG (GPU hang, TDR)",
    "0x887a0007": "DXGI_ERROR_DEVICE_RESET",
}

# Messages that say nothing went wrong, or are expected every run.
QUIET = [
    "VICTORY_SHADER_LOOP_LIMIT",
    "a texture picked by index changed after its upload",
    "levels after the black frame",
]

# Advice for failures whose cause is well known, keyed by a substring of the
# signature key.
ADVICE = {
    "os error 1455": "Windows ran out of commit: close other programs or raise the paging file size (Task Manager > Performance > Memory > Committed).",
    "0xc000001d": "Your CPU lacks an instruction the title uses (CLWB/CLZERO/MONITORX): look for the CPU-emulation patches in the matches.",
    "view heap capped": "NVIDIA drivers cap shader-visible heaps at 1,000,000 descriptors; the title asks for 1,245,184 (see the matches).",
    "title slot past the host heap": "NVIDIA drivers cap shader-visible heaps at 1,000,000 descriptors; the title asks for 1,245,184 (see the matches).",
    "pool INSTANCE_LIST full": "The title's instance pool filled up; this follows very low frame rates in the world.",
}


def clean(text):
    return ANSI.sub("", text)


def template(message):
    """A message with its numbers, addresses and hashes taken out."""
    t = HASH16.sub("<hash>", message)
    t = re.sub(r"0x[0-9a-fA-F]+", "<addr>", t)
    t = re.sub(r"\d+(\.\d+)?", "<n>", t)
    return t


def phrase(message):
    """The words of a message before its first key=value field: what to search for."""
    words = []
    for w in message.split():
        if "=" in w or w.startswith("[") or w.startswith("("):
            break
        if re.search(r"\d", w):
            break
        words.append(w.strip(":;,."))
    return " ".join(words[:9])


class Signature:
    def __init__(self, kind, key, title, terms, severity):
        self.kind, self.key, self.title, self.terms, self.severity = kind, key, title, terms, severity
        self.count = 0
        self.first = None
        self.excerpt = []
        self.details = {}
        self.matches = []
        self.status = "not checked"

    def to_json(self):
        return {k: getattr(self, k) for k in
                ("kind", "key", "title", "terms", "severity", "count", "first", "excerpt", "details", "matches", "status")}

    @staticmethod
    def from_json(d):
        s = Signature(d["kind"], d["key"], d["title"], d["terms"], d["severity"])
        for k in ("count", "first", "excerpt", "details", "matches", "status"):
            setattr(s, k, d.get(k, getattr(s, k)))
        return s


SEVERITY = {"crash": 0, "device": 1, "commit": 1, "pool": 2, "error": 3, "warn": 4}


def add(found, sig, line_no=None, context=None):
    s = found.get(sig.key)
    if s is None:
        s = found[sig.key] = sig
        s.first = line_no
        if context:
            s.excerpt = context
    s.count += 1
    return s


def scan_lines(lines, found, source):
    """Signatures from a VIctory log (stderr) or a crashes.log."""
    lines = [clean(l.rstrip("\n")) for l in lines]
    for i, line in enumerate(lines):
        ctx = lambda: [redact(l) for l in lines[max(0, i - 3): i + 8]]
        m = CRASH.search(line)
        if m:
            code, module, off, access, addr, what = m.groups()
            code = code.lower()
            image = bool(IMAGE.match(module))
            where = f"image+{off.lower()}" if image else f"{module}+{off.lower()}"
            terms = [off.lower()] if image else []
            if not image:
                # Our own code: offsets change with every build; name the
                # title's frame below it instead.
                for later in lines[i + 1: i + 14]:
                    f = FRAME.search(later)
                    if f and IMAGE.match(f.group(1)):
                        terms = [f.group(2).lower()]
                        where += f" (title frame image+{f.group(2).lower()})"
                        break
            if not terms:
                terms = [code]
            label = NAMES.get(code, code)
            extra = f" ({access} {addr})" if access else ""
            s = add(found, Signature("crash", f"crash {code} at {where}", f"Crash: {label} at {where}{extra}",
                                     terms, "crash"), i + 1, ctx())
            s.details.setdefault("source", source)
            continue
        if "os error 1455" in line or "commit limit reached" in line:
            add(found, Signature("commit", "os error 1455", "Windows commit limit reached (os error 1455)",
                                 ["1455", "commit limit"], "commit"), i + 1, ctx())
            continue
        m = LINE.match(line)
        if not m:
            d = DEVICE.search(line)
            if d and ("removed" in line.lower() or "hung" in line.lower()):
                code = d.group(1).lower()
                add(found, Signature("device", f"device {code}", f"GPU device lost: {NAMES.get(code, code)}",
                                     [code], "device"), i + 1, ctx())
            continue
        level, module, message = m.groups()
        if level not in ("WARN", "ERROR"):
            continue
        if any(q in message for q in QUIET):
            continue
        d = DEVICE.search(message)
        if d and ("removed" in message.lower() or "hung" in message.lower() or "device" in message.lower()):
            code = d.group(1).lower()
            s = add(found, Signature("device", f"device {code}", f"GPU device lost: {NAMES.get(code, code)}",
                                     [code], "device"), i + 1, ctx())
            continue
        words = phrase(message)
        fields = " ".join(f"{k}={v}" for k, v in KEY_FIELDS.findall(message))
        key = f"{module}: {words or template(message)[:120]}" + (f" ({fields})" if fields else "")
        terms = [f'"{words}"'] if len(words.split()) >= 3 else []
        hashes = SHADER.findall(message)
        title = f"{level.title()}: {words or message[:80]}" + (f" ({fields})" if fields else "")
        s = add(found, Signature(level.lower(), key, title, terms,
                                 level.lower()), i + 1, ctx())
        if hashes:
            seen = s.details.setdefault("hashes", [])
            for h in hashes:
                if h not in seen and len(seen) < 12:
                    seen.append(h)


def scan_title_crash(lines, found, source):
    """The title's own crash report (`victory-*.crash.log` in its temp folder)."""
    lines = [clean(l.rstrip("\n")) for l in lines]
    in_pools = False
    state = {}
    for i, line in enumerate(lines):
        if line.startswith("========="):
            in_pools = "POOLS" in line
            continue
        for k in ("Game State", "Current SRL State", "Conole Type", "Version", "Frame", "Game Running Time"):
            if line.startswith(k + ":"):
                state[k.replace("Conole", "Console")] = line.split(":", 1)[1].strip()
        if in_pools:
            m = POOL.match(line)
            if m and int(m.group(3)) > 0 and int(m.group(2)) >= int(m.group(3)):
                name = m.group(1)
                s = add(found, Signature("pool", f"pool {name} full", f"The title's {name} pool is full ({m.group(2)}/{m.group(3)})",
                                         [name], "pool"), i + 1, [line.strip()])
                s.details["title state"] = state
                s.details.setdefault("source", source)


def log_start(log):
    """When a log's run started (unix seconds): its first timestamp, else the file's."""
    with open(log, errors="replace") as f:
        for _ in range(50):
            m = re.match(r"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)", clean(f.readline()))
            if m:
                t = datetime.datetime.fromisoformat(m.group(1)).replace(tzinfo=datetime.timezone.utc)
                return int(t.timestamp())
    st = Path(log).stat()
    return int(min(st.st_mtime, st.st_ctime))


def find_crash_files(log_path):
    """crashes.log and the title's crash reports near the default data folder."""
    out = []
    base = Path(os.environ.get("LOCALAPPDATA", "")) / "victory" / "data"
    if base.is_dir():
        for title in base.iterdir():
            c = title / "crashes.log"
            if c.is_file():
                out.append(("crashes", c))
            temp = title / "temp"
            if temp.is_dir():
                for f in sorted(temp.glob("victory-*.crash.log"), key=lambda p: p.stat().st_mtime)[-3:]:
                    out.append(("title-crash", f))
    return out


def tail_since(path, since):
    """The entries of crashes.log written after `since` (unix seconds)."""
    text = path.read_text(errors="replace")
    blocks = re.split(r"\n(?=unix time )", text)
    keep = []
    for b in blocks:
        m = re.match(r"unix time (\d+)", b)
        if m and int(m.group(1)) >= since:
            keep.append(b)
    return "\n".join(keep).splitlines()


def scan(log, crashes=None, title_crashes=(), since=None):
    found = {}
    if log:
        scan_lines(Path(log).read_text(errors="replace").splitlines(), found, str(log))
    if crashes:
        lines = tail_since(Path(crashes), since) if since else Path(crashes).read_text(errors="replace").splitlines()
        scan_lines(lines, found, str(crashes))
    for t in title_crashes:
        scan_title_crash(Path(t).read_text(errors="replace").splitlines(), found, str(t))
    return sorted(found.values(), key=lambda s: (SEVERITY.get(s.severity, 9), -s.count))


# ---------------------------------------------------------------------------
# Privacy
# ---------------------------------------------------------------------------

USER = re.compile(r"([A-Za-z]:\\Users\\)[^\\/\s]+", re.I)
HOMEDIR = re.compile(r"/home/[^/\s]+|/Users/[^/\s]+")


def redact(text):
    text = USER.sub(r"\1<user>", text)
    text = HOMEDIR.sub("<home>", text)
    name = os.environ.get("USERNAME") or os.environ.get("USER")
    if name and len(name) > 2:
        text = re.sub(re.escape(name), "<user>", text, flags=re.I)
    host = platform.node()
    if host and len(host) > 2:
        text = re.sub(re.escape(host), "<host>", text, flags=re.I)
    return text


# ---------------------------------------------------------------------------
# GitHub
# ---------------------------------------------------------------------------

def token():
    t = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if t:
        return t
    try:
        r = subprocess.run(["gh", "auth", "token"], capture_output=True, text=True, timeout=10)
        if r.returncode == 0 and r.stdout.strip():
            return r.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        pass
    return None


def api(path, params=None, method="GET", body=None, tok=None):
    url = "https://api.github.com" + path
    if params:
        url += "?" + urllib.parse.urlencode(params)
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("User-Agent", f"victory-doctor/{VERSION}")
    if tok:
        req.add_header("Authorization", f"Bearer {tok}")
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read().decode())


class Searcher:
    def __init__(self, repos, offline=False):
        self.repos = repos
        self.offline = offline
        self.tok = None if offline else token()
        self.gap = 2.2 if self.tok else 6.5
        self.last = 0.0
        self.cache_path = HOME / "cache.json"
        try:
            self.cache = json.loads(self.cache_path.read_text())
        except (OSError, ValueError):
            self.cache = {}

    def save(self):
        HOME.mkdir(parents=True, exist_ok=True)
        self.cache_path.write_text(json.dumps(self.cache))

    def search(self, terms):
        q = " ".join(terms) + " " + " ".join(f"repo:{r}" for r in self.repos)
        hit = self.cache.get(q)
        if hit and time.time() - hit["at"] < CACHE_HOURS * 3600:
            return hit["items"]
        if self.offline:
            return hit["items"] if hit else None
        wait = self.last + self.gap - time.time()
        if wait > 0:
            time.sleep(wait)
        for attempt in range(3):
            try:
                self.last = time.time()
                r = api("/search/issues", {"q": q, "per_page": 15}, tok=self.tok)
                break
            except urllib.error.HTTPError as e:
                if e.code in (403, 429) and attempt < 2:
                    time.sleep(30 if not self.tok else 10)
                    continue
                print(f"  (GitHub search failed: {e.code}; skipped)", file=sys.stderr)
                return None
            except (urllib.error.URLError, TimeoutError) as e:
                print(f"  (GitHub unreachable: {e}; skipped)", file=sys.stderr)
                return None
        items = []
        for it in r.get("items", []):
            pr = it.get("pull_request")
            items.append({
                "repo": it["repository_url"].split("/repos/", 1)[1],
                "number": it["number"],
                "title": it["title"],
                "url": it["html_url"],
                "state": it["state"],
                "pr": bool(pr),
                "merged": bool(pr and pr.get("merged_at")),
                "comments": it.get("comments", 0),
                "updated": it.get("updated_at", "")[:10],
            })
        self.cache[q] = {"at": time.time(), "items": items}
        return items


def status_of(items):
    if items is None:
        return "not checked"
    if any(i["merged"] for i in items):
        return "fix merged"
    if any(i["pr"] and i["state"] == "open" for i in items):
        return "fix proposed"
    if any(not i["pr"] and i["state"] == "open" for i in items):
        return "known, open"
    if items:
        return "known, closed"
    return "new"


def check(sigs, repos, offline=False, most=15):
    s = Searcher(repos, offline)
    for sig in sigs[:most]:
        queries = []
        if sig.terms:
            queries.append(sig.terms)
        for h in sig.details.get("hashes", [])[:2]:
            queries.append([h])
        items, seen = [], set()
        checked = False
        for q in queries:
            got = s.search(q)
            if got is None:
                continue
            checked = True
            for it in got:
                k = (it["repo"], it["number"])
                if k not in seen:
                    seen.add(k)
                    items.append(it)
        # Reports that name the failure in their title first, then open ones.
        names = [t.strip('"').lower() for t in sig.terms] + sig.details.get("hashes", [])[:2]
        items.sort(key=lambda it: (not any(n and n in it["title"].lower() for n in names),
                                   it["state"] != "open"))
        sig.matches = items
        sig.status = status_of(items if checked else None)
    s.save()
    return sigs


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

MARK = {"fix merged": "MERGED", "fix proposed": "PR", "known, open": "KNOWN", "known, closed": "CLOSED",
        "new": "NEW", "not checked": "--"}
LEGEND = ("MERGED: a merged pull request mentions it (update your build)   PR: an open pull request mentions it\n"
          "KNOWN: open issues report it   CLOSED: only closed reports   NEW: nobody has reported it yet\n")


def show(sigs, limit=8):
    if not sigs:
        print("No failures found.")
        return
    print(f"{len(sigs)} failure signature(s), most severe first.\n{LEGEND}")
    for n, s in enumerate(sigs, 1):
        print(f"[{n}] {MARK.get(s.status, '?'):6} {s.title}  (x{s.count})")
        for k, v in ADVICE.items():
            if k in s.key:
                print(f"       advice: {v}")
        if s.details.get("hashes"):
            print(f"       shaders: {', '.join(s.details['hashes'][:6])}")
        if s.status == "new":
            print("       Nobody has reported this yet: `draft " + str(n) + "` or `post " + str(n) + "`.")
        others = [m for m in s.matches if not m["pr"]]
        if others:
            print(f"       {len(others)} report(s) by others; join them with `comment {n} --issue <number>`.")
        for m in s.matches[:limit]:
            kind = "PR" if m["pr"] else "issue"
            st = "merged" if m["merged"] else m["state"]
            print(f"       {m['repo']}#{m['number']} {kind} {st}, {m['comments']} comments: {m['title'][:90]}")
        print()


def last_path():
    return HOME / "last-scan.json"


def save_last(sigs, meta):
    HOME.mkdir(parents=True, exist_ok=True)
    last_path().write_text(json.dumps({"meta": meta, "signatures": [s.to_json() for s in sigs]}, indent=1))


def load_last():
    try:
        d = json.loads(last_path().read_text())
    except (OSError, ValueError):
        sys.exit("No scan yet: run `scan <log>` first.")
    return d["meta"], [Signature.from_json(s) for s in d["signatures"]]


def pick(n):
    meta, sigs = load_last()
    if not 1 <= n <= len(sigs):
        sys.exit(f"Signature {n} not in the last scan (1-{len(sigs)}).")
    return meta, sigs[n - 1]


# ---------------------------------------------------------------------------
# Machine and run records
# ---------------------------------------------------------------------------

def powershell(cmd):
    try:
        r = subprocess.run(["powershell", "-NoProfile", "-Command", cmd], capture_output=True, text=True, timeout=30)
        return r.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return ""


def machine():
    m = {"os": f"{platform.system()} {platform.release()} {platform.version()}", "cpu": platform.processor()}
    if platform.system() == "Windows":
        cpu = powershell("(Get-CimInstance Win32_Processor | Select-Object -First 1).Name")
        if cpu:
            m["cpu"] = cpu
        gpus = powershell("Get-CimInstance Win32_VideoController | ForEach-Object { $_.Name + '|' + $_.DriverVersion }")
        m["gpus"] = [g.split("|")[0] + " (driver " + g.split("|")[1] + ")" for g in gpus.splitlines() if "|" in g]
        ram = powershell("[math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB)")
        if ram:
            m["ram_gb"] = int(float(ram))
    return m


def settings_from_env(env=None):
    env = env or os.environ
    out = {}
    for k, v in sorted(env.items()):
        if k.startswith("VICTORY_") and "TOKEN" not in k and "KEY" not in k:
            out[k] = redact(v) if ("\\" in v or "/" in v) else v
    return out


def performance(log):
    """Frame rates from the log's frame-rate lines, world frames only (500+ draws)."""
    rows = []
    for line in Path(log).read_text(errors="replace").splitlines():
        line = clean(line)
        m = FPS.search(line)
        if m:
            fps, ms, prep, gpu, back, draws = m.groups()
            rows.append((float(fps), float(ms), float(gpu), int(draws)))
            continue
        m = FPS_SIMPLE.search(line)
        if m:
            rows.append((float(m.group(1)), float(m.group(2)), None, int(m.group(3))))
    world = [r for r in rows if r[3] >= 500]
    perf = {"frame_lines": len(rows), "reached": "boot"}
    if rows:
        perf["reached"] = "menus"
    if world:
        perf["reached"] = "world"
        last = world[-60:]
        fps = sorted(r[0] for r in last)
        perf.update({
            "world_lines": len(world),
            "fps_median": statistics.median(fps),
            "fps_p10": fps[len(fps) // 10],
            "fps_p90": fps[min(len(fps) - 1, len(fps) * 9 // 10)],
            "ms_median": statistics.median(r[1] for r in last),
            "draws_median": statistics.median(r[3] for r in last),
        })
        g = [r[2] for r in last if r[2] is not None]
        if g:
            perf["gpu_ms_median"] = statistics.median(g)
    return perf


def build_info(log):
    """The title build and console mode, from the log or its companion .out."""
    info = {}
    for p in (Path(str(log) + ".out"), Path(log)):
        try:
            text = clean(p.read_text(errors="replace"))
        except OSError:
            continue
        m = re.search(r"^build\s+(.+)$", text, re.M)
        if m:
            info["title_build"] = m.group(1).strip()[:120]
        m = re.search(r"--console\s+(series-[xs])", text)
        if m:
            info["console"] = m.group(1)
    return info


def make_record(log, sigs, settings=None, emulator=None, note=None, mach=None):
    text = Path(log).read_bytes()
    rec = {
        "schema": 1,
        "id": hashlib.sha256(text).hexdigest()[:16],
        "date": datetime.datetime.fromtimestamp(Path(log).stat().st_mtime, datetime.timezone.utc).isoformat()[:19] + "Z",
        "tool": VERSION,
        "machine": mach if mach is not None else machine(),
        "emulator": emulator or {},
        "settings": settings or {},
        "performance": performance(log),
        "failures": [{"key": s.key, "count": s.count, "status": s.status} for s in sigs[:20]],
    }
    rec["emulator"].update(build_info(log))
    if note:
        rec["note"] = note
    return rec


def runs_dir():
    d = HOME / "runs"
    d.mkdir(parents=True, exist_ok=True)
    return d


def save_record(rec):
    p = runs_dir() / f"{rec['id']}.json"
    p.write_text(json.dumps(rec, indent=1))
    return p


def load_record(ref):
    p = Path(ref)
    if p.is_file() and p.suffix == ".json":
        return json.loads(p.read_text())
    p = runs_dir() / f"{ref}.json"
    if p.is_file():
        return json.loads(p.read_text())
    return None


# ---------------------------------------------------------------------------
# Drafts and posting (always confirmed by the person running the tool)
# ---------------------------------------------------------------------------

def environment_block(meta):
    m = meta.get("machine") or machine()
    lines = [f"- OS: {m.get('os', '?')}", f"- CPU: {m.get('cpu', '?')}"]
    for g in m.get("gpus", []):
        lines.append(f"- GPU: {g}")
    if m.get("ram_gb"):
        lines.append(f"- RAM: {m['ram_gb']} GB")
    if meta.get("settings"):
        lines.append("- Settings: " + ", ".join(f"`{k}={v}`" for k, v in meta["settings"].items()))
    if meta.get("emulator"):
        lines.append("- Emulator: " + ", ".join(f"{k} {v}" for k, v in meta["emulator"].items()))
    return "\n".join(lines)


def issue_draft(meta, s):
    title = s.title[:120]
    related = "\n".join(f"- {m['repo']}#{m['number']} ({'PR' if m['pr'] else 'issue'}, "
                        f"{'merged' if m['merged'] else m['state']}): {m['title']}" for m in s.matches[:8])
    body = f"""### What happened

{s.title} (seen {s.count} time(s) in one run).

```
{chr(10).join(s.excerpt[:14])}
```

### Environment

{environment_block(meta)}

### Related reports found

{related or "None found (searched open and closed issues and pull requests)."}

Found with victory-doctor {VERSION}. No game data; user names and paths are removed from the excerpt.
"""
    return title, redact(body)


def comment_draft(meta, s, issue):
    body = f"""Seen here too ({s.count} time(s) in one run).

```
{chr(10).join(s.excerpt[:10])}
```

{environment_block(meta)}

Found with victory-doctor {VERSION}; user names and paths removed.
"""
    return redact(body)


def confirm(question):
    try:
        return input(question + " [y/N] ").strip().lower() in ("y", "yes")
    except EOFError:
        return False


def to_clipboard(text):
    try:
        if platform.system() == "Windows":
            subprocess.run(["clip"], input=text.encode("utf-16le"), check=True)
            return True
    except (OSError, subprocess.SubprocessError):
        pass
    return False


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_scan(a):
    crash_files = []
    if a.crashes:
        crash_files.append(("crashes", Path(a.crashes)))
    if not a.no_auto:
        crash_files += [c for c in find_crash_files(a.log) if c[1] != (Path(a.crashes) if a.crashes else None)]
    since = None
    if a.log and not a.all_crashes:
        since = log_start(a.log) - (a.hours * 3600)
    crashes = next((p for k, p in crash_files if k == "crashes"), None)
    end = Path(a.log).stat().st_mtime + 300 if a.log else None
    titles = [p for k, p in crash_files if k == "title-crash"
              and (since is None or since <= p.stat().st_mtime <= end)]
    sigs = scan(a.log, crashes, titles, since)
    if not a.offline:
        print(f"Looking up {min(len(sigs), a.most)} signature(s) on GitHub ({', '.join(a.repos)})...", file=sys.stderr)
    check(sigs, a.repos, a.offline, a.most)
    meta = {"log": str(a.log), "settings": settings_from_env(), "machine": machine() if not a.offline else {}}
    save_last(sigs, meta)
    if a.json:
        Path(a.json).write_text(json.dumps([s.to_json() for s in sigs], indent=1))
    show(sigs)
    if a.log:
        rec = make_record(a.log, sigs, meta["settings"], mach=meta["machine"])
        p = save_record(rec)
        print(f"Run record saved: {p.name} (share it with `submit {rec['id']}`)")


def cmd_open(a):
    _, s = pick(a.signature)
    if not s.matches:
        sys.exit("No matches for that signature.")
    m = s.matches[min(a.n, len(s.matches)) - 1]
    print(m["url"])
    webbrowser.open(m["url"])


def cmd_draft(a):
    meta, s = pick(a.signature)
    title, body = issue_draft(meta, s)
    out = Path(a.out or f"issue-draft-{a.signature}.md")
    out.write_text(f"# {title}\n\n{body}")
    print(f"Draft written to {out}. Read it, then `post {a.signature}`.")


def cmd_post(a):
    meta, s = pick(a.signature)
    if s.matches and not a.anyway:
        print("Others have reported something matching this already:")
        for m in s.matches[:5]:
            print(f"  {m['url']}  {m['title'][:80]}")
        print("Consider `comment` on one of them instead; `post --anyway` opens a new issue.")
        return
    title, body = issue_draft(meta, s)
    print(f"Title: {title}\n\n{body}")
    if not confirm(f"Open a new issue on {a.repo} with this text in your browser?"):
        return
    url = f"https://github.com/{a.repo}/issues/new?" + urllib.parse.urlencode({"title": title, "body": body[:6000]})
    webbrowser.open(url)
    print("Your browser has the issue form filled in: check it and submit it there.")


def cmd_comment(a):
    meta, s = pick(a.signature)
    body = comment_draft(meta, s, a.issue)
    print(body)
    repo = a.repo
    url = f"https://github.com/{repo}/issues/{a.issue}"
    tok = token()
    if a.api and tok:
        if confirm(f"Post this comment on {repo}#{a.issue} now, as the account of your GitHub token?"):
            r = api(f"/repos/{repo}/issues/{a.issue}/comments", method="POST", body={"body": body}, tok=tok)
            print("Posted:", r.get("html_url"))
        return
    if confirm(f"Copy the comment to the clipboard and open {url}?"):
        print("Copied." if to_clipboard(body) else "Copy it from above.")
        webbrowser.open(url)


def cmd_compare(a):
    def load(ref):
        rec = load_record(ref)
        if rec is not None:
            return rec, {f["key"]: f["count"] for f in rec["failures"]}
        sigs = scan(ref)
        return make_record(ref, sigs, mach={}), {s.key: s.count for s in sigs}

    (ra, fa), (rb, fb) = load(a.a), load(a.b)
    print(f"A: {a.a}\nB: {a.b}\n")
    pa, pb = ra["performance"], rb["performance"]
    for k in ("reached", "fps_median", "ms_median", "gpu_ms_median", "draws_median"):
        va, vb = pa.get(k), pb.get(k)
        if va is None and vb is None:
            continue
        diff = ""
        if isinstance(va, (int, float)) and isinstance(vb, (int, float)) and va:
            diff = f"  ({(vb - va) / va * 100:+.0f}%)"
        print(f"  {k:14} {va!s:>10} -> {vb!s:<10}{diff}")
    sa, sb = set(fa), set(fb)
    print("\nOnly in B (new):")
    for k in sorted(sb - sa):
        print(f"  + {k}  x{fb[k]}")
    print("Only in A (gone in B):")
    for k in sorted(sa - sb):
        print(f"  - {k}  x{fa[k]}")
    both = sorted(sa & sb)
    if both:
        print(f"In both: {len(both)}")
    sets = {**ra.get("settings", {}), **rb.get("settings", {})}
    changed = {k: (ra.get("settings", {}).get(k), rb.get("settings", {}).get(k)) for k in sets
               if ra.get("settings", {}).get(k) != rb.get("settings", {}).get(k)}
    if changed:
        print("\nSettings that differ:")
        for k, (x, y) in sorted(changed.items()):
            print(f"  {k}: {x} -> {y}")


def cmd_record(a):
    settings = dict(kv.split("=", 1) for kv in a.setting) if a.setting else settings_from_env()
    sigs = scan(a.log)
    rec = make_record(a.log, sigs, settings, {"name": a.emulator} if a.emulator else {}, a.note)
    p = save_record(rec)
    print(json.dumps(rec, indent=1))
    print(f"\nSaved {p}")


def cmd_submit(a):
    rec = load_record(a.run)
    if rec is None:
        sys.exit("No such run record (see the runs folder: " + str(runs_dir()) + ").")
    body = "```json\n" + json.dumps(rec, indent=1) + "\n```\n\nSubmitted with victory-doctor " + VERSION + "."
    title = f"[run] {rec['performance'].get('reached', '?')} " \
            f"{(rec['machine'].get('gpus') or ['?'])[0][:40]} " \
            f"{rec['performance'].get('fps_median', '')} fps"
    print(title + "\n\n" + body)
    tok = token()
    if a.api and tok:
        if confirm(f"Create this run report on {RUNS_REPO} now, as the account of your GitHub token?"):
            r = api(f"/repos/{RUNS_REPO}/issues", method="POST", body={"title": title, "body": body}, tok=tok)
            print("Submitted:", r.get("html_url"))
        return
    if confirm(f"Open the run report form on {RUNS_REPO} in your browser?"):
        webbrowser.open(f"https://github.com/{RUNS_REPO}/issues/new?" +
                        urllib.parse.urlencode({"title": title, "body": body[:7000]}))


def cmd_stats(a):
    url = f"https://raw.githubusercontent.com/{RUNS_REPO}/main/data/runs.jsonl"
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "victory-doctor"}), timeout=30) as r:
            rows = [json.loads(l) for l in r.read().decode().splitlines() if l.strip()]
    except (urllib.error.URLError, ValueError) as e:
        sys.exit(f"Could not read the shared runs ({e}).")
    rows += [json.loads(p.read_text()) for p in runs_dir().glob("*.json")] if a.mine else []
    if a.gpu:
        rows = [r for r in rows if any(a.gpu.lower() in g.lower() for g in r["machine"].get("gpus", []))]
    if a.setting:
        rows = [r for r in rows if a.setting in r.get("settings", {})]
    print(f"{len(rows)} run(s)\n")
    groups = {}
    for r in rows:
        gpu = next((g for g in r["machine"].get("gpus", []) if "Radeon(TM) Graphics" not in g), "?")
        key = (gpu.split(" (driver")[0], r["emulator"].get("console", "?"))
        groups.setdefault(key, []).append(r)
    for (gpu, console), rs in sorted(groups.items()):
        fps = [r["performance"]["fps_median"] for r in rs if r["performance"].get("fps_median")]
        world = sum(1 for r in rs if r["performance"].get("reached") == "world")
        best = max(rs, key=lambda r: r["performance"].get("fps_median") or 0)
        print(f"{gpu} [{console}]: {len(rs)} run(s), {world} reached the world"
              + (f", median {statistics.median(fps):.1f} fps, best {max(fps):.1f}" if fps else ""))
        if best["performance"].get("fps_median"):
            print("   best settings: " + (", ".join(f"{k}={v}" for k, v in best.get("settings", {}).items()) or "defaults"))
    common = {}
    for r in rows:
        for f in r.get("failures", [])[:5]:
            common[f["key"]] = common.get(f["key"], 0) + 1
    if common:
        print("\nMost common failures:")
        for k, n in sorted(common.items(), key=lambda x: -x[1])[:10]:
            print(f"  {n:3} run(s): {k}")


def cmd_run(a):
    """Runs the emulator, keeps its log, reports new failures as they happen."""
    if not a.cmd:
        sys.exit("Usage: run -- victory.exe run <title exe> --execute [more arguments]")
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    d = runs_dir() / stamp
    d.mkdir(parents=True, exist_ok=True)
    log = d / "run.log"
    env = dict(os.environ)
    env.setdefault("VICTORY_LOG", "info")
    started = int(time.time())
    print(f"Logging to {log}. Failures are listed as they appear; Ctrl+C stops the game.")
    with open(log, "w", encoding="utf-8", errors="replace") as out:
        proc = subprocess.Popen(a.cmd, stderr=subprocess.PIPE, stdout=subprocess.PIPE, env=env,
                                text=True, errors="replace", bufsize=1)
        seen = {}

        def pump(stream, keep):
            for line in stream:
                if keep:
                    out.write(line)
                found = {}
                scan_lines([line], found, "live")
                for k, s in found.items():
                    if k not in seen:
                        seen[k] = s
                        print(f"  new: {s.title}")
                m = FPS_SIMPLE.search(clean(line))
                if m and int(m.group(3)) >= 500 and time.time() - pump.last > 30:
                    pump.last = time.time()
                    print(f"  {m.group(1)} fps, {m.group(2)} ms/frame, {m.group(3)} draws/frame")
        pump.last = 0.0
        t = threading.Thread(target=pump, args=(proc.stderr, True), daemon=True)
        t.start()
        (d / "run.log.out").write_text(" ".join(a.cmd) + "\n")
        try:
            for line in proc.stdout:
                with open(d / "run.log.out", "a", encoding="utf-8") as o:
                    o.write(line)
            proc.wait()
        except KeyboardInterrupt:
            proc.kill()
        t.join(timeout=5)
    print(f"\nThe game exited ({proc.returncode}). Diagnosing...\n")
    ns = argparse.Namespace(log=str(log), crashes=None, no_auto=False, all_crashes=False, hours=0,
                            offline=a.offline, repos=a.repos, most=a.most, json=None)
    cmd_scan(ns)


def cmd_selftest(_):
    sample = """2026-11-25T10:23:56.997492Z  WARN victory_gpu::descriptor::host: host view heap capped at 1000000; views past it read a null slot count=1245184
2026-11-25T10:24:00.000000Z  WARN victory_gpu::pipeline::host: host pipeline refused error=The parameter is incorrect. (0x80070057) shaders=[compute 6f225b641c5b0708]
2026-11-25T10:24:01.000000Z  INFO victory_gpu::host: 3.1 fps, 319.0 ms/frame (130.6 preparing: copies 70.2 ms 125.8 MB, textures 11.5 ms 30.4 MB; 114.8 on the GPU; 63.0 copying back 54.0 MB), 4706 draws/frame
unix time 1795602452, process 9072
VIctory: unhandled exception 0xc0000005 at victory-image-b99f876b74d4a77f.dll+0x23cf683 (write 0x0: nothing mapped there)
  #0  victory-image-b99f876b74d4a77f.dll+0x23cf683
VIctory: unhandled exception 0xc0000005 at VCRUNTIME140.dll+0x1dafb (read 0xb5bb40000: reserved, never committed)
  #0  VCRUNTIME140.dll+0x1dafb
  #6  victory-image-b99f876b74d4a77f.dll+0x24821e3
VIctory: Windows commit limit reached while committing 6538919936 bytes of physical pages: The paging file is too small for this operation to complete. (os error 1455).
C:\\Users\\someone\\AppData\\Local\\victory
"""
    found = {}
    scan_lines(sample.splitlines(), found, "selftest")
    keys = set(found)
    assert "crash 0xc0000005 at image+0x23cf683" in keys, keys
    assert any(k.startswith("crash 0xc0000005 at VCRUNTIME140.dll+0x1dafb") for k in keys), keys
    assert found[next(k for k in keys if k.startswith("crash 0xc0000005 at VCRUNTIME"))].terms[0] == "0x24821e3"
    assert "os error 1455" in keys
    assert sum(1 for k in keys if "pipeline refused" in k) == 1, keys
    heap = next(s for s in found.values() if "view heap capped" in s.key)
    assert heap.terms == ['"host view heap capped at"'], heap.terms
    refused = next(s for s in found.values() if "pipeline refused" in s.key)
    assert refused.details["hashes"] == ["6f225b641c5b0708"]
    assert "<user>" in redact("C:\\Users\\someone\\AppData")
    assert status_of([]) == "new" and status_of(None) == "not checked"
    assert status_of([{"pr": True, "merged": True, "state": "closed"}]) == "fix merged"
    title = ["========= POOLS =========", " - INSTANCE_LIST: 45000/45000", " - PED: 27/600"]
    found = {}
    scan_title_crash(title, found, "selftest")
    assert list(found) == ["pool INSTANCE_LIST full"]
    p = Path(HOME / "selftest.log")
    HOME.mkdir(parents=True, exist_ok=True)
    p.write_text(sample.splitlines()[2] + "\n")
    perf = performance(p)
    assert perf["reached"] == "world" and perf["fps_median"] == 3.1 and perf["gpu_ms_median"] == 114.8, perf
    p.unlink()
    print("selftest ok")


def main():
    ap = argparse.ArgumentParser(prog="victory-doctor", description=__doc__.split("\n\n")[0])
    ap.add_argument("--version", action="version", version=VERSION)
    sub = ap.add_subparsers(dest="cmd_name", required=True)

    def repos(p):
        p.add_argument("--repos", nargs="+", default=DEFAULT_REPOS, help="repositories to search")
        p.add_argument("--offline", action="store_true", help="no GitHub lookups (cached results only)")
        p.add_argument("--most", type=int, default=15, help="most signatures to look up")

    p = sub.add_parser("scan", help="diagnose a log")
    p.add_argument("log", nargs="?")
    p.add_argument("--crashes", help="crashes.log (found automatically otherwise)")
    p.add_argument("--no-auto", action="store_true", help="do not look for crash files")
    p.add_argument("--all-crashes", action="store_true", help="every crashes.log entry, not only this run's")
    p.add_argument("--hours", type=int, default=0, help="also take crash entries from this many hours before the log")
    p.add_argument("--json", help="write the signatures here")
    repos(p)
    p.set_defaults(fn=cmd_scan)

    p = sub.add_parser("run", help="run the emulator with live diagnosis: run -- victory.exe run <exe> --execute")
    p.add_argument("cmd", nargs=argparse.REMAINDER)
    repos(p)
    p.set_defaults(fn=lambda a: cmd_run(argparse.Namespace(**{**vars(a), "cmd": [c for c in a.cmd if c != "--"]})))

    p = sub.add_parser("open", help="open a match of signature N in the browser")
    p.add_argument("signature", type=int)
    p.add_argument("-n", type=int, default=1, help="which match (default the first)")
    p.set_defaults(fn=cmd_open)

    p = sub.add_parser("draft", help="write an issue draft for signature N")
    p.add_argument("signature", type=int)
    p.add_argument("--out")
    p.set_defaults(fn=cmd_draft)

    p = sub.add_parser("post", help="open a new issue for signature N (browser form; you submit it)")
    p.add_argument("signature", type=int)
    p.add_argument("--repo", default=DEFAULT_REPOS[0])
    p.add_argument("--anyway", action="store_true", help="even if others reported it")
    p.set_defaults(fn=cmd_post)

    p = sub.add_parser("comment", help="add your details to an existing report of signature N")
    p.add_argument("signature", type=int)
    p.add_argument("--issue", type=int, required=True)
    p.add_argument("--repo", default=DEFAULT_REPOS[0])
    p.add_argument("--api", action="store_true", help="post with your GitHub token instead of the browser")
    p.set_defaults(fn=cmd_comment)

    p = sub.add_parser("compare", help="compare two logs or run records")
    p.add_argument("a")
    p.add_argument("b")
    p.set_defaults(fn=cmd_compare)

    p = sub.add_parser("record", help="make a run record from a log")
    p.add_argument("log")
    p.add_argument("--setting", action="append", help="KEY=VALUE the run used (default: VICTORY_* now set)")
    p.add_argument("--emulator", help="which emulator build or fork")
    p.add_argument("--note")
    p.set_defaults(fn=cmd_record)

    p = sub.add_parser("submit", help="share a run record in the public runs database")
    p.add_argument("run", help="run id or record file")
    p.add_argument("--api", action="store_true", help="submit with your GitHub token instead of the browser")
    p.set_defaults(fn=cmd_submit)

    p = sub.add_parser("stats", help="what the shared runs say, by GPU and settings")
    p.add_argument("--gpu")
    p.add_argument("--setting")
    p.add_argument("--mine", action="store_true", help="include your own unsubmitted runs")
    p.set_defaults(fn=cmd_stats)

    p = sub.add_parser("selftest", help="check the parsers")
    p.set_defaults(fn=cmd_selftest)

    a = ap.parse_args()
    a.fn(a)


if __name__ == "__main__":
    main()
