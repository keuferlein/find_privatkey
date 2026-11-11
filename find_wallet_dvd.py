#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import concurrent.futures
import hashlib
import os
import shutil
import sys
import threading
from pathlib import Path

# ---- Arbeitsverzeichnis auf Skript-Ordner setzen (z. B. ~/Downloads) ----
SCRIPT_PATH = Path(__file__).resolve()
SCRIPT_DIR = SCRIPT_PATH.parent
os.chdir(SCRIPT_DIR)

LOGFILE = Path("wallet_search_results.log")
SEARCH_DIR = Path(sys.argv[1] if len(sys.argv) > 1 else "/media/cdrom0")
TREFFER_DIR = Path(sys.argv[2] if len(sys.argv) > 2 else "Trefferliste")

try:
    JOBS = int(sys.argv[3]) if len(sys.argv) > 3 else 3
    if JOBS < 1:
        raise ValueError
except ValueError:
    print("FEHLER: Parallel-Jobs muss eine positive Ganzzahl sein.", file=sys.stderr)
    sys.exit(1)

TREFFER_DIR.mkdir(parents=True, exist_ok=True)
LOGFILE.write_text("", encoding="utf-8")

SCRIPT_NAME = SCRIPT_PATH.name
LOG_NAME = LOGFILE.name

# -------- Farbausgabe (abschaltbar über NO_COLOR) --------
USE_COLOR = not os.environ.get("NO_COLOR") and sys.stdout.isatty()
if USE_COLOR:
    GREEN = "\033[0;32m"
    RED = "\033[0;31m"
    YELLOW = "\033[0;33m"
    CYAN = "\033[0;36m"
    BOLD = "\033[1m"
    RESET = "\033[0m"
else:
    GREEN = RED = YELLOW = CYAN = BOLD = RESET = ""

# -------- Live-Progress (abschaltbar über NO_PROGRESS) --------
PROGRESS = not os.environ.get("NO_PROGRESS") and sys.stdout.isatty()
PROGRESS_ACTIVE = False
OUTPUT_LOCK = threading.Lock()


def log_line(text=""):
    with LOGFILE.open("a", encoding="utf-8") as handle:
        handle.write(text + "\n")


def tee_line(text=""):
    print(text)
    log_line(text)


def progress_clear():
    global PROGRESS_ACTIVE
    if PROGRESS:
        print("\r\033[K", end="", file=sys.stderr, flush=True)
        PROGRESS_ACTIVE = False


def progress_update(processed, total, hits, dupes):
    global PROGRESS_ACTIVE
    if PROGRESS:
        text = (
            f"\r{CYAN}Durchsuche Dateien:{RESET} {processed}/{total}  "
            f"{GREEN}Treffer:{RESET} {hits}  "
            f"{YELLOW}Duplikate:{RESET} {dupes}\033[K"
        )
        print(text, end="", file=sys.stderr, flush=True)
        PROGRESS_ACTIVE = True


def progress_finish():
    if PROGRESS:
        progress_clear()
        print(file=sys.stderr)


def on_err(exc):
    msg = f"FEHLER: Abbruch: {exc}"
    log_line(msg)
    progress_clear()
    if RED:
        print(f"{BOLD}{RED}{msg}{RESET}", file=sys.stderr)
    else:
        print(msg, file=sys.stderr)


# -------- Helpers --------
def make_dest_flat(src):
    base = src.name or "unnamed_file"
    dest = TREFFER_DIR / base
    if not dest.exists():
        return dest

    if "." in base and not base.startswith("."):
        stem, ext = base.rsplit(".", 1)
    else:
        stem, ext = base, ""

    n = 2
    while True:
        name = f"{stem}__{n}.{ext}" if ext else f"{stem}__{n}"
        dest = TREFFER_DIR / name
        if not dest.exists():
            return dest
        n += 1


def copy_hit_flat(src):
    try:
        shutil.copy2(src, make_dest_flat(src))
    except OSError:
        # Entspricht: cp -p ... || true
        pass


def read_at(path, offset, count):
    try:
        with path.open("rb") as handle:
            handle.seek(offset)
            return handle.read(count)
    except OSError:
        return b""


def hex_at(path, offset, count):
    return read_at(path, offset, count).hex()


def sqlite_magic_at(path, offset):
    return read_at(path, offset, 16) == b"SQLite format 3\x00"


def sqlite_header_plausible_at(path, offset):
    raw = read_at(path, offset + 16, 2)
    if len(raw) != 2:
        return False
    page_size = int.from_bytes(raw, byteorder="big")
    return page_size in {512, 1024, 2048, 4096, 8192, 16384, 32768, 65536}


def is_sqlite_loose(path):
    try:
        size = path.stat().st_size
    except OSError:
        size = 0
    if size < 100:
        return False

    if sqlite_magic_at(path, 0) and sqlite_header_plausible_at(path, 0):
        return True

    try:
        with path.open("rb") as handle:
            data = handle.read(1048576)
    except OSError:
        return False

    offset = data.find(b"SQLite format 3\x00")
    return offset >= 0 and sqlite_header_plausible_at(path, offset)


def is_bdb_btree_magic(path):
    try:
        size = path.stat().st_size
    except OSError:
        size = 0
    if size < 16:
        return False

    magic = b"\x62\x31\x05\x00"
    if read_at(path, 12, 4) == magic:
        return True
    return magic in read_at(path, 0, 4096)


def is_inside_treffer_dir(path):
    try:
        path.resolve().relative_to(TREFFER_DIR.resolve())
        return True
    except (ValueError, OSError):
        return False


def scan_one(path):
    try:
        if not path.is_file():
            return None
        if path.name in {SCRIPT_NAME, LOG_NAME}:
            return None
        if is_inside_treffer_dir(path):
            return None

        if is_sqlite_loose(path):
            return "SQLITE", path
        if is_bdb_btree_magic(path):
            return "BDB", path
    except OSError:
        pass
    return None


def sha256_file(path):
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            while True:
                block = handle.read(1024 * 1024)
                if not block:
                    break
                digest.update(block)
        return digest.hexdigest()
    except OSError:
        return ""


def collect_files(root):
    files = []

    def on_walk_error(_error):
        # Entspricht weitgehend: find ... 2>/dev/null
        pass

    for current_root, _dirs, names in os.walk(root, onerror=on_walk_error):
        current = Path(current_root)
        for name in names:
            files.append(current / name)
    return files


def main():
    if not SEARCH_DIR.is_dir():
        tee_line(f"Suchverzeichnis existiert nicht: {SEARCH_DIR}")
        return 1

    tee_line()
    tee_line(f"Suchpfad:       {SEARCH_DIR}")
    tee_line(f"Logdatei:       {LOGFILE}")
    tee_line(f"Trefferordner:  {TREFFER_DIR}")
    tee_line(f"Parallel-Jobs:  {JOBS}")
    tee_line()

    all_files = collect_files(SEARCH_DIR)
    total_files = len(all_files)
    candidates = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=JOBS) as executor:
        for result in executor.map(scan_one, all_files):
            if result is not None:
                candidates.append(result)

    total_candidates = len(candidates)
    size_first_file = {}
    size_first_hashed = set()
    seen_size_hash = {}
    total_hits = 0
    total_dupes = 0
    processed = 0

    progress_update(processed, total_files, total_hits, total_dupes)

    for typ, file_path in candidates:
        if not file_path.is_file():
            continue

        processed += 1
        try:
            size = file_path.stat().st_size
        except OSError:
            size = 0

        file_hash = ""
        if size not in size_first_file and size not in size_first_hashed:
            size_first_file[size] = file_path
        else:
            if size not in size_first_hashed:
                first = size_first_file.get(size)
                if first is not None and first.is_file():
                    first_hash = sha256_file(first)
                    if first_hash:
                        seen_size_hash[(size, first_hash)] = first
                size_first_hashed.add(size)
                size_first_file.pop(size, None)

            file_hash = sha256_file(file_path)
            if not file_hash:
                continue

            key = (size, file_hash)
            if key in seen_size_hash:
                total_dupes += 1
                local_dupe = f"DUPE: {file_path}  -> zuerst: {seen_size_hash[key]}"
                progress_clear()
                log_line(local_dupe)
                print(f"{YELLOW}{local_dupe}{RESET}" if YELLOW else local_dupe)
                progress_update(processed, total_files, total_hits, total_dupes)
                continue
            seen_size_hash[key] = file_path

        total_hits += 1
        if file_hash:
            plain = f"HIT:  [{typ}] {file_path} (size={size}, sha256={file_hash})"
        else:
            plain = f"HIT:  [{typ}] {file_path} (size={size}, sha256=SKIPPED_UNIQUE_SIZE)"

        progress_clear()
        log_line(plain)
        print(f"{GREEN}✅ {plain}{RESET}" if GREEN else plain)
        progress_update(processed, total_files, total_hits, total_dupes)
        copy_hit_flat(file_path)

        if processed % 200 == 0:
            progress_update(processed, total_files, total_hits, total_dupes)

    progress_finish()
    tee_line()
    tee_line(f"Durchsuchte Dateien:        {total_files}")
    tee_line(f"Kandidaten (vor Dedupe):    {total_candidates}")
    tee_line(f"Duplikate:                 {total_dupes}")
    tee_line(f"Treffer (nach Dedupe):      {total_hits}")
    tee_line(f"Log:                        {LOGFILE}")
    tee_line(f"Kopien:                     {TREFFER_DIR}")

    if sys.stdout.isatty():
        print()
        print("========== Scan-Statistik ==========")
        print(f"Suchpfad:      {SEARCH_DIR}")
        print(f"Trefferordner: {TREFFER_DIR}")
        print(f"Dateien:       {total_files}")
        print(f"Kandidaten:    {total_candidates}")
        print(f"Duplikate:     {total_dupes}")
        print(f"Treffer:       {total_hits}")
        print(f"Log:           {LOGFILE}")
        print("====================================")

    if total_hits > 0:
        print(f"{GREEN}✅ Treffer gefunden: {total_hits}{RESET}")
    else:
        print(f"{YELLOW}Keine Treffer gefunden.{RESET}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        progress_clear()
        print("Abbruch durch Benutzer.", file=sys.stderr)
        sys.exit(130)
    except Exception as exc:
        on_err(exc)
        sys.exit(1)
