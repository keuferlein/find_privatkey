#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Python-Umsetzung von find_wallet_praxis.txt – erweiterte Version.

Funktionen:
1) Suche nach SQLite-/BDB-Wallet-Fragmenten.
2) Kopieren der Treffer in den Trefferordner.
3) Zusätzlich Suche nach typischen Wallet-Begriffen:
   bestblock, keymeta, walletversion, pool, cryptedkey, hdmasterpubkey, hdseed
4) Suche nach:
   - direkt vorliegenden WIF-Strings,
   - 64-stelligen Hex-Zeichenfolgen,
   - 32-Byte-Bereichen in der Nähe von Wallet-Markern.
5) Erzeugt daraus so viele WIFs wie möglich.
6) Schreibt:
   - wif_kandidaten.txt      (alle WIF-Kandidaten, eine Zeile pro WIF)
   - wif_sicher.txt          (nur besonders sichere / direkt gültige WIFs)
   - wallet_wif_report.txt   (ausführlicher Report)
"""

import os
import sys
import stat
import hashlib
import shutil
import tempfile
import multiprocessing
import re
import time


# ---------------------------------------------------------------------------
# Basis-Konstanten
# ---------------------------------------------------------------------------

LOGFILE = "wallet_search_results.log"

WIF_REPORT_FILE = "wallet_wif_report.txt"
ALL_WIF_FILE = "wif_kandidaten.txt"
SAFE_WIF_FILE = "wif_sicher.txt"


SQLITE_MAGIC = b"SQLite format 3\x00"
BDB_MAGIC = bytes((0x62, 0x31, 0x05, 0x00))

VALID_PAGE_SIZES = {
    512,
    1024,
    2048,
    4096,
    8192,
    16384,
    32768,
    65536,
}

_CHUNK_SIZE = 512


# ---------------------------------------------------------------------------
# WIF / Base58Check / secp256k1-Konstanten
# ---------------------------------------------------------------------------

SECP256K1_ORDER = (
    0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
)

B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_MAP = {c: i for i, c in enumerate(B58_ALPHABET)}


MARKERS = [
    b"bestblock",
    b"keymeta",
    b"walletversion",
    b"pool",
    b"cryptedkey",
    b"hdmasterpubkey",
    b"hdseed",
]

# Für schnelle Textdatei-Prüfung: etwas seltenere / stärkere Marker.
QUICK_MARKERS = [m for m in MARKERS if m != b"pool"]


WIF_RE = re.compile(
    rb"(?<![1-9A-HJ-NP-Za-km-z])"
    rb"[1-9A-HJ-NP-Za-km-z]{25,120}"
    rb"(?![1-9A-HJ-NP-Za-km-z])"
)

HEX64_RE = re.compile(
    rb"(?<![0-9a-fA-F])[0-9a-fA-F]{64}(?![0-9a-fA-F])"
)


# ---------------------------------------------------------------------------
# Optionale Grenzen via Umgebungsvariablen
# ---------------------------------------------------------------------------

_TEXT_MAX_FILE_MB = float(os.environ.get("TEXT_MAX_FILE_MB", "5"))
_TEXT_PROBE_READ_MB = float(os.environ.get("TEXT_PROBE_READ_MB", "0.25"))
_ANALYZE_MAX_MB = int(float(os.environ.get("MAX_SCAN_MB", "512")))

_TEXT_MAX_BYTES = max(0, int(_TEXT_MAX_FILE_MB * 1024 * 1024))
_TEXT_PROBE_BYTES = max(65536, int(_TEXT_PROBE_READ_MB * 1024 * 1024))


# ---------------------------------------------------------------------------
# Worker-Globale für multiprocessing
# ---------------------------------------------------------------------------

_WORKER_TREFFER_DIR_ABS = ""
_WORKER_SCRIPT_NAME = ""
_WORKER_LOG_NAME = ""


def _worker_init(treffer_dir_abs, script_name, log_name):
    """
    Wird in jedem Worker-Prozess aufgerufen.
    """
    global _WORKER_TREFFER_DIR_ABS
    global _WORKER_SCRIPT_NAME
    global _WORKER_LOG_NAME

    _WORKER_TREFFER_DIR_ABS = treffer_dir_abs
    _WORKER_SCRIPT_NAME = script_name
    _WORKER_LOG_NAME = log_name


# ---------------------------------------------------------------------------
# Kleine Hilfsfunktionen, identisch zur Bash-Version
# ---------------------------------------------------------------------------


def _read_bytes_at(path, offset, count):
    """
    Äquivalent zu: dd if=path bs=1 skip=offset count=count 2>/dev/null
    """
    if count <= 0:
        return b""

    try:
        with open(path, "rb") as f:
            if offset > 0:
                f.seek(offset)
            return f.read(count)
    except OSError:
        return b""


def _hex_at(path, offset, count):
    """
    Äquivalent zu:
      dd ... | od -An -tx1 | tr -d ' \n'
    """
    return _read_bytes_at(path, offset, count).hex()


def _file_size(path):
    """
    stat -c%s -- "$f" 2>/dev/null || echo 0
    """
    try:
        return os.lstat(path).st_size
    except OSError:
        return 0


def _sqlite_header_plausible_at(path, offset):
    """
    Prüft die Page-Size nach dem SQLite-Magic.
    """
    hx = _hex_at(path, offset + 16, 2)

    if len(hx) != 4:
        return False

    try:
        page_size = int(hx, 16)
    except ValueError:
        return False

    return page_size in VALID_PAGE_SIZES


def _is_sqlite_loose(path):
    """
    is_sqlite_loose()

    - Datei muss mindestens 100 Byte groß sein.
    - Zuerst Magic an Offset 0 prüfen.
    - Dann im ersten 1 MB nach dem Magic suchen.
    - Wenn gefunden, Page-Size plausibel sein müssen.
    """
    size = _file_size(path)

    if size < 100:
        return False

    try:
        with open(path, "rb") as f:
            data = f.read(1_048_576)
    except OSError:
        return False

    if len(data) < 16:
        return False

    # Schnellprüfung an Offset 0.
    if data[:16] == SQLITE_MAGIC and _sqlite_header_plausible_at(path, 0):
        return True

    # Danach erste Stelle im ersten 1 MB suchen.
    off = data.find(SQLITE_MAGIC)

    if off != -1 and _sqlite_header_plausible_at(path, off):
        return True

    return False


def _is_bdb_btree_magic(path):
    """
    is_bdb_btree_magic()

    - Datei muss mindestens 16 Byte groß sein.
    - Magic an Offset 12 prüfen: 62310500
    - Oder Magic in den ersten 4096 Bytes suchen.
    """
    size = _file_size(path)

    if size < 16:
        return False

    if _hex_at(path, 12, 4) == "62310500":
        return True

    data = _read_bytes_at(path, 0, 4096)
    return BDB_MAGIC in data


def _sha256_file(path):
    """
    sha256sum -- "$file" 2>/dev/null | awk '{print $1}' || true
    """
    h = hashlib.sha256()

    try:
        with open(path, "rb") as f:
            while True:
                chunk = f.read(1_048_576)
                if not chunk:
                    break
                h.update(chunk)
    except OSError:
        return ""

    return h.hexdigest()


def _make_dest_flat(src, treffer_dir):
    """
    make_dest_flat()

    Kopiert flach in den Trefferordner.
    Bei Namenskollision:
      name.ext  ->  name__2.ext
      name      ->  name__2
    """
    base = os.path.basename(src) or "unnamed_file"

    dest = os.path.join(treffer_dir, base)

    if not os.path.exists(dest):
        return dest

    # Bash: [[ "$base" == *.* && "$base" != .* ]]
    if "." in base and not base.startswith("."):
        stem, ext = base.rsplit(".", 1)
    else:
        stem = base
        ext = ""

    n = 2
    while True:
        if ext:
            name = f"{stem}__{n}.{ext}"
        else:
            name = f"{stem}__{n}"

        dest = os.path.join(treffer_dir, name)

        if not os.path.exists(dest):
            break

        n += 1

    return dest


def _copy_hit_flat(src, treffer_dir):
    """
    copy_hit_flat()

    cp -p -- "$src" "$dest" 2>/dev/null || true
    """
    try:
        dest = _make_dest_flat(src, treffer_dir)
        shutil.copy2(src, dest)
        return dest
    except OSError:
        return None


# ---------------------------------------------------------------------------
# Base58 / WIF-Helper
# ---------------------------------------------------------------------------


def _b58_encode(data):
    """
    Einfache Base58-Encoding-Funktion.
    """
    n = int.from_bytes(data, "big")
    res = ""

    while n > 0:
        n, r = divmod(n, 58)
        res = B58_ALPHABET[r] + res

    for byte in data:
        if byte == 0:
            res = "1" + res
        else:
            break

    return res


def _b58_decode(s):
    """
    Einfache Base58-Decoding-Funktion.
    """
    s = s.strip()
    if not s:
        return None

    num = 0
    for ch in s:
        if ch not in _B58_MAP:
            return None
        num = num * 58 + _B58_MAP[ch]

    zeros = 0
    for ch in s:
        if ch == "1":
            zeros += 1
        else:
            break

    if num == 0:
        return b"\x00" * len(s)

    length = max(1, (num.bit_length() + 7) // 8)
    body = num.to_bytes(length, "big")
    return b"\x00" * zeros + body


def _b58check_decode(s):
    """
    Dekodiert Base58 und prüft den 4-Byte-Checksum.
    Gibt payload zurück oder None.
    """
    raw = _b58_decode(s)

    if not raw or len(raw) < 5:
        return None

    payload, chk = raw[:-4], raw[-4:]
    calc_chk = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]

    if calc_chk != chk:
        return None

    return payload


def _is_valid_private_key(key):
    """
    Prüft, ob ein 32-Byte-Wert als secp256k1-privater Schlüssel gültig sein kann.
    """
    if not key or len(key) != 32:
        return False

    n = int.from_bytes(key, "big")
    return 0 < n < SECP256K1_ORDER


def _make_wif(key, compressed):
    """
    Erstellt einen WIF-String aus einem 32-Byte-privaten Schlüssel.
    """
    if not key or len(key) != 32:
        return ""

    payload = b"\x80" + key
    if compressed:
        payload += b"\x01"

    chk = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return _b58_encode(payload + chk)


def _wif_info_from_string(s):
    """
    Prüft, ob ein String ein gültiger mainnet-WIF ist.

    Rückgabe:
      None
      oder dict mit key / compressed / version
    """
    if not s:
        return None

    payload = _b58check_decode(s)
    if not payload or len(payload) < 34:
        return None

    version = payload[0]
    body = payload[1:]

    # mainnet: 0x80, testnet: 0xef
    if version == 0x80:
        net = "mainnet"
    elif version == 0xef:
        net = "testnet"
    else:
        return None

    compressed = False
    key = None

    if len(body) == 32:
        key = body
        compressed = False
    elif len(body) == 33 and body[-1] == 0x01:
        key = body[:32]
        compressed = True
    else:
        return None

    if not _is_valid_private_key(key):
        return None

    return {
        "key": key,
        "compressed": compressed,
        "version": net,
    }


# ---------------------------------------------------------------------------
# Heuristik für 32-Byte-Kandidaten
# ---------------------------------------------------------------------------


def _plausible_random32(b):
    """
    Sehr grobe Filterung, damit nicht jedes zufällige 0x20 + Bytes
    als privater Schlüssel ausgegeben wird.

    Das ist kein sicherer Beweis, aber es reduziert False Positives deutlich.
    """
    if not b or len(b) != 32:
        return False

    n = int.from_bytes(b, "big")
    if not (0 < n < SECP256K1_ORDER):
        return False

    # Nicht alles gleich.
    first = b[0]
    all_same = True
    for x in b:
        if x != first:
            all_same = False
            break
    if all_same:
        return False

    # Nicht zu viele gleiche Bytes direkt hintereinander.
    maxrun = 1
    cur = 1
    for i in range(1, len(b)):
        if b[i] == b[i - 1]:
            cur += 1
            if cur > maxrun:
                maxrun = cur
        else:
            cur = 1
    if maxrun > 10:
        return False

    # Mindestens etwas "zufällig" aussehen.
    if len(set(b)) < 10:
        return False

    # Binaire Zufallsbytes sollten normalerweise nicht nur druckbare ASCII-Zeichen sein.
    nonprint = 0
    for x in b:
        if x < 32 or x > 126:
            nonprint += 1

    if nonprint == 0:
        return False

    return True


# ---------------------------------------------------------------------------
# Schnelle Textdatei-Prüfung für die parallele Suche
# ---------------------------------------------------------------------------


def _quick_text_hit(path):
    """
    Prüft kleine Dateien sehr schnell auf:
      - starke Wallet-Marker,
      - direkt gültige WIFs.

    Damit werden z. B. Logs / Textdateien mit exportierten Schlüsseln
    ebenfalls in den Trefferordner kopiert.
    """
    size = _file_size(path)

    if size <= 0 or size > _TEXT_MAX_BYTES:
        return False

    try:
        with open(path, "rb") as f:
            data = f.read(min(size, _TEXT_PROBE_BYTES))
    except OSError:
        return False

    # Starke Marker zuerst – das ist sehr schnell.
    for pat in QUICK_MARKERS:
        if pat in data:
            return True

    # Direkt gültige WIFs suchen, aber nicht zu viele prüfen.
    checked = 0
    for m in WIF_RE.finditer(data):
        try:
            s = m.group(1).decode("ascii")
        except Exception:
            continue

        if _wif_info_from_string(s) is not None:
            return True

        checked += 1
        if checked >= 200:
            break

    return False


# ---------------------------------------------------------------------------
# Datei-Chunk-Iterator für große Dateien
# ---------------------------------------------------------------------------


def _iter_file_chunks(path, max_bytes=None):
    """
    Liest eine Datei in überlappenden Chunks.
    """
    chunk = 8 * 1024 * 1024
    overlap = 32 * 1024
    step = chunk - overlap

    if max_bytes is not None and max_bytes <= 0:
        return

    try:
        f = open(path, "rb")
    except OSError:
        return

    with f:
        pos = 0
        while True:
            want = chunk if max_bytes is None else min(chunk, max_bytes - pos)
            if want <= 0:
                break

            f.seek(pos)
            data = f.read(want)

            if not data:
                break

            yield pos, data

            if len(data) < want:
                break

            if max_bytes is not None and (pos + len(data)) >= max_bytes:
                break

            pos += step


# ---------------------------------------------------------------------------
# WIF-Analyse einer einzelnen Datei
# ---------------------------------------------------------------------------


def _analyze_wallet_file(path):
    """
    Analysiert eine Datei auf:
      - direkt gültige WIFs,
      - 64-Byte-Hex-Kandidaten,
      - 32-Byte-Bereiche in der Nähe von Wallet-Markern.

    Rückgabe:
      entries, markers, notes
    """
    entries = []
    markers = []
    notes = []

    size = _file_size(path)
    if size <= 0:
        return entries, markers, notes

    max_bytes = int(float(os.environ.get("MAX_SCAN_MB", str(_ANALYZE_MAX_MB)))) * 1024 * 1024
    if size > max_bytes:
        notes.append(
            f"Datei ist größer als {max_bytes // (1024 * 1024)} MB; "
            f"nur der erste Teil wurde gescannt."
        )

    # BDB-Hinweis am Dateianfang.
    try:
        with open(path, "rb") as f:
            head = f.read(64)
        if b"\x00\x09\x13\x2d" in head:
            notes.append("möglicher BDB-Header-Hinweis am Dateianfang gefunden.")
    except OSError:
        pass

    result_limit = int(float(os.environ.get("MAX_ENTRIES_PER_FILE", "300")))
    marker_limit = int(float(os.environ.get("MAX_MARKER_HITS", "500")))

    seen = set()
    raw_key_seen = set()
    marker_seen = set()
    all_marker_offsets = []

    file_base = os.path.basename(path).lower()
    is_candidate_filename = any(
        x in file_base
        for x in ("key", "wif", "priv", "secret", "candidate", "kandidat")
    )

    def _add_raw(key, off, reason, conf):
        if not key or len(key) != 32:
            return False

        if not _plausible_random32(key):
            return False

        hexs = key.hex()
        if hexs in raw_key_seen:
            return False

        if len(entries) >= result_limit:
            return False

        wifs = [
            _make_wif(key, False),
            _make_wif(key, True),
        ]

        entries.append({
            "kind": "raw32",
            "value": hexs,
            "offset": off,
            "reason": reason,
            "confidence": conf,
            "wifs": wifs,
        })

        raw_key_seen.add(hexs)
        return True

    for pos, data in _iter_file_chunks(path, max_bytes):
        # ---------------------------------------------------------------
        # 1) Marker suchen und in deren Nähe nach 32-Byte-Kandidaten schauen
        # ---------------------------------------------------------------
        if len(marker_seen) < marker_limit:
            for pat in MARKERS:
                if len(marker_seen) >= marker_limit:
                    break

                start = 0
                while True:
                    i = data.find(pat, start)
                    if i < 0 or len(marker_seen) >= marker_limit:
                        break

                    abs_off = pos + i
                    mkey = (pat, abs_off)

                    if mkey not in marker_seen:
                        marker_seen.add(mkey)
                        all_marker_offsets.append(abs_off)

                        if len(markers) < 200:
                            markers.append((pat, abs_off))

                        # In der Nähe des Markers nach 32-Byte-Bereichen suchen.
                        start_ = max(0, i - 256)
                        end_ = min(len(data) - 33, i + 2048)

                        if end_ >= start_:
                            added_for_marker = 0
                            before_entries = len(entries)

                            for j in range(start_, end_ + 1):
                                b = data[j]

                                if b == 0x20:
                                    # 0x20 = 32 dezimal -> möglicher Längen-Byte.
                                    conf = "niedrig"
                                    if pat != b"cryptedkey":
                                        if pat in (b"keymeta", b"hdmasterpubkey"):
                                            conf = "mittel"
                                        else:
                                            conf = "niedrig"

                                    if _add_raw(
                                        data[j + 1:j + 33],
                                        pos + j + 1,
                                        f"{pat.decode(errors='ignore')}_len32",
                                        conf,
                                    ):
                                        added_for_marker += 1

                                elif b == 0x21:
                                    # 0x21 = 33 dezimal -> evtl. 33-Byte-Abschnitt.
                                    if _add_raw(
                                        data[j + 1:j + 33],
                                        pos + j + 1,
                                        f"{pat.decode(errors='ignore')}_len33",
                                        "niedrig",
                                    ):
                                        added_for_marker += 1

                                # Nicht zu viele Kandidaten pro Marker erzeugen.
                                if (
                                    len(entries) - before_entries >= 5
                                    or added_for_marker >= 5
                                ):
                                    break

                    start = i + len(pat)

        # ---------------------------------------------------------------
        # 2) Direkt gültige WIF-Strings suchen
        # ---------------------------------------------------------------
        for m in WIF_RE.finditer(data):
            if len(entries) >= result_limit:
                break

            off = pos + m.start()
            skey = ("WIF", off, m.group(1))
            if skey in seen:
                continue
            seen.add(skey)

            try:
                s = m.group(1).decode("ascii")
            except Exception:
                continue

            info = _wif_info_from_string(s)
            if info is None:
                continue

            entries.append({
                "kind": "wif",
                "value": s,
                "offset": off,
                "reason": f"base58check_wif_{info['version']}",
                "confidence": "hoch",
                "wifs": [s],
            })

        # ---------------------------------------------------------------
        # 3) 64-stellige Hex-Zeichenfolgen suchen
        # ---------------------------------------------------------------
        for m in HEX64_RE.finditer(data):
            if len(entries) >= result_limit:
                break

            off = pos + m.start()
            hkey = ("HEX", off, m.group(1))
            if hkey in seen:
                continue
            seen.add(hkey)

            try:
                hexs = m.group(1).decode("ascii").lower()
            except Exception:
                continue

            try:
                b = bytes.fromhex(hexs)
            except ValueError:
                continue

            if not _is_valid_private_key(b):
                continue

            # Um viele False Positives zu vermeiden, nur dann berücksichtigen,
            # wenn entweder:
            # - der Dateiname auf Kandidaten hindeutet,
            # - eine Wallet-Marker in der Nähe ist,
            # - oder man es explizit erlaubt hat.
            allow = (
                is_candidate_filename
                or os.environ.get("ALLOW_HEX64_ANYWHERE") == "1"
            )

            near_marker = False
            if not allow:
                for mo in all_marker_offsets[-500:]:
                    if abs(mo - off) <= 2048:
                        allow = True
                        near_marker = True
                        break

            if not allow:
                continue

            conf = "mittel" if (near_marker or is_candidate_filename) else "niedrig"

            wifs = [
                _make_wif(b, False),
                _make_wif(b, True),
            ]

            entries.append({
                "kind": "hex64",
                "value": hexs,
                "offset": off,
                "reason": (
                    "hex64_string_near_marker" if near_marker else "hex64_string"
                ),
                "confidence": conf,
                "wifs": wifs,
            })

    return entries[:result_limit], markers[:200], notes


# ---------------------------------------------------------------------------
# WIF-Aggregation
# ---------------------------------------------------------------------------

_CONF_RANK = {"hoch": 3, "mittel": 2, "niedrig": 1}


def _add_wif(all_wifs, wif, conf, file, reason):
    """
    Sammelt alle gefundenen WIFs und merkt sich beste Confidence + Quelle.
    """
    if not wif:
        return

    d = all_wifs.get(wif)

    if d is None:
        all_wifs[wif] = {
            "conf": conf,
            "rank": _CONF_RANK.get(conf, 0),
            "files": [file],
            "reasons": [reason],
        }
    else:
        new_rank = _CONF_RANK.get(conf, 0)
        if new_rank > d["rank"]:
            d["conf"] = conf
            d["rank"] = new_rank

        if file not in d["files"] and len(d["files"]) < 5:
            d["files"].append(file)

        if reason not in d["reasons"] and len(d["reasons"]) < 3:
            d["reasons"].append(reason)


# ---------------------------------------------------------------------------
# Worker für die parallele Suche
# ---------------------------------------------------------------------------


def _scan_one_worker(file):
    """
    scan_one()

    Rückgabe:
      None
      "SQLITE\t<path>"
      "BDB\t<path>"
      "TEXT\t<path>"
    """
    if not file:
        return None

    try:
        st = os.lstat(file)
    except OSError:
        return None

    # find -type f -> nur reguläre Dateien, keine Symlinks.
    if not stat.S_ISREG(st.st_mode):
        return None

    base = os.path.basename(file) or ""

    # Eigene Skriptdatei, Logdatei und eigene Ergebnis-Dateien überspringen.
    skip_names = (
        _WORKER_SCRIPT_NAME,
        LOGFILE,
        WIF_REPORT_FILE,
        ALL_WIF_FILE,
        SAFE_WIF_FILE,
    )

    if base in skip_names:
        return None

    # Trefferordner selbst nicht durchsuchen.
    tdir_abs = _WORKER_TREFFER_DIR_ABS
    if tdir_abs:
        abs_file = os.path.abspath(file)
        if abs_file == tdir_abs or abs_file.startswith(tdir_abs + os.sep):
            return None

    # 1) SQLite-Fragmente.
    try:
        if _is_sqlite_loose(file):
            return f"SQLITE\t{file}"
    except Exception:
        pass

    # 2) BDB/Btree-Fragmente.
    try:
        if _is_bdb_btree_magic(file):
            return f"BDB\t{file}"
    except Exception:
        pass

    # 3) Kleine Dateien zusätzlich auf Wallet-Marker / direkte WIFs prüfen.
    size = st.st_size
    if 0 < size <= _TEXT_MAX_BYTES:
        try:
            if _quick_text_hit(file):
                return f"TEXT\t{file}"
        except Exception:
            pass

    return None


def _iter_null_chunks(path, chunk_size=_CHUNK_SIZE):
    """
    Liest eine Null-separierte Datei in kleinen Chunks.
    """
    acc = []
    leftover = b""

    with open(path, "rb") as f:
        while True:
            part = f.read(8 * 1024 * 1024)
            if not part:
                break

            data = leftover + part
            parts = data.split(b"\x00")
            leftover = parts.pop()

            for p in parts:
                if not p:
                    continue

                acc.append(os.fsdecode(p))

                if len(acc) >= chunk_size:
                    yield acc
                    acc = []

    if leftover:
        s = os.fsdecode(leftover)
        if s:
            acc.append(s)

    if acc:
        yield acc


# ---------------------------------------------------------------------------
# Hauptprogramm
# ---------------------------------------------------------------------------


def main():
    # Ausgabe robust machen, falls stdout/stderr keine UTF-8-Konsole ist.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    # -----------------------------------------------------------------------
    # Parameter wie im Bash-Skript
    # -----------------------------------------------------------------------

    search_dir = sys.argv[1] if len(sys.argv) > 1 else "."
    treffer_dir = sys.argv[2] if len(sys.argv) > 2 else "Trefferliste"
    jobs_raw = sys.argv[3] if len(sys.argv) > 3 else "32"

    try:
        jobs = int(jobs_raw)
    except (TypeError, ValueError):
        jobs = 32

    if jobs < 1:
        jobs = 1

    # -----------------------------------------------------------------------
    # Farben wie im Bash-Skript
    # -----------------------------------------------------------------------

    no_color_flag = bool(os.environ.get("NO_COLOR"))
    use_color = (not no_color_flag) and sys.stdout.isatty()

    if use_color:
        GREEN = "\033[0;32m"
        RED = "\033[0;31m"
        YELLOW = "\033[0;33m"
        CYAN = "\033[0;36m"
        BOLD = "\033[1m"
        RESET = "\033[0m"
    else:
        GREEN = ""
        RED = ""
        YELLOW = ""
        CYAN = ""
        BOLD = ""
        RESET = ""

    # -----------------------------------------------------------------------
    # Progress wie im Bash-Skript
    # -----------------------------------------------------------------------

    no_progress_flag = bool(os.environ.get("NO_PROGRESS"))
    progress_enabled = (not no_progress_flag) and sys.stdout.isatty()

    def p_clear():
        if progress_enabled:
            sys.stderr.write("\r\033[K")
            sys.stderr.flush()

    def p_update(processed, total, hits, dupes):
        if not progress_enabled:
            return

        line = (
            f"\r{CYAN}Durchsuche Dateien:{RESET} "
            f"{processed}/{total}  "
            f"{GREEN}Treffer:{RESET} {hits}  "
            f"{YELLOW}Duplikate:{RESET} {dupes}\033[K"
        )
        sys.stderr.write(line)
        sys.stderr.flush()

    def p_finish():
        if not progress_enabled:
            return

        p_clear()
        sys.stderr.write("\n")
        sys.stderr.flush()

    # -----------------------------------------------------------------------
    # Logfunktion
    # -----------------------------------------------------------------------

    logfile = None
    tmp_all_path = None
    tmp_cand_path = None

    def log(msg):
        if logfile is not None:
            try:
                logfile.write(msg + "\n")
                logfile.flush()
            except OSError:
                pass

    def say(msg):
        """
        tee -a "$LOGFILE"
        """
        log(msg)
        sys.stdout.write(msg + "\n")
        sys.stdout.flush()

    # -----------------------------------------------------------------------
    # Hauptverarbeitung
    # -----------------------------------------------------------------------

    try:
        # Wie im Bash-Skript:
        # mkdir -p "$TREFFER_DIR"
        os.makedirs(treffer_dir, exist_ok=True)

        # : > "$LOGFILE"
        with open(LOGFILE, "w", encoding="utf-8"):
            pass

        logfile = open(LOGFILE, "a", encoding="utf-8")

        if not os.path.isdir(search_dir):
            say(f"Suchverzeichnis existiert nicht: {search_dir}")
            sys.exit(1)

        # SCRIPT_NAME="$(basename "$0")"
        try:
            script_path = (
                os.path.abspath(__file__)
                if "__file__" in globals()
                else (sys.argv[0] or "")
            )
        except Exception:
            script_path = ""

        script_name = os.path.basename(script_path) or "find_wallet_praxis.py"

        treffer_abs = os.path.abspath(treffer_dir)

        # -------------------------------------------------------------------
        # Kopfzeilen wie im Bash-Skript
        # -------------------------------------------------------------------

        say("")
        say(f"Suchpfad:       {search_dir}")
        say(f"Logdatei:       {LOGFILE}")
        say(f"Trefferordner:  {treffer_dir}")
        say(f"Parallel-Jobs:  {jobs}")
        say("")

        # -------------------------------------------------------------------
        # Datei-Liste erzeugen, wie find -type f -print0
        # -------------------------------------------------------------------

        with tempfile.NamedTemporaryFile(
            delete=False,
            suffix=".files",
            prefix="wallet_files_",
        ) as all_tmp:
            tmp_all_path = all_tmp.name
            total_files = 0

            for root, _dirs, files in os.walk(search_dir):
                for name in files:
                    path = os.path.join(root, name)

                    try:
                        st = os.lstat(path)
                    except OSError:
                        continue

                    # find -type f -> nur reguläre Dateien.
                    if stat.S_ISREG(st.st_mode):
                        all_tmp.write(os.fsencode(path) + b"\x00")
                        total_files += 1

        # -------------------------------------------------------------------
        # Parallel scannen, wie xargs -P "$JOBS" bash -c 'scan_one "$1"'
        # -------------------------------------------------------------------

        with tempfile.NamedTemporaryFile(
            delete=False,
            suffix=".cand",
            prefix="wallet_cand_",
        ) as cand_tmp:
            tmp_cand_path = cand_tmp.name
            total_candidates = 0

            if total_files > 0:
                with multiprocessing.Pool(
                    processes=jobs,
                    initializer=_worker_init,
                    initargs=(treffer_abs, script_name, LOGFILE),
                ) as pool:
                    for chunk in _iter_null_chunks(tmp_all_path, _CHUNK_SIZE):
                        if not chunk:
                            continue

                        for line in pool.imap_unordered(_scan_one_worker, chunk):
                            if line is None:
                                continue

                            cand_tmp.write(os.fsencode(line) + b"\x00")
                            total_candidates += 1

        # -------------------------------------------------------------------
        # Dedupe und Ausgabe der Treffer
        # -------------------------------------------------------------------

        first_file = {}
        first_hashed = set()
        seen_size_hash = {}

        total_hits = 0
        total_dupes = 0
        processed = 0

        p_update(processed, total_files, total_hits, total_dupes)

        for chunk in _iter_null_chunks(tmp_cand_path, _CHUNK_SIZE):
            for line in chunk:
                if "\t" not in line:
                    continue

                typ, file = line.split("\t", 1)

                # [[ -f "$file" ]] || continue
                try:
                    st = os.lstat(file)
                    exists_regular = stat.S_ISREG(st.st_mode)
                except OSError:
                    exists_regular = False

                if not exists_regular:
                    continue

                processed += 1

                size = _file_size(file)
                h = ""

                # Dedupe-Logik wie im Bash-Skript.
                if size not in first_file and size not in first_hashed:
                    first_file[size] = file
                else:
                    if size not in first_hashed:
                        first = first_file.get(size)

                        if first is not None:
                            try:
                                st_first = os.lstat(first)
                                first_exists_regular = stat.S_ISREG(st_first.st_mode)
                            except OSError:
                                first_exists_regular = False

                            if first_exists_regular:
                                h1 = _sha256_file(first)
                                if h1:
                                    seen_size_hash[f"{size}:{h1}"] = first

                        first_hashed.add(size)
                        first_file.pop(size, None)

                    h = _sha256_file(file)

                    # [[ -n "$hash" ]] || continue
                    if not h:
                        continue

                    key = f"{size}:{h}"

                    if key in seen_size_hash:
                        total_dupes += 1

                        local_dupe = (
                            f"DUPE: {file}  -> zuerst: "
                            f"{seen_size_hash[key]}"
                        )

                        p_clear()
                        log(local_dupe)

                        if use_color:
                            print(f"{YELLOW}{local_dupe}{RESET}")
                        else:
                            print(local_dupe)

                        p_update(processed, total_files, total_hits, total_dupes)
                        continue

                    seen_size_hash[key] = file

                # -----------------------------------------------------------
                # Treffer
                # -----------------------------------------------------------

                total_hits += 1

                if h:
                    plain = (
                        f"HIT:  [{typ}] {file} "
                        f"(size={size}, sha256={h})"
                    )
                else:
                    plain = (
                        f"HIT:  [{typ}] {file} "
                        f"(size={size}, sha256=SKIPPED_UNIQUE_SIZE)"
                    )

                p_clear()
                log(plain)

                if use_color:
                    print(f"{GREEN}\u2705 {plain}{RESET}")
                else:
                    print(plain)

                # copy_hit_flat "$file"
                _copy_hit_flat(file, treffer_dir)

                p_update(processed, total_files, total_hits, total_dupes)

        p_finish()

        # -------------------------------------------------------------------
        # Zusammenfassung in Log + stdout
        # -------------------------------------------------------------------

        say("")
        say(f"Durchsuchte Dateien:        {total_files}")
        say(f"Kandidaten (vor Dedupe):    {total_candidates}")
        say(f"Duplikate:                 {total_dupes}")
        say(f"Treffer (nach Dedupe):      {total_hits}")
        say(f"Log:                        {LOGFILE}")
        say(f"Kopien:                     {treffer_dir}")

        # -------------------------------------------------------------------
        # Hübsch formatierte Statistik nur auf Bildschirm
        # -------------------------------------------------------------------

        if sys.stdout.isatty():
            print("")
            print(f"{BOLD}{CYAN}========== Scan-Statistik =========={RESET}")
            print(f"{CYAN}Suchpfad:      {RESET}{search_dir}")
            print(f"{CYAN}Trefferordner: {RESET}{treffer_dir}")
            print(f"{CYAN}Dateien:       {RESET}{total_files}")
            print(f"{CYAN}Kandidaten:    {RESET}{total_candidates}")
            print(f"{CYAN}Duplikate:     {RESET}{total_dupes}")
            print(f"{CYAN}Treffer:       {RESET}{total_hits}")
            print(f"{CYAN}Log:           {RESET}{LOGFILE}")
            print(f"{BOLD}{CYAN}===================================={RESET}")

        # -------------------------------------------------------------------
        # WIF-Analyse der Trefferliste
        # -------------------------------------------------------------------

        say("")
        say("WIF-Analyse:")
        say(f"  Report:       {os.path.abspath(WIF_REPORT_FILE)}")
        say(f"  Alle WIFs:    {os.path.abspath(ALL_WIF_FILE)}")
        say(f"  Sichere:      {os.path.abspath(SAFE_WIF_FILE)}")

        all_wifs = {}
        report_lines = []
        marker_lines = []
        analyzed_files = []

        try:
            names = sorted(os.listdir(treffer_dir))
        except OSError as e:
            say(f"  FEHLER: Trefferordner kann nicht gelesen werden: {e}")
            names = []

        skip_names = (
            script_name,
            LOGFILE,
            WIF_REPORT_FILE,
            ALL_WIF_FILE,
            SAFE_WIF_FILE,
        )

        for name in names:
            p = os.path.join(treffer_dir, name)

            if not os.path.isfile(p):
                continue

            if name in skip_names:
                continue

            try:
                entries, markers, notes = _analyze_wallet_file(p)
            except Exception as e:
                report_lines.append(f"FEHLER bei {name}: {e}")
                analyzed_files.append(name)
                continue

            analyzed_files.append(name)

            # Marker / Notizen sammeln.
            for note in notes:
                marker_lines.append(f"{name}: NOTIZ: {note}")

            shown_markers = 0
            for pat, off in markers:
                if shown_markers >= 6:
                    break
                try:
                    pats = pat.decode(errors="ignore")
                except Exception:
                    pats = repr(pat)
                marker_lines.append(
                    f"{name}: {pats} @ {off} ({hex(off)})"
                )
                shown_markers += 1

            if len(markers) > 6:
                marker_lines.append(
                    f"{name}: weitere {len(markers) - 6} Marker-Fundstellen im Report."
                )

            # WIFs / Kandidaten sammeln.
            direct_wifs = 0
            raw_candidates = 0

            for e in entries:
                kind = e.get("kind")
                conf = e.get("confidence", "niedrig")
                reason = e.get("reason", "")
                off = e.get("offset")
                value = e.get("value", "")

                if kind == "wif":
                    _add_wif(all_wifs, e["value"], conf, name, reason)
                    direct_wifs += 1
                    report_lines.append(
                        f"[{conf}] {name}:{off} WIF: {e['value']} ({reason})"
                    )

                else:
                    for wif in e.get("wifs", []):
                        _add_wif(all_wifs, wif, conf, name, reason)

                    raw_candidates += 1

                    if raw_candidates <= 80:
                        short = value[:16] + "..." if len(value) > 20 else value
                        report_lines.append(
                            f"[{conf}] {name}:{off} {kind} {short} ({reason})"
                        )

        # -------------------------------------------------------------------
        # WIF-Dateien schreiben
        # -------------------------------------------------------------------

        with open(ALL_WIF_FILE, "w", encoding="utf-8") as f:
            for wif in sorted(all_wifs.keys()):
                f.write(wif + "\n")

        safe_count = 0
        with open(SAFE_WIF_FILE, "w", encoding="utf-8") as f:
            items = sorted(
                all_wifs.items(),
                key=lambda kv: (kv[1]["rank"], kv[0]),
                reverse=True,
            )

            for wif, info in items:
                if info.get("conf") == "hoch":
                    f.write(wif + "\n")
                    safe_count += 1

        # -------------------------------------------------------------------
        # Report schreiben
        # -------------------------------------------------------------------

        with open(WIF_REPORT_FILE, "w", encoding="utf-8") as f:
            f.write("Wallet WIF Report\n")
            f.write("=" * 60 + "\n")
            f.write(f"Zeit:              {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Suchpfad:          {search_dir}\n")
            f.write(f"Trefferordner:     {treffer_dir}\n")
            f.write(f"Analysierte Files: {len(analyzed_files)}\n")
            f.write(f"WIFs gesamt:       {len(all_wifs)}\n")
            f.write(f"Sichere WIFs:      {safe_count}\n")

            f.write("\n=== Sichere / direkte WIFs (Base58Check gültig) ===\n")
            safe_items = [
                (wif, info)
                for wif, info in all_wifs.items()
                if info.get("conf") == "hoch"
            ]

            if not safe_items:
                f.write("keine\n")
            else:
                for wif, info in sorted(safe_items):
                    files = ", ".join(info["files"])
                    reasons = ", ".join(info["reasons"])
                    f.write(f"{wif}\n")
                    f.write(f"    Quelle: {files} | Grund: {reasons}\n")

            f.write("\n=== Alle gefundenen WIF-Kandidaten (Auswahl) ===\n")
            all_items = sorted(
                all_wifs.items(),
                key=lambda kv: (kv[1]["rank"], kv[0]),
                reverse=True,
            )

            if not all_items:
                f.write("keine\n")
            else:
                shown = 0
                for wif, info in all_items:
                    if shown >= 200:
                        break
                    conf = info.get("conf", "?")
                    files = ", ".join(info["files"])
                    reasons = ", ".join(info["reasons"])
                    f.write(f"{wif}\n")
                    f.write(
                        f"    Confidence: {conf} | Quelle: {files} | Grund: {reasons}\n"
                    )
                    shown += 1

                if len(all_items) > shown:
                    f.write(
                        f"... weitere {len(all_items) - shown} Kandidaten "
                        f"sind in {ALL_WIF_FILE}\n"
                    )

            f.write("\n=== Marker / Notizen (Auswahl) ===\n")
            if not marker_lines:
                f.write("keine\n")
            else:
                for line in marker_lines[:500]:
                    f.write(line + "\n")

            f.write("\n=== Analyse-Einträge (Auswahl) ===\n")
            if not report_lines:
                f.write("keine\n")
            else:
                for line in report_lines[:1000]:
                    f.write(line + "\n")

        # -------------------------------------------------------------------
        # WIF-Zusammenfassung nach außen
        # -------------------------------------------------------------------

        total_wifs = len(all_wifs)

        say("")
        say(f"  Analysierte Dateien: {len(analyzed_files)}")
        say(f"  WIFs gesamt:         {total_wifs}")
        say(f"  Sichere WIFs:        {safe_count}")
        say(f"  Alle WIFs:           {os.path.abspath(ALL_WIF_FILE)}")
        say(f"  Sichere WIFs Datei:  {os.path.abspath(SAFE_WIF_FILE)}")
        say(f"  Report:              {os.path.abspath(WIF_REPORT_FILE)}")

        if total_wifs > 0:
            print(f"{GREEN}\u2705 WIF-Kandidaten gefunden: {total_wifs}{RESET}")

            shown = 0
            for wif, info in sorted(
                all_wifs.items(),
                key=lambda kv: (kv[1]["rank"], kv[0]),
                reverse=True,
            ):
                if shown >= 10:
                    break
                conf = info.get("conf", "?")
                print(f"  [{conf}] {wif}")
                shown += 1

        else:
            print(
                f"{RED}\u274c Keine gültigen WIF-Kandidaten gefunden.{RESET}"
            )

    except SystemExit:
        raise

    except Exception as exc:
        tb = getattr(exc, "__traceback__", None)
        line_no = tb.tb_lineno if tb is not None else "?"

        msg = f"FEHLER: Abbruch in Zeile {line_no}"

        log(msg)
        p_clear()

        if use_color:
            print(f"{BOLD}{RED}{msg}{RESET}", file=sys.stderr)
        else:
            print(msg, file=sys.stderr)

        sys.exit(1)

    finally:
        if tmp_all_path is not None:
            try:
                os.unlink(tmp_all_path)
            except OSError:
                pass

        if tmp_cand_path is not None:
            try:
                os.unlink(tmp_cand_path)
            except OSError:
                pass

        if logfile is not None:
            try:
                logfile.close()
            except OSError:
                pass


if __name__ == "__main__":
    main()

