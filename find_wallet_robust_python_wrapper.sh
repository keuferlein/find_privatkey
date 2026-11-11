#!/usr/bin/env bash
set -uo pipefail

usage() {
    cat <<'EOF'
Usage: find_wallet_robust_python_wrapper.sh SEARCH_ROOT [OUTPUT_DIR] [JOBS]

Searches for wallet-like files and validates any WIF-like strings using a Python
wrapper.

- SEARCH_ROOT: directory to scan
- OUTPUT_DIR: output directory for logs and results (default: SEARCH_ROOT/.wallet_scan_results)
- JOBS: optional worker count, kept for compatibility (default: 4)

All generated files are written to OUTPUT_DIR, never to the current shell directory.
EOF
}

if [[ ${1:-} == "--help" || ${1:-} == "-h" ]]; then
    usage
    exit 0
fi

if [[ $# -lt 1 || $# -gt 3 ]]; then
    usage >&2
    exit 2
fi

SEARCH_ROOT=${1}
OUTPUT_DIR=${2:-${SEARCH_ROOT%/}/.wallet_scan_results}
JOBS=${3:-4}

if ! [[ "$JOBS" =~ ^[1-9][0-9]*$ ]]; then
    echo "Error: JOBS must be a positive integer." >&2
    exit 2
fi

if [[ ! -d "$SEARCH_ROOT" ]]; then
    echo "Error: search root does not exist: $SEARCH_ROOT" >&2
    exit 1
fi

SEARCH_ROOT=$(cd "$SEARCH_ROOT" 2>/dev/null && pwd -P) || {
    echo "Error: cannot resolve search root: $SEARCH_ROOT" >&2
    exit 1
}

if [[ "$OUTPUT_DIR" != /* ]]; then
    OUTPUT_DIR="$SEARCH_ROOT/$OUTPUT_DIR"
fi

mkdir -p "$OUTPUT_DIR" || {
    echo "Error: cannot create output directory: $OUTPUT_DIR" >&2
    exit 1
}

OUTPUT_DIR=$(cd "$OUTPUT_DIR" 2>/dev/null && pwd -P) || {
    echo "Error: cannot resolve output directory: $OUTPUT_DIR" >&2
    exit 1
}

if [[ "$OUTPUT_DIR" == "$SEARCH_ROOT" ]]; then
    echo "Error: OUTPUT_DIR must not be the same as SEARCH_ROOT." >&2
    exit 2
fi

LOGFILE="$OUTPUT_DIR/wallet_search_results.log"
REPORT_FILE="$OUTPUT_DIR/wallet_wif_report.txt"
ALL_WIF_FILE="$OUTPUT_DIR/wif_kandidaten.txt"
SAFE_WIF_FILE="$OUTPUT_DIR/wif_sicher.txt"
HITS_FILE="$OUTPUT_DIR/wallet_hits.txt"

: > "$LOGFILE" || {
    echo "Error: cannot initialize log file: $LOGFILE" >&2
    exit 1
}

FILE_LIST=$(mktemp "${TMPDIR:-/tmp}/wallet_scan.XXXXXX")
trap 'rm -f "$FILE_LIST"' EXIT

find "$SEARCH_ROOT" -type f \( -path "$OUTPUT_DIR/*" -prune \) -o -type f -print0 > "$FILE_LIST"

python3 - "$SEARCH_ROOT" "$OUTPUT_DIR" "$FILE_LIST" "$LOGFILE" "$REPORT_FILE" "$ALL_WIF_FILE" "$SAFE_WIF_FILE" "$HITS_FILE" <<'PY'
import hashlib
import os
import re
import stat
import sys
from collections import defaultdict

search_root = sys.argv[1]
output_dir = sys.argv[2]
file_list = sys.argv[3]
logfile = sys.argv[4]
report_file = sys.argv[5]
all_wif_file = sys.argv[6]
safe_wif_file = sys.argv[7]
hits_file = sys.argv[8]

B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
B58_MAP = {c: i for i, c in enumerate(B58_ALPHABET)}
SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
WALLET_MARKERS = (
    b"bestblock",
    b"keymeta",
    b"walletversion",
    b"pool",
    b"cryptedkey",
    b"hdmasterpubkey",
    b"hdseed",
)
WIF_RE = re.compile(rb"(?<![1-9A-HJ-NP-Za-km-z])([1-9A-HJ-NP-Za-km-z]{25,120})(?![1-9A-HJ-NP-Za-km-z])")
MAX_TEXT_BYTES = 5 * 1024 * 1024


def log(msg):
    with open(logfile, "a", encoding="utf-8") as f:
        f.write(msg + "\n")
    print(msg)


def sha256_file(path):
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def is_valid_private_key(key):
    if not key or len(key) != 32:
        return False
    n = int.from_bytes(key, "big")
    return 0 < n < SECP256K1_ORDER


def b58_decode(s):
    s = s.strip()
    if not s:
        return None
    num = 0
    for ch in s:
        if ch not in B58_MAP:
            return None
        num = num * 58 + B58_MAP[ch]
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


def b58check_decode(s):
    raw = b58_decode(s)
    if not raw or len(raw) < 5:
        return None
    payload, checksum = raw[:-4], raw[-4:]
    calc = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    if calc != checksum:
        return None
    return payload


def validate_wif_string(s):
    if not s:
        return None
    try:
        payload = b58check_decode(s)
    except Exception:
        return None
    if not payload or len(payload) < 33:
        return None
    version = payload[0]
    if version not in (0x80, 0xEF):
        return None
    body = payload[1:]
    if len(body) == 32:
        key = body
        compressed = False
    elif len(body) == 33 and body[-1] == 0x01:
        key = body[:-1]
        compressed = True
    else:
        return None
    if not is_valid_private_key(key):
        return None
    return {
        "key": key,
        "compressed": compressed,
        "network": "mainnet" if version == 0x80 else "testnet",
    }


def candidate_files():
    found = []
    seen_hashes = set()
    try:
        with open(file_list, "rb") as f:
            while True:
                path = f.read(4096)
                if not path:
                    break
                # The file list is NUL-delimited.
                for p in path.split(b"\x00"):
                    if not p:
                        continue
                    p = p.decode("utf-8", "surrogateescape")
                    if not os.path.isfile(p):
                        continue
                    if os.path.abspath(p).startswith(os.path.abspath(output_dir) + os.sep):
                        continue
                    try:
                        st = os.lstat(p)
                    except OSError:
                        continue
                    if not stat.S_ISREG(st.st_mode):
                        continue
                    h = sha256_file(p)
                    if not h:
                        continue
                    if h in seen_hashes:
                        continue
                    seen_hashes.add(h)
                    found.append(p)
    except Exception:
        pass
    return found


def is_bdb_like(path):
    try:
        with open(path, "rb") as f:
            head = f.read(64)
    except OSError:
        return False
    if not head:
        return False
    if head[12:16] == b"\x62\x31\x05\x00":
        return True
    if b"\x62\x31\x05\x00" in head:
        return True
    return False


def has_wallet_markers(path, limit=5 * 1024 * 1024):
    try:
        st = os.lstat(path)
    except OSError:
        return False
    if st.st_size > limit:
        return False
    try:
        with open(path, "rb") as f:
            data = f.read(limit)
    except OSError:
        return False
    return any(marker in data for marker in WALLET_MARKERS)


def extract_valid_wifs(path):
    valid = []
    seen = set()
    try:
        st = os.lstat(path)
    except OSError:
        return valid
    if st.st_size > MAX_TEXT_BYTES:
        return valid
    try:
        with open(path, "rb") as f:
            data = f.read(st.st_size)
    except OSError:
        return valid
    for m in WIF_RE.finditer(data):
        try:
            s = m.group(1).decode("ascii")
        except Exception:
            continue
        info = validate_wif_string(s)
        if info is None:
            continue
        if s in seen:
            continue
        seen.add(s)
        valid.append((s, info["network"]))
    return valid


all_valid = {}
valid_count = 0
hits = []

for path in candidate_files():
    if is_bdb_like(path) or has_wallet_markers(path):
        hits.append(path)

if not hits:
    log("No wallet-like candidates found.")
    open(all_wif_file, "w", encoding="utf-8").close()
    open(safe_wif_file, "w", encoding="utf-8").close()
    with open(report_file, "w", encoding="utf-8") as f:
        f.write("Wallet WIF Report\n")
        f.write("====================\n")
        f.write(f"Search root: {search_root}\n")
        f.write(f"Output dir: {output_dir}\n")
        f.write("No wallet-like candidates found.\n")
    with open(hits_file, "w", encoding="utf-8") as f:
        pass
    sys.exit(0)

for path in hits:
    file_hash = sha256_file(path)
    valid = extract_valid_wifs(path)
    if not valid:
        log(f"Candidate file {path} matched wallet heuristics but no valid WIFs found.")
        continue
    for wif, net in valid:
        all_valid.setdefault(wif, {"network": net, "files": set(), "hash": file_hash})
        all_valid[wif]["files"].add(path)
    log(f"Candidate {path} -> {len(valid)} valid WIF(s)")

sorted_wifs = sorted(all_valid)
with open(all_wif_file, "w", encoding="utf-8") as f:
    for wif in sorted_wifs:
        f.write(wif + "\n")

with open(safe_wif_file, "w", encoding="utf-8") as f:
    for wif in sorted_wifs:
        if all_valid[wif]["network"] == "mainnet":
            f.write(wif + "\n")

with open(hits_file, "w", encoding="utf-8") as f:
    for p in hits:
        f.write(p + "\n")

with open(report_file, "w", encoding="utf-8") as f:
    f.write("Wallet WIF Report\n")
    f.write("====================\n")
    f.write(f"Search root: {search_root}\n")
    f.write(f"Output dir: {output_dir}\n")
    f.write(f"Candidate files: {len(hits)}\n")
    f.write(f"Valid WIFs: {len(sorted_wifs)}\n\n")
    if not sorted_wifs:
        f.write("No valid WIFs were found.\n")
    else:
        for wif in sorted_wifs:
            info = all_valid[wif]
            files = ", ".join(sorted(info["files"]))
            f.write(f"{wif} | network={info['network']} | file(s)={files}\n")

log(f"Found {len(sorted_wifs)} valid WIF(s) in {len(hits)} candidate file(s).")
PY

if [[ -s "$ALL_WIF_FILE" ]]; then
    echo "Finished. Valid WIF candidates written to: $OUTPUT_DIR"
else
    echo "Finished. No valid WIFs found. Results stored in: $OUTPUT_DIR"
fi
