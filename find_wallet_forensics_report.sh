#!/usr/bin/env bash
set -uo pipefail

usage() {
    cat <<'EOF'
Usage: find_wallet_forensics_report.sh SEARCH_ROOT [OUTPUT_DIR]

Creates a forensic-safe wallet scan report.

- Detects wallet-like files and candidate key material
- Validates WIF-like candidates with Python
- Reports results in a redacted form by default
- No raw key material is printed unless explicitly allowed in a controlled environment

This script is intentionally conservative and forensically safe.
EOF
}

if [[ ${1:-} == "--help" || ${1:-} == "-h" ]]; then
    usage
    exit 0
fi

if [[ $# -lt 1 || $# -gt 2 ]]; then
    usage >&2
    exit 2
fi

SEARCH_ROOT=${1}
OUTPUT_DIR=${2:-${SEARCH_ROOT%/}/.wallet_scan_results}

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
REPORT_FILE="$OUTPUT_DIR/wallet_forensics_report.txt"
CANDIDATES_FILE="$OUTPUT_DIR/wallet_candidates.txt"
MACRO_FILE="$OUTPUT_DIR/wallet_macro_summary.txt"
HITS_FILE="$OUTPUT_DIR/wallet_hits.txt"

: > "$LOGFILE" || {
    echo "Error: cannot initialize log file: $LOGFILE" >&2
    exit 1
}

log() {
    printf '%s\n' "$*" | tee -a "$LOGFILE"
}

FILE_LIST=$(mktemp "${TMPDIR:-/tmp}/wallet_scan.XXXXXX")
trap 'rm -f "$FILE_LIST"' EXIT

find "$SEARCH_ROOT" -type f \( -path "$OUTPUT_DIR/*" -prune \) -o -type f -print0 > "$FILE_LIST"

python3 - "$SEARCH_ROOT" "$OUTPUT_DIR" "$FILE_LIST" "$LOGFILE" "$REPORT_FILE" "$CANDIDATES_FILE" "$MACRO_FILE" "$HITS_FILE" <<'PY'
import hashlib
import os
import re
import stat
import sys

search_root = sys.argv[1]
output_dir = sys.argv[2]
file_list = sys.argv[3]
logfile = sys.argv[4]
report_file = sys.argv[5]
candidates_file = sys.argv[6]
macro_file = sys.argv[7]
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
HEX64_RE = re.compile(rb"(?<![0-9a-fA-F])([0-9a-fA-F]{64})(?![0-9a-fA-F])")
MAX_TEXT_BYTES = 5 * 1024 * 1024


def log(msg):
    with open(logfile, "a", encoding="utf-8") as f:
        f.write(msg + "\n")
    print(msg)


def redact(value):
    if not value:
        return "[redacted]"
    if len(value) <= 8:
        return "[redacted]"
    return value[:6] + "..." + value[-4:]


def sha256_file(path):
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


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


def is_valid_private_key(key):
    if not key or len(key) != 32:
        return False
    n = int.from_bytes(key, "big")
    return 0 < n < SECP256K1_ORDER


def validate_wif_string(s):
    payload = b58check_decode(s)
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
        "network": "mainnet" if version == 0x80 else "testnet",
        "key": key,
        "compressed": compressed,
    }


def candidate_files():
    results = []
    seen_hashes = set()
    try:
        with open(file_list, "rb") as f:
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                for item in chunk.split(b"\x00"):
                    if not item:
                        continue
                    p = item.decode("utf-8", "surrogateescape")
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
                    if h in seen_hashes:
                        continue
                    seen_hashes.add(h)
                    results.append(p)
    except Exception:
        return []
    return results


def is_bdb_like(path):
    try:
        with open(path, "rb") as f:
            head = f.read(64)
    except OSError:
        return False
    return head[12:16] == b"\x62\x31\x05\x00" or b"\x62\x31\x05\x00" in head


def has_wallet_markers(path):
    try:
        st = os.lstat(path)
    except OSError:
        return False
    if st.st_size > MAX_TEXT_BYTES:
        return False
    try:
        with open(path, "rb") as f:
            data = f.read(st.st_size)
    except OSError:
        return False
    return any(marker in data for marker in WALLET_MARKERS)


def collect_wif_candidates(path):
    results = []
    seen = set()
    try:
        st = os.lstat(path)
    except OSError:
        return results
    if st.st_size > MAX_TEXT_BYTES:
        return results
    try:
        with open(path, "rb") as f:
            data = f.read(st.st_size)
    except OSError:
        return results

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
        results.append({
            "type": "wif",
            "value": s,
            "network": info["network"],
            "display": redact(s),
        })

    for m in HEX64_RE.finditer(data):
        try:
            hex_s = m.group(1).decode("ascii")
        except Exception:
            continue
        try:
            raw = bytes.fromhex(hex_s)
        except ValueError:
            continue
        if not is_valid_private_key(raw):
            continue
        label = f"HEX64:{hex_s}"
        if label in seen:
            continue
        seen.add(label)
        results.append({
            "type": "hex64",
            "value": label,
            "network": "unknown",
            "display": label[:10] + "...",
        })

    return results

hits = []
for path in candidate_files():
    if is_bdb_like(path) or has_wallet_markers(path):
        hits.append(path)

with open(hits_file, "w", encoding="utf-8") as f:
    for p in hits:
        f.write(p + "\n")

all_candidates = []
for path in hits:
    candidates = collect_wif_candidates(path)
    for item in candidates:
        all_candidates.append({
            "file": path,
            "type": item["type"],
            "value": item["value"],
            "network": item["network"],
            "display": item["display"],
        })

with open(candidates_file, "w", encoding="utf-8") as f:
    for item in all_candidates:
        f.write(f"{item['display']}\t{item['type']}\t{item['network']}\t{item['file']}\n")

with open(macro_file, "w", encoding="utf-8") as f:
    f.write("Wallet Forensics Macro Summary\n")
    f.write("=============================\n")
    f.write(f"Search root: {search_root}\n")
    f.write(f"Output dir: {output_dir}\n")
    f.write(f"Candidate files: {len(hits)}\n")
    f.write(f"Validated candidates: {len(all_candidates)}\n")
    if not all_candidates:
        f.write("No validated wallet-related key material found.\n")
    else:
        f.write("\n")
        for item in all_candidates:
            f.write(f"- {item['display']} | type={item['type']} | network={item['network']} | file={item['file']}\n")

with open(report_file, "w", encoding="utf-8") as f:
    f.write("Wallet Forensics Report\n")
    f.write("=======================\n")
    f.write(f"Search root: {search_root}\n")
    f.write(f"Output dir: {output_dir}\n")
    f.write(f"Candidate files: {len(hits)}\n")
    f.write(f"Validated candidates: {len(all_candidates)}\n\n")
    if not all_candidates:
        f.write("No validated wallet-related candidates found.\n")
    else:
        for item in all_candidates:
            f.write(f"{item['display']} | type={item['type']} | network={item['network']} | file={item['file']}\n")

log(f"Candidate files: {len(hits)}")
log(f"Validated candidates: {len(all_candidates)}")
if not all_candidates:
    log("No validated wallet-related candidate material found.")
else:
    log("Results are redacted by default. This is a forensic-safe summary report.")
PY

echo "Finished. Forensic-safe results stored in: $OUTPUT_DIR"
