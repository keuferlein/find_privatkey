#!/usr/bin/env bash
set -uo pipefail

usage() {
    cat <<'EOF'
Usage: find_wallet_forensics_single.sh SEARCH_ROOT [OUTPUT_DIR]

Creates exactly one forensic-safe report file in OUTPUT_DIR.

- Searches for wallet-like files and candidate key material
- Validates WIF-like candidates with Python
- Writes one report only: wallet_forensics_single_report.txt
- All results are redacted by default
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

REPORT_FILE="$OUTPUT_DIR/wallet_forensics_single_report.txt"
TMP_FILE=$(mktemp "${TMPDIR:-/tmp}/wallet_forensics.XXXXXX")
trap 'rm -f "$TMP_FILE"' EXIT

python3 - "$SEARCH_ROOT" "$OUTPUT_DIR" "$TMP_FILE" <<'PY'
import hashlib
import os
import re
import stat
import sys

search_root = sys.argv[1]
output_dir = sys.argv[2]
tmp_file = sys.argv[3]

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


def iter_files():
    seen_hashes = set()
    try:
        with open(os.path.join(output_dir, "._scan_list"), "rb") as f:
            items = f.read().split(b"\x00")
    except OSError:
        return []
    out = []
    for item in items:
        if not item:
            continue
        p = item.decode("utf-8", "surrogateescape")
        if not os.path.isfile(p):
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
        out.append(p)
    return out


def walk_files(root):
    results = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if os.path.abspath(os.path.join(dirpath, d)) != os.path.abspath(output_dir)]
        for name in filenames:
            p = os.path.join(dirpath, name)
            if os.path.abspath(p).startswith(os.path.abspath(output_dir) + os.sep):
                continue
            results.append(p)
    return results


hits = []
for p in walk_files(search_root):
    try:
        with open(p, "rb") as f:
            head = f.read(64)
    except OSError:
        continue
    if head[12:16] == b"\x62\x31\x05\x00" or b"\x62\x31\x05\x00" in head:
        hits.append(p)
        continue
    try:
        st = os.lstat(p)
    except OSError:
        continue
    if st.st_size <= MAX_TEXT_BYTES:
        try:
            with open(p, "rb") as f:
                data = f.read(st.st_size)
        except OSError:
            continue
        if any(marker in data for marker in WALLET_MARKERS):
            hits.append(p)

results = []
for p in hits:
    try:
        st = os.lstat(p)
    except OSError:
        continue
    if st.st_size > MAX_TEXT_BYTES:
        continue
    try:
        with open(p, "rb") as f:
            data = f.read(st.st_size)
    except OSError:
        continue

    for m in WIF_RE.finditer(data):
        try:
            s = m.group(1).decode("ascii")
        except Exception:
            continue
        info = validate_wif_string(s)
        if info is None:
            continue
        results.append({
            "type": "wif",
            "value": redact(s),
            "network": info["network"],
            "file": p,
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
        results.append({
            "type": "hex64",
            "value": hex_s[:10] + "...",
            "network": "unknown",
            "file": p,
        })

# unique by file+type+value
seen = set()
uniq = []
for item in results:
    k = (item["file"], item["type"], item["value"])
    if k in seen:
        continue
    seen.add(k)
    uniq.append(item)

report = [
    "Wallet Forensics Single Report",
    "=============================",
    f"Search root: {search_root}",
    f"Output dir: {output_dir}",
    f"Candidate files: {len(hits)}",
    f"Validated candidates: {len(uniq)}",
    "",
]

if not uniq:
    report.append("No validated wallet-related candidates found.")
else:
    for item in uniq:
        report.append(f"- {item['value']} | type={item['type']} | network={item['network']} | file={item['file']}")

with open(tmp_file, "w", encoding="utf-8") as f:
    f.write("\n".join(report) + "\n")

print("VALIDATED_CANDIDATES=%d" % len(uniq), flush=True)
PY

mv "$TMP_FILE" "$REPORT_FILE"

echo "Finished. Single forensic-safe report written to: $REPORT_FILE"
