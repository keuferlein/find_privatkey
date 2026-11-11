#!/usr/bin/env bash
set -uo pipefail

usage() {
    cat <<'EOF'
Usage: find_wallet_robust.sh SEARCH_ROOT [OUTPUT_DIR] [JOBS]

Searches for wallet-like files and writes results into OUTPUT_DIR instead of the
current working directory.

- SEARCH_ROOT: directory to scan
- OUTPUT_DIR: destination for log/report files (default: SEARCH_ROOT/.wallet_scan_results)
- JOBS: number of worker processes for the scan (default: 4)

Important:
- OUTPUT_DIR is created automatically.
- OUTPUT_DIR is excluded from the scan.
- The script never writes generated files into the current shell directory.
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

# Do not scan the output directory itself and avoid writing outputs to the current CWD.
# If OUTPUT_DIR is inside SEARCH_ROOT, it is excluded from scans.
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
SAFE_WIF_FILE="$OUTPUT_DIR/safe_wif.txt"

: > "$LOGFILE" || {
    echo "Error: cannot initialize log file: $LOGFILE" >&2
    exit 1
}

log() {
    printf '%s\n' "$*" | tee -a "$LOGFILE"
}

# If output directory is inside search root, exclude it from the scan.
find_args=(
    "$SEARCH_ROOT"
    -type f
    -path "$OUTPUT_DIR/*" -prune -o
    -type f
    -print0
)

if [[ -d "$OUTPUT_DIR" ]]; then
    file_list=$(mktemp "${TMPDIR:-/tmp}/wallet_scan.XXXXXX")
    trap 'rm -f "$file_list"' EXIT

    find "$SEARCH_ROOT" -type f \( -path "$OUTPUT_DIR/*" -prune \) -o -type f -print0 > "$file_list"

    total_files=0
    while IFS= read -r -d '' file; do
        total_files=$((total_files + 1))
    done < "$file_list"

    log "Search root:      $SEARCH_ROOT"
    log "Output dir:       $OUTPUT_DIR"
    log "Log file:         $LOGFILE"
    log "Report file:      $REPORT_FILE"
    log "Total files:      $total_files"
    log ""

    if (( total_files == 0 )); then
        log "No files found in search root."
        printf 'No files found.\n' >&2
        exit 0
    fi

    hits=0
    declare -A seen_hashes=()
    declare -A seen_paths=()

    while IFS= read -r -d '' file; do
        [[ "$file" == "$OUTPUT_DIR"/* ]] && continue

        if ! [[ -r "$file" ]]; then
            continue
        fi

        if ! size=$(stat -c '%s' -- "$file" 2>/dev/null); then
            continue
        fi

        hdr=$(od -An -tx1 -N16 -- "$file" 2>/dev/null | tr -d ' \n' || true)
        bdb_match=0
        if [[ "$hdr" == *"62310500"* ]]; then
            bdb_match=1
        fi

        marker_match=0
        if (( size <= 5242880 )); then
            if grep -aE -q 'bestblock|keymeta|walletversion|cryptedkey|hdmasterpubkey|hdseed' -- "$file" 2>/dev/null; then
                marker_match=1
            fi
        fi

        wif_match=0
        if (( size <= 5242880 )); then
            if grep -aE -q '(^|[^1-9A-HJ-NP-Za-km-z])[1-9A-HJ-NP-Za-km-z]{25,120}([^1-9A-HJ-NP-Za-km-z]|$)' -- "$file" 2>/dev/null; then
                wif_match=1
            fi
        fi

        if (( bdb_match == 0 && marker_match == 0 && wif_match == 0 )); then
            continue
        fi

        hash=$(sha256sum -- "$file" 2>/dev/null | awk '{print $1}' || true)
        if [[ -z "$hash" ]]; then
            continue
        fi

        if [[ -n ${seen_hashes[$hash]:-} ]]; then
            continue
        fi

        seen_hashes[$hash]=1
        seen_paths[$file]=1

        hits=$((hits + 1))
        printf '%s\n' "$file" >> "$OUTPUT_DIR/wallet_hits.txt"

        if (( bdb_match )); then
            printf 'BDB signal: %s\n' "$file" | tee -a "$LOGFILE"
        elif (( marker_match )); then
            printf 'Wallet marker: %s\n' "$file" | tee -a "$LOGFILE"
        else
            printf 'WIF-like text: %s\n' "$file" | tee -a "$LOGFILE"
        fi
    done < "$file_list"

    log ""
    log "Hits detected: $hits"

    if (( hits == 0 )); then
        printf 'No wallet-like candidates found.\n' >&2
        printf 'No wallet-like candidates found.\n' > "$REPORT_FILE"
        printf '\n' > "$ALL_WIF_FILE"
        printf '\n' > "$SAFE_WIF_FILE"
        exit 0
    fi

    {
        printf 'Wallet Search Report\n'
        printf '%s\n' "===================="
        printf 'Search root: %s\n' "$SEARCH_ROOT"
        printf 'Output dir: %s\n' "$OUTPUT_DIR"
        printf 'Time: %s\n' "$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
        printf 'Hits detected: %s\n' "$hits"
        printf '\n'
        printf 'Files:\n'
        while IFS= read -r file; do
            [[ -n "$file" ]] || continue
            printf '  %s\n' "$file"
        done < "$OUTPUT_DIR/wallet_hits.txt"
    } > "$REPORT_FILE"

    : > "$ALL_WIF_FILE"
    : > "$SAFE_WIF_FILE"

    log "Report written to: $REPORT_FILE"
    log "Candidate list written to: $ALL_WIF_FILE"
    log "Safe list written to: $SAFE_WIF_FILE"

    printf 'Finished. %s candidate file(s) found.\n' "$hits"
    printf 'Results stored in: %s\n' "$OUTPUT_DIR"
    exit 0
else
    echo "Error: cannot read output directory: $OUTPUT_DIR" >&2
    exit 1
fi