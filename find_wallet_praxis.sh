#!/usr/bin/env bash
set -Eeuo pipefail

LOGFILE="wallet_search_results.log"
SEARCH_DIR="${1:-.}"
TREFFER_DIR="${2:-Trefferliste}"
JOBS="${3:-32}"

mkdir -p "$TREFFER_DIR"
: > "$LOGFILE"

SCRIPT_NAME="$(basename "$0")"
LOG_NAME="$(basename "$LOGFILE")"

# -------- Farbausgabe (abschaltbar über NO_COLOR) --------
if [[ -n "${NO_COLOR:-}" || ! -t 1 ]]; then
  GREEN=""
  RED=""
  YELLOW=""
  CYAN=""
  BOLD=""
  RESET=""
else
  GREEN=$'\033[0;32m'
  RED=$'\033[0;31m'
  YELLOW=$'\033[0;33m'
  CYAN=$'\033[0;36m'
  BOLD=$'\033[1m'
  RESET=$'\033[0m'
fi

# -------- Live-Progress (abschaltbar über NO_PROGRESS) --------
if [[ -n "${NO_PROGRESS:-}" || ! -t 1 ]]; then
  PROGRESS=0
else
  PROGRESS=1
fi
PROGRESS_ACTIVE=0
progress_clear() {
  if (( PROGRESS )); then
    printf '\r\033[K' >&2
    PROGRESS_ACTIVE=0
  fi
}
progress_update() {
  # args: processed total hits dupes
  local processed="$1" total="$2" hits="$3" dupes="$4"
  if (( PROGRESS )); then
    printf '\r%sDurchsuche Dateien:%s %s/%s  %sTreffer:%s %s  %sDuplikate:%s %s\033[K' \
      "${CYAN}" "${RESET}" \
      "$processed" "$total" \
      "${GREEN}" "${RESET}" "$hits" \
      "${YELLOW}" "${RESET}" "$dupes" >&2
    PROGRESS_ACTIVE=1
  fi
}
progress_finish() {
  if (( PROGRESS )); then
    progress_clear
    printf '\n' >&2
  fi
}

# -------- Fehlerausgabe rot+fett (nur Bildschirm), Log clean --------
on_err() {
  local msg="FEHLER: Abbruch in Zeile ${1:-?}"
  # Log immer plain
  echo "$msg" >> "$LOGFILE"
  # Bildschirm (fett/rot, falls möglich)
  progress_clear
  if [[ -n "$RED" ]]; then
    echo -e "${BOLD}${RED}${msg}${RESET}" >&2
  else
    echo "$msg" >&2
  fi
}
trap 'on_err "$LINENO"' ERR

if [[ ! -d "$SEARCH_DIR" ]]; then
  echo "Suchverzeichnis existiert nicht: $SEARCH_DIR" | tee -a "$LOGFILE"
  exit 1
fi

echo "" | tee -a "$LOGFILE"
echo "Suchpfad:       $SEARCH_DIR"     | tee -a "$LOGFILE"
echo "Logdatei:       $LOGFILE"        | tee -a "$LOGFILE"
echo "Trefferordner:  $TREFFER_DIR"    | tee -a "$LOGFILE"
echo "Parallel-Jobs:  $JOBS"           | tee -a "$LOGFILE"
echo "" | tee -a "$LOGFILE"

# -------- Helpers --------

make_dest_flat() {
  local src="$1"
  local base stem ext name dest n
  base="$(basename -- "$src")"

  [[ -n "$base" ]] || base="unnamed_file"

  dest="$TREFFER_DIR/$base"
  if [[ ! -e "$dest" ]]; then
    printf '%s' "$dest"
    return 0
  fi

  if [[ "$base" == *.* && "$base" != .* ]]; then
    stem="${base%.*}"
    ext="${base##*.}"
  else
    stem="$base"
    ext=""
  fi

  n=2
  while :; do
    if [[ -n "$ext" ]]; then
      name="${stem}__${n}.${ext}"
    else
      name="${stem}__${n}"
    fi
    dest="$TREFFER_DIR/$name"
    [[ -e "$dest" ]] || break
    ((n++))
  done

  printf '%s' "$dest"
}

copy_hit_flat() {
  local src="$1"
  local dest
  dest="$(make_dest_flat "$src")"
  cp -p -- "$src" "$dest" 2>/dev/null || true
}

hex_at() {
  local f="$1" off="$2" count="$3"
  dd if="$f" bs=1 skip="$off" count="$count" 2>/dev/null \
    | od -An -tx1 \
    | tr -d ' \n'
}

sqlite_magic_at() {
  local f="$1" off="$2"
  dd if="$f" bs=1 skip="$off" count=16 2>/dev/null \
    | grep -a -q $'SQLite format 3\000'
}

sqlite_header_plausible_at() {
  local f="$1" off="$2" hx ps
  hx="$(hex_at "$f" $((off+16)) 2)"
  [[ ${#hx} -eq 4 ]] || return 1
  ps=$((16#$hx))
  case "$ps" in
    512|1024|2048|4096|8192|16384|32768|65536) return 0 ;;
    *) return 1 ;;
  esac
}

is_sqlite_loose() {
  local f="$1" size off
  size=$(stat -c%s -- "$f" 2>/dev/null || echo 0)
  (( size >= 100 )) || return 1

  if sqlite_magic_at "$f" 0 && sqlite_header_plausible_at "$f" 0; then
    return 0
  fi

  off="$(
    head -c 1048576 -- "$f" 2>/dev/null \
      | LC_ALL=C grep -aobm1 $'SQLite format 3\000' \
      | head -n1 \
      | cut -d: -f1 || true
  )"
  [[ -n "${off:-}" ]] || return 1

  if sqlite_header_plausible_at "$f" "$off"; then
    return 0
  fi

  return 1
}

is_bdb_btree_magic() {
  local f="$1" size hx
  size=$(stat -c%s -- "$f" 2>/dev/null || echo 0)
  (( size >= 16 )) || return 1

  hx="$(hex_at "$f" 12 4)"
  if [[ "$hx" == "62310500" ]]; then
    return 0
  fi

  head -c 4096 -- "$f" 2>/dev/null \
    | grep -a -q $'\x62\x31\x05\x00' && return 0

  return 1
}

scan_one() {
  local file="$1"
  local base

  [[ -f "$file" ]] || return 0

  base="$(basename -- "$file")"

  [[ "$base" == "$SCRIPT_NAME" || "$base" == "$LOG_NAME" ]] && return 0

  case "$file" in
    "$TREFFER_DIR"/*) return 0 ;;
  esac

  if is_sqlite_loose "$file"; then
    printf "SQLITE\t%s\n" "$file"
    return 0
  fi

  if is_bdb_btree_magic "$file"; then
    printf "BDB\t%s\n" "$file"
    return 0
  fi

  return 0
}

export -f scan_one is_sqlite_loose sqlite_magic_at sqlite_header_plausible_at hex_at is_bdb_btree_magic
export SEARCH_DIR TREFFER_DIR SCRIPT_NAME LOG_NAME LOGFILE

TMP_CAND="$(mktemp)"
TMP_ALLFILES="$(mktemp)"
trap 'rm -f "$TMP_CAND" "$TMP_ALLFILES"' EXIT

find "$SEARCH_DIR" -type f -print0 2>/dev/null \
  | tee >(tr '\0' '\n' > "$TMP_ALLFILES") \
  | xargs -0 -n1 -P "$JOBS" bash -c 'scan_one "$1"' _ \
  > "$TMP_CAND"

TOTAL_FILES="$(wc -l < "$TMP_ALLFILES" | tr -d ' ')"
TOTAL_CANDS="$(wc -l < "$TMP_CAND" | tr -d ' ')"

declare -A size_first_file
declare -A size_first_hashed
declare -A seen_size_hash
TOTAL_HITS=0
TOTAL_DUPES=0
PROCESSED=0

# Progress jetzt über TOTAL_FILES (wie gewünscht)
progress_update "$PROCESSED" "$TOTAL_FILES" "$TOTAL_HITS" "$TOTAL_DUPES"

while IFS=$'\t' read -r typ file; do
  [[ -f "$file" ]] || continue

  ((PROCESSED++)) || true

  size="$(stat -c%s -- "$file" 2>/dev/null || echo 0)"
  hash=""

  if [[ -z "${size_first_file[$size]+x}" && -z "${size_first_hashed[$size]+x}" ]]; then
    size_first_file["$size"]="$file"
  else
    if [[ -z "${size_first_hashed[$size]+x}" ]]; then
      first="${size_first_file[$size]}"
      if [[ -f "$first" ]]; then
        h1="$(sha256sum -- "$first" 2>/dev/null | awk '{print $1}' || true)"
        if [[ -n "$h1" ]]; then
          seen_size_hash["$size:$h1"]="$first"
        fi
      fi
      size_first_hashed["$size"]=1
      unset 'size_first_file[$size]' 2>/dev/null || true
    fi

    hash="$(sha256sum -- "$file" 2>/dev/null | awk '{print $1}' || true)"
    [[ -n "$hash" ]] || continue

    if [[ -n "${seen_size_hash[$size:$hash]:-}" ]]; then
      ((TOTAL_DUPES++)) || true
      local_dupe="DUPE: $file  -> zuerst: ${seen_size_hash[$size:$hash]}"
      # Log plain
      progress_clear
      echo "$local_dupe" >> "$LOGFILE"
      # Bildschirm gelb (wenn möglich)
      if [[ -n "$YELLOW" ]]; then
        echo -e "${YELLOW}${local_dupe}${RESET}"
      else
        echo "$local_dupe"
      fi
      progress_update "$PROCESSED" "$TOTAL_FILES" "$TOTAL_HITS" "$TOTAL_DUPES"
      continue
    fi
    seen_size_hash["$size:$hash"]="$file"
  fi

  ((TOTAL_HITS++)) || true

  if [[ -n "$hash" ]]; then
    plain="HIT:  [$typ] $file (size=$size, sha256=$hash)"
  else
    plain="HIT:  [$typ] $file (size=$size, sha256=SKIPPED_UNIQUE_SIZE)"
  fi

  progress_clear
  echo "$plain" >> "$LOGFILE"
  if [[ -n "$GREEN" ]]; then
    echo -e "${GREEN}✅ ${plain}${RESET}"
  else
    echo "$plain"
  fi
  progress_update "$PROCESSED" "$TOTAL_FILES" "$TOTAL_HITS" "$TOTAL_DUPES"

  copy_hit_flat "$file"

  # Progress throttling (wie gehabt, nur Anzeige)
  if (( PROCESSED % 200 == 0 )); then
    progress_update "$PROCESSED" "$TOTAL_FILES" "$TOTAL_HITS" "$TOTAL_DUPES"
  fi

done < "$TMP_CAND"

progress_finish

echo "" | tee -a "$LOGFILE"
echo "Durchsuchte Dateien:        $TOTAL_FILES"  | tee -a "$LOGFILE"
echo "Kandidaten (vor Dedupe):    $TOTAL_CANDS"  | tee -a "$LOGFILE"
echo "Duplikate:                 $TOTAL_DUPES"   | tee -a "$LOGFILE"
echo "Treffer (nach Dedupe):      $TOTAL_HITS"   | tee -a "$LOGFILE"
echo "Log:                        $LOGFILE"      | tee -a "$LOGFILE"
echo "Kopien:                     $TREFFER_DIR"  | tee -a "$LOGFILE"

# -------- Hübsch formatierte Statistik nur auf Bildschirm --------
if [[ -t 1 ]]; then
  echo ""
  echo -e "${BOLD}${CYAN}========== Scan-Statistik ==========${RESET}"
  echo -e "${CYAN}Suchpfad:      ${RESET}${SEARCH_DIR}"
  echo -e "${CYAN}Trefferordner: ${RESET}${TREFFER_DIR}"
  echo -e "${CYAN}Dateien:       ${RESET}${TOTAL_FILES}"
  echo -e "${CYAN}Kandidaten:    ${RESET}${TOTAL_CANDS}"
  echo -e "${CYAN}Duplikate:     ${RESET}${TOTAL_DUPES}"
  echo -e "${CYAN}Treffer:       ${RESET}${TOTAL_HITS}"
  echo -e "${CYAN}Log:           ${RESET}${LOGFILE}"
  echo -e "${BOLD}${CYAN}====================================${RESET}"
fi

# -------- Status nur auf Bildschirm --------
if (( TOTAL_HITS > 0 )); then
  echo -e "${GREEN}✅ Treffer gefunden: ${TOTAL_HITS}${RESET}"
else
  echo -e "${RED}❌ Keine passenden Dateien gefunden.${RESET}"
fi