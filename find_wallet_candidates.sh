#!/usr/bin/env bash

set -uo pipefail

usage() {
    printf 'Usage: %s [SEARCH_ROOT ...]\n' "${0##*/}"
    printf 'Search directories for files named wallet.dat or with a Berkeley DB header.\n'
    printf 'If no directory is given, the current directory is searched.\n'
    printf 'This script only reads file headers and metadata; it never prints file contents.\n'
}

if [[ ${1-} == "--help" ]]; then
    usage
    exit 0
fi

if (($# == 0)); then
    set -- .
fi

for root in "$@"; do
    if [[ ! -d $root ]]; then
        printf 'Error: not a directory: %s\n' "$root" >&2
        exit 2
    fi
done

printf '%-24s %12s  %s\n' "MATCH" "SIZE" "PATH"
found=0
declare -A seen=()

for root in "$@"; do
    while IFS= read -r -d '' file; do
        name_match=0
        base=${file##*/}
        if [[ ${base,,} == "wallet.dat" ]]; then
            name_match=1
        fi

        if [[ -n ${seen["$file"]+x} ]]; then
            continue
        fi

        if ! header=$(od -An -tx1 -N4 -- "$file" 2>&1); then
            printf 'Warning: cannot read header: %s (%s)\n' "$file" "$header" >&2
            if ((name_match == 0)); then
                continue
            fi
            signature_match=0
        else
            compact_header=${header//[[:space:]]/}
            case "$compact_header" in
                61150600|00061561) signature_match=1 ;;
                *) signature_match=0 ;;
            esac
        fi

        if ((name_match == 0 && signature_match == 0)); then
            continue
        fi

        if ((name_match && signature_match)); then
            match="wallet.dat + Berkeley DB"
        elif ((name_match)); then
            match="wallet.dat filename"
        else
            match="Berkeley DB header"
        fi

        if ! size=$(stat -c '%s' -- "$file" 2>&1); then
            printf 'Warning: cannot read file metadata: %s (%s)\n' "$file" "$size" >&2
            continue
        fi

        printf '%-24s %12s  %q\n' "$match" "$size" "$file"
        seen["$file"]=1
        found=1
    done < <(find "$root" -type f -print0)
done

if ((found == 0)); then
    printf 'No candidate files found. Check the search roots and any find permission warnings.\n' >&2
    exit 1
fi
