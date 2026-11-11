#!/usr/bin/env python3
"""Create one redacted forensic report for wallet-like files."""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import stat
import sys
import tempfile
from pathlib import Path

B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
B58_MAP = {char: index for index, char in enumerate(B58_ALPHABET)}
SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
SQLITE_MAGIC = b"SQLite format 3\x00"
BDB_MAGIC = b"\x62\x31\x05\x00"
WALLET_MARKERS = (
    b"bestblock",
    b"keymeta",
    b"walletversion",
    b"pool",
    b"cryptedkey",
    b"hdmasterpubkey",
    b"hdseed",
)
WIF_RE = re.compile(
    rb"(?<![1-9A-HJ-NP-Za-km-z])"
    rb"([1-9A-HJ-NP-Za-km-z]{25,120})"
    rb"(?![1-9A-HJ-NP-Za-km-z])"
)
HEX64_RE = re.compile(
    rb"(?<![0-9a-fA-F])([0-9a-fA-F]{64})(?![0-9a-fA-F])"
)
MAX_ANALYSIS_BYTES = 5 * 1024 * 1024
READ_CHUNK_SIZE = 1024 * 1024


def redact_wif(value: str) -> str:
    if len(value) <= 10:
        return "[redacted]"
    return f"{value[:6]}...{value[-4:]}"


def decode_base58(value: str) -> bytes | None:
    if not value:
        return None

    number = 0
    for char in value:
        digit = B58_MAP.get(char)
        if digit is None:
            return None
        number = number * 58 + digit

    leading_zeroes = len(value) - len(value.lstrip("1"))
    if number == 0:
        return b"\x00" * leading_zeroes

    byte_length = (number.bit_length() + 7) // 8
    return b"\x00" * leading_zeroes + number.to_bytes(byte_length, "big")


def decode_base58check(value: str) -> bytes | None:
    decoded = decode_base58(value)
    if decoded is None or len(decoded) < 5:
        return None

    payload, checksum = decoded[:-4], decoded[-4:]
    expected = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return payload if checksum == expected else None


def is_valid_private_key(key: bytes) -> bool:
    return (
        len(key) == 32
        and 0 < int.from_bytes(key, "big") < SECP256K1_ORDER
    )


def validate_wif(value: str) -> tuple[str, bool] | None:
    payload = decode_base58check(value)
    if payload is None or len(payload) < 33 or payload[0] not in (0x80, 0xEF):
        return None

    body = payload[1:]
    if len(body) == 32:
        key, compressed = body, False
    elif len(body) == 33 and body[-1] == 0x01:
        key, compressed = body[:-1], True
    else:
        return None

    if not is_valid_private_key(key):
        return None

    network = "mainnet" if payload[0] == 0x80 else "testnet"
    return network, compressed


def walk_files(search_root: Path, output_dir: Path) -> tuple[list[Path], list[str]]:
    files: list[Path] = []
    warnings: list[str] = []
    output_resolved = output_dir.resolve()

    def on_walk_error(error: OSError) -> None:
        warnings.append(f"Could not inspect directory: {error.filename}: {error.strerror}")

    for root, directories, filenames in os.walk(
        search_root,
        followlinks=False,
        onerror=on_walk_error,
    ):
        root_path = Path(root)
        directories[:] = [
            name
            for name in directories
            if (root_path / name).resolve() != output_resolved
            and not (root_path / name).is_symlink()
        ]
        for name in filenames:
            path = root_path / name
            try:
                file_stat = path.lstat()
            except OSError as error:
                warnings.append(f"Could not inspect file {path}: {error.strerror}")
                continue
            if stat.S_ISREG(file_stat.st_mode):
                files.append(path)

    return files, warnings


def sha256_file(path: Path) -> str | None:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as source:
            for chunk in iter(lambda: source.read(READ_CHUNK_SIZE), b""):
                digest.update(chunk)
    except OSError:
        return None
    return digest.hexdigest()


def wallet_signals(path: Path) -> tuple[list[str], list[str]]:
    signals: list[str] = []
    warnings: list[str] = []
    try:
        file_size = path.stat().st_size
        with path.open("rb") as source:
            header = source.read(4096)
            if header.startswith(SQLITE_MAGIC):
                signals.append("SQLite header")
            if BDB_MAGIC in header:
                signals.append("Berkeley DB signature")

            if file_size <= MAX_ANALYSIS_BYTES:
                source.seek(0)
                data = source.read(MAX_ANALYSIS_BYTES + 1)
                found_markers = [
                    marker.decode("ascii")
                    for marker in WALLET_MARKERS
                    if marker in data
                ]
                if found_markers:
                    signals.append("wallet marker(s): " + ", ".join(found_markers))
    except OSError as error:
        warnings.append(f"Could not read {path}: {error.strerror}")

    return signals, warnings


def inspect_key_candidates(path: Path) -> tuple[list[dict[str, str]], int, int, list[str]]:
    candidates: list[dict[str, str]] = []
    invalid_wif_count = 0
    hex_key_count = 0
    warnings: list[str] = []
    try:
        file_size = path.stat().st_size
        if file_size > MAX_ANALYSIS_BYTES:
            return candidates, invalid_wif_count, hex_key_count, warnings
        with path.open("rb") as source:
            data = source.read(MAX_ANALYSIS_BYTES + 1)
    except OSError as error:
        warnings.append(f"Could not analyze {path}: {error.strerror}")
        return candidates, invalid_wif_count, hex_key_count, warnings

    seen_wifs: set[str] = set()
    for match in WIF_RE.finditer(data):
        value = match.group(1).decode("ascii")
        validation = validate_wif(value)
        if validation is None:
            invalid_wif_count += 1
            continue
        if value in seen_wifs:
            continue
        seen_wifs.add(value)
        network, compressed = validation
        candidates.append(
            {
                "type": "verified WIF",
                "display": redact_wif(value),
                "network": network,
                "format": "compressed" if compressed else "uncompressed",
                "file": str(path),
            }
        )

    seen_hex_keys: set[bytes] = set()
    for match in HEX64_RE.finditer(data):
        key = bytes.fromhex(match.group(1).decode("ascii"))
        if not is_valid_private_key(key) or key in seen_hex_keys:
            continue
        seen_hex_keys.add(key)
        hex_key_count += 1
        candidates.append(
            {
                "type": "valid 32-byte key-shaped value",
                "display": "[redacted]",
                "network": "not encoded",
                "format": "hex",
                "file": str(path),
            }
        )

    return candidates, invalid_wif_count, hex_key_count, warnings


def build_report(search_root: Path, output_dir: Path) -> str:
    files, warnings = walk_files(search_root, output_dir)
    candidate_files: list[tuple[Path, list[str], str | None]] = []
    candidates: list[dict[str, str]] = []
    invalid_wif_count = 0
    hex_key_count = 0
    seen_file_hashes: set[str] = set()

    for path in files:
        digest = sha256_file(path)
        if digest is None:
            warnings.append(f"Could not hash file: {path}")
        elif digest in seen_file_hashes:
            continue
        else:
            seen_file_hashes.add(digest)

        signals, signal_warnings = wallet_signals(path)
        warnings.extend(signal_warnings)
        if not signals:
            continue
        candidate_files.append((path, signals, digest))

        found, invalid_count, hex_count, analysis_warnings = inspect_key_candidates(path)
        candidates.extend(found)
        invalid_wif_count += invalid_count
        hex_key_count += hex_count
        warnings.extend(analysis_warnings)

    report = [
        "Wallet Forensics Report",
        "=======================",
        f"Search root: {search_root}",
        f"Output directory: {output_dir}",
        f"Unique files scanned: {len(seen_file_hashes)}",
        f"Wallet-pattern files: {len(candidate_files)}",
        f"Verified WIFs: {sum(item['type'] == 'verified WIF' for item in candidates)}",
        f"Valid 32-byte key-shaped values: {hex_key_count}",
        f"Invalid WIF-like strings: {invalid_wif_count}",
        f"Maximum file size for key analysis: {MAX_ANALYSIS_BYTES} bytes",
        "",
        "Wallet-pattern files",
        "---------------------",
    ]

    if not candidate_files:
        report.append("None found.")
    for path, signals, digest in candidate_files:
        digest_text = digest if digest is not None else "unavailable"
        report.append(f"- {path} | signals={'; '.join(signals)} | sha256={digest_text}")

    report.extend(["", "Validated key candidates", "------------------------"])
    if not candidates:
        report.append("None found.")
    for item in candidates:
        report.append(
            f"- {item['display']} | type={item['type']} | "
            f"network={item['network']} | format={item['format']} | file={item['file']}"
        )

    report.extend(["", "Warnings", "--------"])
    if not warnings:
        report.append("None.")
    else:
        report.extend(f"- {warning}" for warning in warnings)

    report.append("")
    report.append(
        "Note: a valid WIF checksum and key range do not prove ownership, "
        "wallet relevance, or recoverability."
    )
    return "\n".join(report)


def write_report_atomically(report_path: Path, contents: str) -> None:
    temp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=report_path.parent,
            prefix=".wallet-report-",
            suffix=".tmp",
            delete=False,
        ) as temporary:
            temp_path = Path(temporary.name)
            temporary.write(contents)
            temporary.flush()
            os.fsync(temporary.fileno())
        os.replace(temp_path, report_path)
    finally:
        if temp_path is not None:
            try:
                temp_path.unlink(missing_ok=True)
            except OSError:
                pass


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Create one redacted forensic report for wallet-like files."
    )
    parser.add_argument("search_root", type=Path, help="directory to scan")
    parser.add_argument(
        "output_dir",
        nargs="?",
        type=Path,
        help="report directory (default: SEARCH_ROOT/.wallet_scan_results)",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    search_root = args.search_root.expanduser()
    if not search_root.is_dir():
        print(f"Error: search root is not a directory: {search_root}", file=sys.stderr)
        return 2

    try:
        search_root = search_root.resolve(strict=True)
        requested_output = args.output_dir or search_root / ".wallet_scan_results"
        if not requested_output.is_absolute():
            requested_output = search_root / requested_output
        requested_output.mkdir(parents=True, exist_ok=True)
        output_dir = requested_output.resolve(strict=True)
    except OSError as error:
        print(f"Error: cannot prepare paths: {error}", file=sys.stderr)
        return 2

    if output_dir == search_root:
        print("Error: output directory must not be the same as search root.", file=sys.stderr)
        return 2

    report_path = output_dir / "wallet_forensics_single_report.txt"
    try:
        report = build_report(search_root, output_dir)
        write_report_atomically(report_path, report)
    except OSError as error:
        print(f"Error: could not write report: {error}", file=sys.stderr)
        return 1

    print(f"Report written to: {report_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
