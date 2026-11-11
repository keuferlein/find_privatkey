#!/bin/bash

# Funktion zum Erkennen von Berkeley DB-Magic und Keywords
erkennung() {
    local file="$1"
    if [[ $(xxd -p -l 4 "$file" | grep -q '^00913d') ]]; then
        return 0
    fi
    for keyword in "bestblock" "keymeta" "walletversion" "pool"; do
        if grep -q "$keyword" "$file"; then
            return 0
        fi
    done
    # Suchen nach Hex-Werten und WIFs
    if xxd -p -l 32 "$file" | grep -qE '^(00|5[KL])'; then
        return 0
    fi
    return 1
}

# Funktion zum Extrahieren von Private Keys (Hex-Strings)
extraktion() {
    local file="$1"
    xxd -p "$file" | awk '
        BEGIN { RS=""; FS="\n" }
        NF > 32 && substr($0, 1, 2) == "20" {
            print substr($0, 3, 64)
        }' >> kandidaten.txt
}

# Funktion zur Base58-Kodierung in Bash
base58() {
    local input="$1"
    local alphabet="123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    local output=""
    while [ -n "$input" ]; do
        local remainder=$((16#$input % 58))
        output=${alphabet:$remainder:1}$output
        input=$(bc <<< "obase=16; $input / 58")
    done
    echo "$output"
}

# Funktion zur Erzeugung von WIFs aus Private Keys
wif_erkellen() {
    local hex_key="$1"
    local wif=${hex_key}80$(openssl dgst -sha256 -binary <<< "${hex_key}80" | openssl dgst -sha256 -binary | xxd -p -l 8)
    echo $(base58 "$wif")
}

# Funktion zum Ableiten des Public Keys aus dem Private Key
public_key() {
    local hex_key="$1"
    openssl ec -inform DER -text -noout <<< "0x04$(openssl ecparam -name secp256k1 -genkey -noout | openssl asn1parse -inform der)" <(echo "$hex_key") | grep ": (EC key, secp256k1) -" | cut -d ':' -f 3-
}

# Funktion zur Erzeugung von Bitcoin-Adressen aus Public Keys
adresse_erkellen() {
    local public_key="$1"
    local hash=$(openssl dgst -sha256 <<< "${public_key}" | xxd -r -p | openssl dgst -ripemd160 -provider legacy -provider default)
    local address="12$(base58 "00${hash}")"
    echo "$address"
}

# Funktion zum Guthabencheck über API
guthaben_check() {
    local adresse="$1"
    curl -s "https://blockstream.info/api/address/$adresse" | jq '.chain_stats.funded_txo_sum'
}

# Hauptprogrammablauf
while true; do
    echo "Such- und Filterkriterien erfüllen..."
    find . -type f \( -exec ./erkennung {} \; -print \) >> kandidaten.txt

    if [ ! -s "kandidaten.txt" ]; then
        echo "Keine potenziellen Wallet-Dateien gefunden."
        exit 1
    fi

    echo "Private Keys extrahieren..."
    while read file; do
        extraktion "$file"
    done < kandidaten.txt

    if [ ! -s "kandidaten.txt" ]; then
        echo "Keine Private Keys gefunden."
        exit 1
    fi

    echo "[A] Beenden oder [B] weiter mit WIF-Generierung und Guthabencheck?"
    read choice
    case $choice in
        A)
            exit 0
            ;;
        B)
            echo "WIFs generieren..."
            while read hex_key; do
                wif=$(wif_erkellen "$hex_key")
                public_key=$(public_key "$hex_key")
                adresse=$(adresse_erkellen "$public_key")
                guthaben=$(guthaben_check "$adresse")

                if [ $guthaben -gt 0 ]; then
                    echo "${adresse} | ${guthaben} | ${wif}" >> funde.txt
                fi
            done < kandidaten.txt

            echo "Funde:"
            cat funde.txt
            ;;
    esac
done

