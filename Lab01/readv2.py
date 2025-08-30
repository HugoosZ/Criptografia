#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import string
from typing import List, Tuple, Dict, Optional
from scapy.all import rdpcap, ICMP, Raw  # type: ignore

MIN_PATTERN_LEN = 4      # mínimo de 0x09,0x0A,0x0B,... consecutivos
DEFAULT_ACCEPT_TYPES = (8,)  # por defecto SOLO Echo Request

def find_char_offset(data: bytes) -> Optional[int]:
    n = len(data)
    for start in range(1, n - MIN_PATTERN_LEN):
        ok = True
        for i in range(MIN_PATTERN_LEN):
            expected = (0x09 + i) & 0xFF
            if start + i >= n or data[start + i] != expected:
                ok = False
                break
        if ok:
            char_pos = start - 1
            if char_pos >= 0:
                return char_pos
    return None

def extract_cipher_from_pcap(pcap_path: str, accept_types=DEFAULT_ACCEPT_TYPES) -> str:
    """
    Lee la traza, toma SOLO los tipos ICMP de accept_types (por defecto, {8}),
    autodetecta el offset del carácter (byte anterior a la cola 0x09..),
    agrupa por icmp.id y reconstruye el flujo principal.
    Deduplica por seq para evitar duplicados.
    """
    pkts = rdpcap(pcap_path)
    flows: Dict[int, Dict[int, Tuple[float, bytes]]] = {}  # id -> {seq: (ts, ch)}

    for p in pkts:
        if not (p.haslayer(ICMP) and p.haslayer(Raw)):
            continue
        icmp = p[ICMP]
        if getattr(icmp, "type", None) not in accept_types or getattr(icmp, "code", None) != 0:
            continue

        data: bytes = p[Raw].load
        if not data or len(data) < 12:
            continue

        char_offset = find_char_offset(data)
        if char_offset is None or char_offset >= len(data):
            continue

        ch = data[char_offset:char_offset+1]
        icmp_id = int(getattr(icmp, "id", 0))
        icmp_seq = int(getattr(icmp, "seq", 0))
        ts = float(getattr(p, "time", 0.0))

        flows.setdefault(icmp_id, {})
        # dedupe: si ya vimos este seq, nos quedamos con el primero (ts menor)
        if icmp_seq not in flows[icmp_id] or ts < flows[icmp_id][icmp_seq][0]:
            flows[icmp_id][icmp_seq] = (ts, ch)

    if not flows:
        # Plan B: intentar con Echo Reply únicamente, por si la captura sólo los contiene
        if accept_types != (0,):
            return extract_cipher_from_pcap(pcap_path, accept_types=(0,))
        return ""

    # Elegir el id con más secuencias únicas
    best_id = max(flows.keys(), key=lambda k: len(flows[k]))
    seqmap = flows[best_id]

    # Ordenar por seq
    ordered = sorted(seqmap.items(), key=lambda kv: kv[0])  # (seq, (ts, ch))

    chars: List[str] = []
    for _, (_, ch) in ordered:
        try:
            c = ch.decode("ascii")
            chars.append(c if c in string.printable else " ")
        except UnicodeDecodeError:
            chars.append(" ")
    return "".join(chars)

# ====== César ======
def caesar_shift(text: str, k: int) -> str:
    res = []
    for ch in text:
        if 'a' <= ch <= 'z':
            res.append(chr((ord(ch) - ord('a') - k) % 26 + ord('a')))
        elif 'A' <= ch <= 'Z':
            res.append(chr((ord(ch) - ord('A') - k) % 26 + ord('A')))
        else:
            res.append(ch)
    return "".join(res)

COMMON_WORDS = [
    " el ", " la ", " de ", " que ", " y ", " en ", " a ", " los ", " se ", " del ",
    " por ", " un ", " con ", " para ", " las ", " es ", " una ", " su ", " al ", " lo ",
    " criptografia ", " seguridad ", " redes "
]
FREQ_WEIGHTS = {"e": 12.5, "a": 11.5, "o": 8.5, "s": 7.8, "r": 7.6, "n": 7.2, "i": 6.9, "l": 5.5, "d": 5.0, "t": 4.6}

def spanish_score(s: str) -> float:
    st = " " + s.lower() + " "
    score = 0.0
    for w in COMMON_WORDS:
        score += 8.0 * st.count(w)
    for ch, w in FREQ_WEIGHTS.items():
        score += w * st.count(ch)
    score += st.count(" ") * 0.5
    return score

GREEN = "\033[92m"
RESET = "\033[0m"

def print_all_candidates(cipher: str) -> Tuple[int, str]:
    candidates = []
    for k in range(26):
        plain = caesar_shift(cipher, k)
        candidates.append((k, plain, spanish_score(plain)))
    best_k, best_text, _ = max(candidates, key=lambda x: x[2])
    for k, txt, _ in candidates:
        line = f"{k:>2} {txt}"
        if k == best_k:
            print(GREEN + line + RESET)
        else:
            print(line)
    return best_k, best_text

def main():
    if len(sys.argv) < 2:
        print("Uso: sudo python3 readv2.py captura.pcapng")
        sys.exit(1)

    pcap_path = sys.argv[1]
    cipher = extract_cipher_from_pcap(pcap_path)

    best_k, best = print_all_candidates(cipher)
    print("\nMejor corrimiento (k):", best_k)
    print("Mensaje probable:", best)

if __name__ == "__main__":
    main()