#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import string
from typing import List, Tuple, Dict
from scapy.all import rdpcap, ICMP, Raw  # type: ignore

# ====== Parámetros del payload/patrón ======
PAYLOAD_LEN_DEFAULT = 48   # tamaño del data ICMP que usaste en el emisor
CHECK_TAIL = 8             # cuántos bytes del patrón validar (a partir de data[1])

def looks_like_my_template(data: bytes, payload_len: int) -> bool:
    """
    Valida que:
      - el largo del payload sea 'payload_len'
      - data[1..] siga el patrón 0x09, 0x0A, 0x0B, ... (validamos los primeros CHECK_TAIL)
    data[0] puede ser cualquier byte (ahí va el carácter útil).
    """
    if len(data) != payload_len:
        return False
    # validar patrón en los primeros CHECK_TAIL bytes desde la posición 1
    for i in range(1, 1 + CHECK_TAIL):
        expected = (0x08 + i) & 0xFF  # 0x09, 0x0A, 0x0B, ...
        if data[i] != expected:
            return False
    return True

# ====== 1) Extraer el mensaje desde el PCAP ======
def extract_cipher_from_pcap(pcap_path: str, char_offset: int = 0, payload_len: int = PAYLOAD_LEN_DEFAULT) -> str:
    """
    Reconstruye el mensaje tomando 1 byte por Echo Request (ICMP type=8) del flujo correcto.
    Filtra por:
      - tamaño de payload == payload_len
      - patrón de padding (ver looks_like_my_template)
    Agrupa por ICMP id y selecciona el flujo con más paquetes.
    """
    pkts = rdpcap(pcap_path)

    # Recolectar candidatos por id
    flows: Dict[int, List[Tuple[float, int, bytes]]] = {}  # id -> [(ts, seq, ch)]
    for p in pkts:
        if p.haslayer(ICMP) and p.haslayer(Raw):
            icmp = p[ICMP]
            if getattr(icmp, "type", None) == 8 and getattr(icmp, "code", None) == 0:
                data: bytes = p[Raw].load
                if looks_like_my_template(data, payload_len=payload_len):
                    icmp_id = int(getattr(icmp, "id", 0))
                    icmp_seq = int(getattr(icmp, "seq", 0))
                    ts = float(getattr(p, "time", 0.0))
                    if len(data) > char_offset:
                        ch = data[char_offset:char_offset+1]
                        flows.setdefault(icmp_id, []).append((ts, icmp_seq, ch))

    if not flows:
        return ""

    # Elegimos el id con más paquetes (el flujo “bueno”)
    best_id = max(flows.keys(), key=lambda k: len(flows[k]))
    records = flows[best_id]

    # Orden: primero por seq, como respaldo por tiempo
    records.sort(key=lambda t: (t[1], t[0]))

    # Construimos el texto
    chars: List[str] = []
    for _, _, ch in records:
        try:
            c = ch.decode("ascii")
            chars.append(c if c in string.printable else " ")
        except UnicodeDecodeError:
            chars.append(" ")
    return "".join(chars)

# ====== 2) Decodificación César ======
def caesar_shift(text: str, k: int) -> str:
    """Desplaza texto por k posiciones (k=0..25). Mantiene mayúsc./minúsc. No altera espacios ni signos."""
    res = []
    for ch in text:
        if 'a' <= ch <= 'z':
            res.append(chr((ord(ch) - ord('a') - k) % 26 + ord('a')))
        elif 'A' <= ch <= 'Z':
            res.append(chr((ord(ch) - ord('A') - k) % 26 + ord('A')))
        else:
            res.append(ch)
    return "".join(res)

# ====== 3) Heurística para elegir el más probable en español ======
COMMON_WORDS = [
    " el ", " la ", " de ", " que ", " y ", " en ", " a ", " los ", " se ", " del ",
    " por ", " un ", " con ", " para ", " las ", " es ", " una ", " su ", " al ", " lo ",
    # del contexto de tu práctica:
    " criptografia ", " seguridad ", " redes "
]
FREQ_WEIGHTS = {"e": 12.5, "a": 11.5, "o": 8.5, "s": 7.8, "r": 7.6, "n": 7.2, "i": 6.9, "l": 5.5, "d": 5.0, "t": 4.6}

def spanish_score(s: str) -> float:
    st = " " + s.lower() + " "
    score = 0.0
    # 1) Palabras comunes
    for w in COMMON_WORDS:
        score += 8.0 * st.count(w)
    # 2) Frecuencia de letras
    for ch, w in FREQ_WEIGHTS.items():
        score += w * st.count(ch)
    # 3) Bonus pequeño por espacios (texto legible)
    score += st.count(" ") * 0.5
    return score

# ====== 4) Impresión con color ======
GREEN = "\033[92m"
RESET = "\033[0m"

def print_all_candidates(cipher: str) -> Tuple[int, str]:
    """
    Imprime todas las combinaciones (0..25) y resalta en verde la mejor.
    Retorna (mejor_k, mejor_texto).
    """
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

# ====== 5) Main ======
def main():
    if len(sys.argv) < 2:
        print("Uso: sudo python3 readv2.py captura.pcapng [char_offset] [payload_len]")
        print("  char_offset=0 si el carácter útil está en el primer byte del payload ICMP (por defecto).")
        print(f"  payload_len={PAYLOAD_LEN_DEFAULT} por defecto (ajústalo si en el envío usaste otro).")
        sys.exit(1)

    pcap_path = sys.argv[1]
    char_offset = int(sys.argv[2]) if len(sys.argv) >= 3 else 0
    payload_len = int(sys.argv[3]) if len(sys.argv) >= 4 else PAYLOAD_LEN_DEFAULT

    cipher = extract_cipher_from_pcap(pcap_path, char_offset=char_offset, payload_len=payload_len)

    best_k, best = print_all_candidates(cipher)

    print("\nMejor corrimiento (k):", best_k)
    print("Mensaje probable:", best)

if __name__ == "__main__":
    main()