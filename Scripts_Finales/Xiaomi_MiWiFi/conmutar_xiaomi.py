import requests
import hashlib
import time
import random
import sys
import argparse

def sha1(text):
    return hashlib.sha1(text.encode('utf-8')).hexdigest()

def do_login(password, router_ip="192.168.31.1"):
    base_url = f"http://{router_ip}"
    key = "a2ffa5c9be07488bbb04a3a47d3c5f6a"
    
    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36"
    })
    
    # Obtención de la MAC utilizada en la autenticación.
    try:
        r_html = session.get(f"{base_url}/cgi-bin/luci/web", timeout=5)
        import re
        mac_match = re.search(r"deviceId\s*=\s*['\"]([^'\"]+)['\"]", r_html.text)
        mac = mac_match.group(1) if mac_match else "e0:d4:64:23:5f:0f"
    except requests.exceptions.RequestException:
        print("No se pudo contactar con el router Xiaomi.")
        return None, None

    # Generación del nonce de la petición.
    nonce = f"0_{mac}_{int(time.time())}_{random.randint(0, 9999)}"
    
    # Cálculo de los dos hashes SHA-1.
    inner_hash = sha1(password + key)
    final_hash = sha1(nonce + inner_hash)
    
    # Envío de la petición de inicio de sesión.
    payload = {
        "username": "admin",
        "password": final_hash,
        "logtype": "2",
        "nonce": nonce
    }
    
    login_url = f"{base_url}/cgi-bin/luci/api/xqsystem/login"
    r_login = session.post(login_url, data=payload)
    data = r_login.json()
    
    if data.get("code") == 0:
        return session, data.get("token")
    else:
        return None, None

def conmutar_wifi(action, password, router_ip, wifi_pwd, ssid):
    print(f"Conectando con Xiaomi en {router_ip}...")
    
    session, stok = do_login(password, router_ip)
    if not stok:
        print("Fallo de autenticación. Comprueba la contraseña de admin.")
        sys.exit(1)
        
    print(f"Sesión iniciada. Token (stok): {stok}")
    print(f"Cambiando estado de Wi-Fi a {action.upper()}...")
    
    estado_on = "1" if action == "on" else "0"
    
    # Parámetros de la banda de 2,4 GHz, identificada por wifiIndex 1.
    payload_wifi = {
        "wifiIndex": "1",
        "on": estado_on,
        "ssid": ssid,
        "pwd": wifi_pwd,
        "encryption": "mixed-psk",
        "channel": "0",
        "bandwidth": "0",
        "hidden": "0",
        "txpwr": "max"
    }
    
    url_wifi = f"http://{router_ip}/cgi-bin/luci/;stok={stok}/api/xqnetwork/set_wifi"
    
    try:
        r_wifi = session.post(url_wifi, data=payload_wifi, timeout=5)
        print(f"Respuesta del router: {r_wifi.text}")
    except requests.exceptions.RequestException as exc:
        if action == "off":
            print(
                "Sin confirmación: la orden de apagado ya fue enviada; "
                f"no se recibió respuesta: {exc}"
            )
            return True
        print(f"No se pudo confirmar el cambio de Wi-Fi: {exc}")
        return False
        
    print("Proceso terminado.")
    return True

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Script para conmutar Wi-Fi en router Xiaomi Mi 4C")
    parser.add_argument("password", help="Contraseña de administrador del router")
    parser.add_argument("wifi_pwd", help="Contraseña de la red Wi-Fi (necesaria en la API)")
    parser.add_argument("ssid", help="Nombre de la red Wi-Fi (SSID)")
    parser.add_argument("accion", choices=["on", "off"], help="Acción a realizar (on / off)")
    parser.add_argument("--ip", default="192.168.31.1", help="IP del router (por defecto 192.168.31.1)")
    
    args = parser.parse_args()
    
    sys.exit(
        0 if conmutar_wifi(
            args.accion,
            password=args.password,
            router_ip=args.ip,
            wifi_pwd=args.wifi_pwd,
            ssid=args.ssid,
        ) else 1
    )
