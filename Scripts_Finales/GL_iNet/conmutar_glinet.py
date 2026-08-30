import requests
import hashlib
import sys
import argparse
import urllib3
from passlib.hash import sha256_crypt

# Desactivación de avisos por certificados HTTPS autofirmados.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def get_glinet_hash(username, password, nonce, salt):
    """Calcula la respuesta de autenticación con SHA-256 Crypt y SHA-256."""
    # Hash SHA-256 Crypt con la sal del router y 5000 iteraciones.
    shadow = sha256_crypt.using(salt=salt, rounds=5000).hash(password)
    
    # Combinación del hash, el usuario y el nonce.
    text_to_hash = f"{username}:{shadow}:{nonce}"
    
    # Hash final de la respuesta de autenticación.
    final_hash = hashlib.sha256(text_to_hash.encode('utf-8')).hexdigest()
    return final_hash

def conmutar_wifi(target_state, router_ip="192.168.8.1", username="root", password=""):
    base_url = f"http://{router_ip}"
    rpc_url = f"{base_url}/rpc"
    
    session = requests.Session()
    # Cabeceras de la interfaz web del router.
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "Accept": "application/json, text/plain, */*",
        "Content-Type": "application/json"
    })

    print(f"Conectando con GL.iNet en {router_ip}...")
    
    # Solicitud del desafío de autenticación.
    print("Solicitando el desafío de autenticación...")
    payload_challenge = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "challenge",
        "params": {"username": username}
    }
    
    try:
        r1 = session.post(rpc_url, json=payload_challenge, verify=False)
        r1_data = r1.json()
        
        if "result" not in r1_data:
            print("Error en el desafío:", r1_data)
            return False
            
        nonce = r1_data["result"]["nonce"]
        salt = r1_data["result"]["salt"]
    except Exception as e:
        print("Error conectando al router:", str(e))
        return False

    # Cálculo de la respuesta al desafío.
    print("Calculando la respuesta de autenticación...")
    final_hash = get_glinet_hash(username, password, nonce, salt)
    
    # Inicio de sesión con la respuesta calculada.
    print("Iniciando sesión...")
    payload_login = {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "login",
        "params": {
            "username": username,
            "hash": final_hash
        }
    }
    
    r2 = session.post(rpc_url, json=payload_login, verify=False)
    r2_data = r2.json()
    
    if "result" not in r2_data or "sid" not in r2_data["result"]:
        print("Error: Credenciales inválidas o hash incorrecto.")
        print("Respuesta:", r2_data)
        return False
        
    sid = r2_data["result"]["sid"]
    print(f"Sesión iniciada. Token de sesión (SID): {sid}")
    
    # Inclusión del token de sesión en las cookies.
    session.cookies.set("Admin-Token", sid)

    # Cambio del estado del Wi-Fi mediante ubus RPC.
    enabled_bool = (target_state == "on")
    print(f"Cambiando el estado del Wi-Fi a {'ENCENDIDO' if enabled_bool else 'APAGADO'}...")
    
    iface = "wifi2g"
    
    rpc_id = 3
    payload_wifi = {
        "jsonrpc": "2.0",
        "id": rpc_id,
        "method": "call",
        "params": [
            sid,
            "wifi",
            "set_config",
            {"iface_name": iface, "enabled": enabled_bool}
        ]
    }
    
    try:
        r_wifi = session.post(rpc_url, json=payload_wifi, verify=False, timeout=5)
        print(f"Interfaz {iface}: {r_wifi.text}")
    except requests.exceptions.RequestException as exc:
        if target_state == "off":
            print(
                "Sin confirmación: la orden de apagado ya fue enviada; "
                f"no se recibió respuesta: {exc}"
            )
            return True
        print(f"No se pudo confirmar el cambio de Wi-Fi: {exc}")
        return False
    rpc_id += 1

    # Cierre de la sesión de la API.
    print("Cerrando la sesión de ubus...")
    payload_logout = {
        "jsonrpc": "2.0",
        "id": rpc_id,
        "method": "call",
        "params": [sid, "ui", "logout", {}]
    }
    try:
        session.post(rpc_url, json=payload_logout, verify=False, timeout=2)
    except requests.exceptions.RequestException:
        pass  # Es normal si hemos tirado la red Wi-Fi
    print("Proceso terminado.")
    return True

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Script para conmutar Wi-Fi en router GL.iNet (ubus JSON-RPC)")
    parser.add_argument("password", help="Contraseña del router")
    parser.add_argument("accion", choices=["on", "off"], help="Acción a realizar (on / off)")
    parser.add_argument("--ip", default="192.168.8.1", help="IP del router (por defecto 192.168.8.1)")
    
    args = parser.parse_args()
    sys.exit(0 if conmutar_wifi(args.accion, router_ip=args.ip, password=args.password) else 1)
