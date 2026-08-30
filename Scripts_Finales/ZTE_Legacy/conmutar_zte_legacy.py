import requests
import hashlib
import time
import re
import sys

def zte_login(session, base_url, username, password):
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "es-ES,es;q=0.9"
    })
    
    # Petición inicial para obtener el token de sesión.
    try:
        r1 = session.get(base_url + "/")
    except Exception as e:
        print(f"Error de conexión: {e}")
        return False
        
    match = re.search(r'["\']_sessionTOKEN["\']\s*,\s*["\'](\d+)["\']', r1.text)
    if not match:
        print("No se encontró _sessionTOKEN inicial.")
        return False
    session_token = match.group(1)
    
    # Petición de la semilla de autenticación.
    timestamp = int(time.time() * 1000)
    token_url = f"{base_url}/function_module/login_module/login_page/logintoken_lua.lua?_={timestamp}"
    r2 = session.get(token_url, headers={"X-Requested-With": "XMLHttpRequest"})
    
    seed_match = re.search(r'>\s*(\d+)\s*<', r2.text)
    if not seed_match:
        seed_match = re.search(r'(\d+)', r2.text)
    if not seed_match:
        print("No se pudo extraer la semilla.")
        return False
    seed = seed_match.group(1)
    
    # Hash SHA-256 de la contraseña y la semilla.
    hash_password = hashlib.sha256((password + seed).encode('utf-8')).hexdigest()
    
    # Envío de la petición de inicio de sesión.
    payload = {
        "action": "login",
        "Username": username,
        "Password": hash_password,
        "_sessionTOKEN": session_token
    }
    
    r3 = session.post(base_url + "/", data=payload, headers={"Content-Type": "application/x-www-form-urlencoded"}, allow_redirects=False)
    
    if r3.status_code == 302 or "SID" in r3.cookies:
        print("Sesión iniciada.")
        return True
    return False

def get_new_token(session, base_url):
    """
    Después de iniciar sesión, necesitamos un nuevo _sessionTOKEN para hacer cambios.
    Navegamos a la página de WLAN (Localnet_WlanBasicAd_t.lp) para que el router
    inicialice la sesión de esa sección, y extraemos el _sessionTmpToken de su HTML.
    """
    # Visita al menú WLAN para autorizar las peticiones siguientes.
    # La cuenta 'user' accede a WlanBasicUser_t.lp; Ad_t.lp devuelve un 404.
    url_wlan = base_url + "/getpage.lua?pid=1002&nextpage=Localnet_WlanBasicUser_t.lp"
    r = session.get(url_wlan, allow_redirects=True)
    
    # Ante un 404 se visita primero la página principal
    # y se repite la petición al menú WLAN.
    if len(r.text) < 500:
        session.get(base_url + "/?_type=menuData&_theme=black&_type=menuData&_theme=black")
        r = session.get(url_wlan, allow_redirects=True)
    
    # Extracción del último token codificado en hexadecimal.
    matches = re.findall(r'_sessionTmpToken\s*=\s*["\']([^"\']+)["\']', r.text)
    if not matches:
        # Alternativa para respuestas con _sessionTOKEN sin codificar.
        matches = re.findall(r'["\']_sessionTOKEN["\']\s*,\s*["\'](\d+)["\']', r.text)
        if matches: return matches[-1]
        return None
        
    raw_token = matches[-1] # El último token es el válido para el formulario de aplicar
    
    try:
        clean_token = raw_token.encode('utf-8').decode('unicode_escape')
        return clean_token
    except Exception:
        return raw_token.replace('\\x', '')

def toggle_wifi(session, base_url, action):
    # Obtención de un token actualizado.
    new_token = get_new_token(session, base_url)
    if not new_token:
        print("No se pudo obtener el _sessionTOKEN para autorizar el cambio de Wi-Fi.")
        return False
        
    # Estado solicitado: 1 para encendido y 0 para apagado.
    status_val = "1" if action == "on" else "0"
    
    print(f"Enviando orden para poner el Wi-Fi en estado: {action.upper()} (Valor: {status_val})")
    
    # RadioStatus_0 controla la banda de 2,4 GHz y RadioStatus_1 la de 5 GHz.
    payload = {
        "IF_ACTION": "Apply",
        "RadioStatus": "",
        "_InstID_0": "DEV.WIFI.RD1",
        "Band_0": "2.4GHz",
        "RadioStatus_0": status_val,
        "_InstID_1": "DEV.WIFI.RD2",
        "Band_1": "5GHz",
        "RadioStatus_1": status_val,
        "_InstID": "",
        "Band": "",
        "Btn_cancel_WlanBasicAdConf": "",
        "Btn_apply_WlanBasicAdConf": "",
        "_sessionTOKEN": new_token
    }
    
    target_url = f"{base_url}/common_page/Localnet_WlanBasicAd_OnOff_lua.lua"
    headers = {
        "X-Requested-With": "XMLHttpRequest",
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        "Origin": base_url,
        "Referer": base_url + "/"
    }
    
    try:
        r = session.post(target_url, data=payload, headers=headers)
    except requests.exceptions.RequestException as exc:
        if action == "off":
            print(
                "Sin confirmación: la orden de apagado ya fue enviada; "
                f"no se recibió respuesta: {exc}"
            )
            return True
        print(f"Falló la petición: {exc}")
        return False

    print(f"Orden de Wi-Fi {action.upper()} enviada. Respuesta: {r.text[:300]}")
    return True

def main():
    if len(sys.argv) < 3:
        print("Uso: python3 conmutar_zte_legacy.py <password> <on|off>")
        sys.exit(1)
        
    password = sys.argv[1]
    action = sys.argv[2].lower()
    
    if action not in ['on', 'off']:
        print("La acción debe ser 'on' u 'off'.")
        sys.exit(1)
        
    ip = "192.168.1.1"
    base_url = f"http://{ip}"
    username = "user" # Ajusta si el usuario del operador es distinto (por defecto user)
    
    s = requests.Session()
    
    if not zte_login(s, base_url, username, password):
        print("Fallo de autenticación. Comprueba la contraseña de admin.")
        return 1

    return 0 if toggle_wifi(s, base_url, action) else 1

if __name__ == "__main__":
    sys.exit(main())
