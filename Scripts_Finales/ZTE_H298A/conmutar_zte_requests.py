import requests
import hashlib
from base64 import b64encode
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
import sys

def rsa_encrypt(data_str, pub_key_pem):
    """Encripta el hash con la clave pública RSA del router"""
    rsa_key = RSA.importKey(pub_key_pem)
    cipher = PKCS1_v1_5.new(rsa_key)
    encrypted = cipher.encrypt(data_str.encode('utf-8'))
    return b64encode(encrypted).decode('utf-8')

def main():
    if len(sys.argv) < 3:
        print("Uso: python conmutar_zte_requests.py <password> <on|off>")
        return 1
        
    pwd = sys.argv[1]
    action = sys.argv[2].lower()
    
    if action not in ["on", "off"]:
        print("Acción inválida. Usa 'on' o 'off'")
        return 1
        
    status_val = "1" if action == "on" else "0"
    base_url = "http://192.168.1.2"
    
    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Origin": base_url,
        "Referer": f"{base_url}/",
        "X-Requested-With": "XMLHttpRequest"
    })
    
    print("Cargando la página de inicio...")
    session.cookies.set("_TESTCOOKIESUPPORT", "1")
    session.get(f"{base_url}/")
    
    print("Obteniendo el token de sesión...")
    r1 = session.get(f"{base_url}/?_type=loginData&_tag=login_entry")
    sess_token = r1.json().get("sess_token")
        
    print("Obteniendo la semilla de autenticación...")
    r2 = session.get(f"{base_url}/?_type=loginData&_tag=login_token")
    seed = r2.text.replace("<ajax_response_xml_root>", "").replace("</ajax_response_xml_root>", "").strip()
    
    print("Calculando el hash de la contraseña...")
    sha256_pass = hashlib.sha256((pwd + seed).encode('utf-8')).hexdigest()
    
    print("Iniciando sesión...")
    login_payload = {
        "action": "login",
        "Username": "user",
        "Password": sha256_pass,
        "_sessionTOKEN": sess_token
    }
    
    r3 = session.post(f"{base_url}/?_type=loginData&_tag=login_entry", data=login_payload)
    json_resp = r3.json()
    new_sess_token = json_resp.get("sess_token")
    if not json_resp.get("login_need_refresh"):
        print(f"Error en el login: {json_resp.get('loginErrMsg')}")
        return 1
        
    print("Sesión iniciada. Token temporal:", new_sess_token)
    
    session.get(f"{base_url}/")
    
    
    print("Accediendo a los menús requeridos por el router...")
    import time
    ts = int(time.time() * 1000)
    
    # El router requiere visitar los menús antes de aceptar el cambio de Wi-Fi.
    # Sin estas peticiones previas puede responder con SessionTimeout.
    session.get(f"{base_url}/?_type=menuView&_tag=localNetStatus&Menu3Location=0&_={ts}")
    session.get(f"{base_url}/?_type=menuView&_tag=wlanBasic&Menu3Location=0&_={ts+1}")
    session.get(f"{base_url}/?_type=menuData&_tag=wlan_wlanbasiconoff_lua.lua&_={ts+2}")
    
    print("Actualizando el token de sesión...")
    final_sess_token = session.get(f"{base_url}/?_type=loginData&_tag=login_entry").json().get("sess_token")
    
    print(f"Enviando la orden de Wi-Fi {action.upper()}...")
    
    post_data_str = f"IF_ACTION=Apply&RadioStatus=&_InstID_0=DEV.WIFI.RD1&Band_0=2.4GHz&RadioStatus_0={status_val}&_InstID_1=DEV.WIFI.RD2&Band_1=5GHz&RadioStatus_1={status_val}&_InstID=&Band=&Btn_cancel_WlanBasicAdConf=&Btn_apply_WlanBasicAdConf=&_sessionTOKEN={final_sess_token}"
    
    payload_hash = hashlib.sha256(post_data_str.encode('utf-8')).hexdigest()
    
    pub_key = (
        "-----BEGIN PUBLIC KEY-----\n"
        "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAwlo/vZBnSJ2MyJ0dbNcw\n"
        "DvzPqBN+O/BPvLX93GIJVSZmquJHD9X6Xn6VYeM9mRKzjEbXPlv73Dj/gjjtNj9j\n"
        "Tq2QVyW2Sd4ZkY9e3h1ALCCCfkbjnmSqedyrcvXriTeW+J65jhBje6lTJbafmC5q\n"
        "bGiItjt0OeOkT+Vb4S7hYPSWIjeYYBh+7Y/fg25Rt2a+RgC8dahvJ3ttB1LHXADr\n"
        "oCm6q7G+lpbRAlpC8jjc0rZdS0c6HcBoYgzW8vxjj2fTuFy3CZZTrpPyTv/C8K6B\n"
        "hjTnjRe6ocgFVyQ0RIYfx2hxSJcuauR57OzfMzlgFQv3RAXguDZtuVUFLO2sAiwL\n"
        "ELph3Acfy9Eh58SHcswZvsOSXY0JNb0XeRM9gxpntLRfM6TB7f9hYtYTDw5oKdyN\n"
        "BY+nnEa/IpBUjndGDrSs3Z4BxRbYcJEwkKQZkvw/5TpQYbkD6sTRVSlZPaXSjeCl\n"
        "0hsLCttqwJqRZcjbWXrINBYFw8PYE14Xr9BCyPgqocdQh7FgvasVgG6u5mLR1PBZ\n"
        "o4EFF/LdY0yvMG5rl9egBk1XD/UMayhRtmSQEUzYt3eEWLBbqJB6MbVJ2ygcv5EL\n"
        "ReDY0SWXw1PIEbHeP51A/MyB6kwSgZwdoQW3JiaPnGHMaE0NqfAYPNiGJLMsmvT/\n"
        "rNUI/8iSCW+WvSzx9tByUxsCAwEAAQ==\n"
        "-----END PUBLIC KEY-----"
    )
    
    headers = {
        "Check": rsa_encrypt(payload_hash, pub_key),
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"
    }
    
    try:
        r4 = session.post(
            f"{base_url}/?_type=menuData&_tag=wlan_wlanbasiconoff_lua.lua",
            data=post_data_str,
            headers=headers,
        )
    except requests.exceptions.RequestException as exc:
        if action == "off":
            print(
                "Sin confirmación: la orden de apagado ya fue enviada; "
                f"no se recibió respuesta: {exc}"
            )
            return 0
        print(f"Falló la petición de cambio de Wi-Fi: {exc}")
        return 1

    print(f"Orden de Wi-Fi {action.upper()} enviada. Respuesta: {r4.text}")
        
    # Cierre de sesión tras enviar el cambio.
    session.post(f'{base_url}/?_type=loginData&_tag=logout_entry', data={'IF_LogOff': '1', '_sessionTOKEN': final_sess_token})
    print("Sesión cerrada.")
    return 0

if __name__ == "__main__":
    sys.exit(main())
