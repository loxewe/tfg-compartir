import requests
import json
import base64
import os
import random
import string
import urllib.parse
import hashlib

def rsa_encrypt_chunk(text_chunk, n_hex, e_hex="010001"):
    N = int(n_hex, 16)
    E = int(e_hex, 16)
    k = (N.bit_length() + 7) // 8
    text_bytes = text_chunk.encode("utf-8")
    ps_len = k - 3 - len(text_bytes)
    ps = bytearray()
    while len(ps) < ps_len:
        r = os.urandom(1)[0]
        if r != 0:
            ps.append(r)
    padded = b"\x00\x02" + bytes(ps) + b"\x00" + text_bytes
    m = int.from_bytes(padded, "big")
    c = pow(m, E, N)
    hex_str = format(c, "x")
    if len(hex_str) < 2 * k:
        hex_str = "0" * (2 * k - len(hex_str)) + hex_str
    return hex_str

def get_rsa_signature(raw_str, n_hex, e_hex="010001"):
    chunks = [raw_str[i : i + 53] for i in range(0, len(raw_str), 53)]
    return "".join(rsa_encrypt_chunk(chk, n_hex, e_hex) for chk in chunks).lower()

def aes_encrypt(text, key_str, iv_str):
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad
    cipher = AES.new(key_str.encode("utf-8"), AES.MODE_CBC, iv_str.encode("utf-8"))
    padded = pad(text.encode("utf-8"), AES.block_size)
    return base64.b64encode(cipher.encrypt(padded)).decode("utf-8")

def do_login(password_str):
    base_url = "http://192.168.0.1"
    s = requests.Session()

    c_val = "".join(random.choices("0123456789abcdef", k=32))
    c_val = "".join(random.choices("0123456789abcdef", k=32))
    s.cookies.set("sysauth", c_val)
    
    s.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36",
        "Accept": "application/json, text/javascript, */*; q=0.01",
        "Accept-Encoding": "gzip, deflate",
        "Accept-Language": "es-ES,es;q=0.5",
        "Connection": "keep-alive",
        "Host": "mwlogin.net",
        "Origin": "http://mwlogin.net",
        "Referer": "http://mwlogin.net/webpages/index.html?t=254c026b",
        "X-Requested-With": "XMLHttpRequest",
    })

    print("Obteniendo las claves del router...")
    r_keys = s.post(f"{base_url}/cgi-bin/luci/;stok=/login?form=keys", data="operation=read", headers={"Content-Type": "application/x-www-form-urlencoded"})
    j_keys = r_keys.json()["data"]
    nk, ek = j_keys["password"][:2]
    
    pwd_rsa = get_rsa_signature(password_str, nk, ek)

    print("Obteniendo los datos de autenticación...")
    r_auth = s.post(f"{base_url}/cgi-bin/luci/;stok=/login?form=auth", data="operation=read", headers={"Content-Type": "application/x-www-form-urlencoded"})
    j_auth = r_auth.json()["data"]
    seq = j_auth["seq"]
    na, ea = j_auth["key"][:2]

    import time
    ts = str(int(time.time() * 1000))
    key = (ts + str(int(random.random() * 1e9)))[:16]
    iv = (ts + str(int(random.random() * 1e9)))[:16]
    
    payload = f"password={urllib.parse.quote(pwd_rsa)}&operation=login"
    crypted_data = aes_encrypt(payload, key, iv)
    
    h_val = hashlib.md5(f"admin{password_str}".encode("utf-8")).hexdigest()
    
    req_seq = seq + len(crypted_data)
    sig = get_rsa_signature(f"k={key}&i={iv}&h={h_val}&s={req_seq}", na, ea)
    
    body = f"sign={urllib.parse.quote(sig, safe='')}&data={urllib.parse.quote(crypted_data, safe='')}"
    
    print("Iniciando sesión...")
    r_log = s.post(f"{base_url}/cgi-bin/luci/;stok=/login?form=login", data=body, headers={"Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"})
    
    print("Respuesta:", r_log.text)
    
    # Descifrado de la respuesta del router.
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import unpad
    try:
        resp_json = r_log.json()
        enc_resp = resp_json['data']
        cipher_dec = AES.new(key.encode("utf-8"), AES.MODE_CBC, iv.encode("utf-8"))
        decrypted = unpad(cipher_dec.decrypt(base64.b64decode(enc_resp)), AES.block_size).decode("utf-8")
        print("Respuesta descifrada:", decrypted)
        
        
        data_inner = json.loads(decrypted)['data']
        stok = data_inner['stok']
        print("Token de sesión:", stok)
        return s, stok, key, iv, h_val, seq, na, ea
    except Exception as e:
        print("No se pudo descifrar o interpretar la respuesta:", e)
        return None, None, None, None, None, None, None, None

import sys

def main():
    if len(sys.argv) < 3:
        print("Uso: python3 conmutar_mercusys.py <password> <on|off>")
        sys.exit(1)
        
    password = sys.argv[1]
    action = sys.argv[2].lower()
    
    if action not in ['on', 'off']:
        print("La acción debe ser 'on' u 'off'.")
        sys.exit(1)

    session, stok, key, iv, h_val, seq, na, ea = do_login(password)
    if not stok:
        print("No se pudo iniciar sesión.")
        sys.exit(1)
        
    print(f"\nCambiando el estado del Wi-Fi a {action}...")
    
    def tp_request(s, stok, path, payload, key, iv, h_val, seq, na, ea, timeout=None):
        crypted_data = aes_encrypt(payload, key, iv)
        req_seq = seq + len(crypted_data)
        sig = get_rsa_signature(f"h={h_val}&s={req_seq}", na, ea)
        body = f"sign={urllib.parse.quote(sig, safe='')}&data={urllib.parse.quote(crypted_data, safe='')}"
        r = s.post(f"http://192.168.0.1/cgi-bin/luci/;stok={stok}{path}", data=body, headers={"Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"}, timeout=timeout)
        
        try:
            import base64
            from Crypto.Cipher import AES
            from Crypto.Util.Padding import unpad
            import json
            resp_json = r.json()
            enc_resp = resp_json['data']
            cipher_dec = AES.new(key.encode("utf-8"), AES.MODE_CBC, iv.encode("utf-8"))
            decrypted = unpad(cipher_dec.decrypt(base64.b64decode(enc_resp)), AES.block_size).decode("utf-8")
            return json.loads(decrypted)
        except Exception as e:
            print("No se pudo descifrar o interpretar la respuesta:", e)
            return None

    path = "/admin/wireless?form=wireless_2g&form=wireless_5g"
    
    if action == 'off':
        payload = "operation=write_spf&wireless_2g_enable=off&wireless_2g_disabled_all=on&wireless_2g_transmitPowerDisable=&wireless_2g_hwmode=bgn&wireless_2g_htmode=auto&wireless_2g_channel=auto&wireless_2g_txpower=high&wireless_5g_enable=off&wireless_5g_disabled_all=on&wireless_5g_transmitPowerDisable=&wireless_5g_hwmode=anacax_5&wireless_5g_htmode=80&wireless_5g_channel=auto&wireless_5g_txpower=high&wireless_5g_mu_mimo=on"
    else:
        payload = "operation=write_spf&wireless_2g_enable=on&wireless_2g_disabled_all=off&wireless_2g_transmitPowerDisable=&wireless_2g_hwmode=bgn&wireless_2g_htmode=auto&wireless_2g_channel=auto&wireless_2g_txpower=high&wireless_5g_enable=on&wireless_5g_disabled_all=off&wireless_5g_transmitPowerDisable=&wireless_5g_hwmode=anacax_5&wireless_5g_htmode=80&wireless_5g_channel=auto&wireless_5g_txpower=high&wireless_5g_mu_mimo=on"
        
    try:
        resp = tp_request(session, stok, path, payload, key, iv, h_val, seq, na, ea)
    except requests.exceptions.RequestException as exc:
        if action == "off":
            print(
                "Sin confirmación: la orden de apagado ya fue enviada; "
                f"no se recibió respuesta: {exc}"
            )
            return 0
        print(f"No se pudo cambiar el estado del Wi-Fi a {action}: {exc}")
        return 1

    print(f"Orden de Wi-Fi {action} enviada. Respuesta: {resp}")
    print("Cerrando sesión...")
    try:
        logout_resp = tp_request(
            session, stok, "/admin/system?form=logout", "",
            key, iv, h_val, seq, na, ea, timeout=3,
        )
        if isinstance(logout_resp, dict) and logout_resp.get("success") is True:
            print("Sesión cerrada.")
        else:
            print("El router no ha confirmado el cierre de sesión.")
    except requests.exceptions.RequestException:
        print("No se ha podido confirmar el cierre de sesión por falta de respuesta.")
    return 0

if __name__ == "__main__":
    sys.exit(main())
