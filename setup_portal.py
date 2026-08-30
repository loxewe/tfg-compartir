import os
from pathlib import Path
import signal
import subprocess
import sys
from flask import Flask, request, redirect, render_template_string


SETUP_MARKER = "/root/tfg/.setup_complete"
CAPTIVE_DNS_REDIRECT = "dhcp.@dnsmasq[0].address=/#/192.168.2.1"


def remove_captive_dns_redirect():
    """Retira la redirección DNS utilizada por el portal cautivo."""
    subprocess.run(
        ["uci", "-q", "del_list", CAPTIVE_DNS_REDIRECT],
        stderr=subprocess.DEVNULL,
    )


def cleanup_captive_dns():
    """Aplica la retirada de la redirección y recarga dnsmasq."""
    remove_captive_dns_redirect()
    subprocess.run(["uci", "commit", "dhcp"])
    subprocess.run(["/etc/init.d/dnsmasq", "restart"])


def mark_setup_complete():
    """Registra que la migración terminó correctamente."""
    marker = Path(SETUP_MARKER)
    temporary_marker = marker.with_name(f"{marker.name}.tmp")
    temporary_marker.write_text("completed\n", encoding="utf-8")
    os.replace(temporary_marker, marker)


def stop_portal(_signum, _frame):
    """Convierte la señal de parada en una salida limpia de Flask."""
    raise SystemExit(0)


def launch_detached(script, log_path, *args):
    """Lanza un proceso independiente de SSH, con registro privado."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0)
    with os.fdopen(os.open(log_path, flags, 0o600), "a") as log:
        if os.name == "posix":
            os.fchmod(log.fileno(), 0o600)
        return subprocess.Popen(
            [sys.executable, "-u", script, *args],
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )


def reset_router_state():
    print("Preparando la red para el portal de configuración...")
    # Detención del controlador anterior con las herramientas de BusyBox.
    subprocess.run("kill -9 $(ps | grep '[c]ontrolador_aut.py' | awk '{print $1}')", shell=True, stderr=subprocess.DEVNULL)
    # Las reglas anteriores no deben bloquear el acceso al portal.
    subprocess.run(
        ["nft", "delete", "table", "netdev", "tfg_l2"],
        stderr=subprocess.DEVNULL,
    )
    subprocess.run(
        ["nft", "delete", "table", "inet", "tfg_l3"],
        stderr=subprocess.DEVNULL,
    )
    # Activación del DHCP de configuración y la redirección DNS.
    subprocess.run(["uci", "set", "dhcp.wifi.ignore=0"])
    remove_captive_dns_redirect()
    subprocess.run(["uci", "add_list", CAPTIVE_DNS_REDIRECT])
    subprocess.run(["uci", "commit", "dhcp"])
    subprocess.run(["/etc/init.d/dnsmasq", "restart"])

app = Flask(__name__)

# Plantillas del portal.
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SDN Smart Home Setup</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #eef2f5; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
        .container { background: white; padding: 40px; border-radius: 12px; box-shadow: 0 8px 20px rgba(0,0,0,0.1); width: 100%; max-width: 400px; text-align: center; }
        h2 { color: #2c3e50; margin-bottom: 10px; }
        select, input, button { width: 100%; padding: 14px; margin: 10px 0; border: 1px solid #ccd1d9; border-radius: 6px; box-sizing: border-box; font-size: 16px; }
        input:focus, select:focus { outline: none; border-color: #3498db; }
        button { background-color: #3498db; color: white; border: none; cursor: pointer; font-weight: bold; font-size: 18px; transition: background 0.3s; margin-top: 20px;}
        button:hover { background-color: #2980b9; }
        p.info { font-size: 14px; color: #7f8c8d; margin-bottom: 25px; line-height: 1.5;}
        .brand { font-size: 12px; color: #bdc3c7; margin-top: 20px; }
    </style>
</head>
<body>
    <div class="container">
        <h2>Network Takeover</h2>
        <p class="info">Select your ISP router model and enter the administrator password to migrate devices to the SDN controller.</p>
        <form method="POST" action="/setup">
            <select name="router_brand" required>
                <option value="" disabled selected>Select Router Model...</option>
                <option value="glinet">GL.iNet</option>
                <option value="mercusys">Mercusys / TP-Link</option>
                <option value="xiaomi">Xiaomi MiWiFi</option>
                <option value="zte_h298a">ZTE H298A</option>
                <option value="zte_legacy">ZTE Legacy</option>
            </select>
            <input type="password" name="password" placeholder="Router Admin Password" required>
            <input type="text" name="ssid" placeholder="Original Wi-Fi Name (SSID)" required>
            <input type="password" name="wifi_password" placeholder="Original Wi-Fi Password" required>
            <button type="submit">Migrate Network</button>
        </form>
        <div class="brand">Raspberry Pi SDN Controller</div>
    </div>
</body>
</html>
"""

SUCCESS_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Migration Successful</title>
    <style>
        body { font-family: 'Segoe UI', sans-serif; background-color: #eef2f5; display: flex; justify-content: center; align-items: center; height: 100vh; text-align: center; margin: 0;}
        .container { background: white; padding: 40px; border-radius: 12px; box-shadow: 0 8px 20px rgba(0,0,0,0.1); max-width: 400px; }
        h2 { color: #27ae60; margin-top: 0;}
        p { color: #34495e; line-height: 1.5;}
        .loader { border: 4px solid #f3f3f3; border-top: 4px solid #27ae60; border-radius: 50%; width: 40px; height: 40px; animation: spin 2s linear infinite; margin: 20px auto; }
        @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
    </style>
</head>
<body>
    <div class="container">
        <h2>✅ Takeover Initiated!</h2>
        <p>The ISP Wi-Fi is being disabled. The SDN controller is now broadcasting the cloned network.</p>
        <div class="loader"></div>
        <p><small>Your devices will reconnect automatically. You may close this window.</small></p>
    </div>
</body>
</html>
"""


def shutdown_isp_router(script, password, ssid, wifi_password, brand):
    """Ejecuta el script del router y comprueba su código de salida."""
    if not script:
        print("No hay un script de apagado para el router seleccionado.")
        return False

    print(f"Ejecutando el script del router: {script}")
    if brand == "xiaomi":
        command = ["python3", script, password, wifi_password, ssid, "off"]
    else:
        command = ["python3", script, password, "off"]

    try:
        result = subprocess.run(command, check=False, timeout=60)
    except (OSError, subprocess.SubprocessError) as exc:
        print(f"No se pudo completar el apagado del router ISP: {exc}")
        return False

    if result.returncode != 0:
        print(
            "El router ISP no confirmó el apagado "
            f"(código {result.returncode}). "
            "Se mantiene activo el portal cautivo."
        )
        return False

    return True


def finalize_takeover(script, password, ssid, wifi_password, brand):
    import time

    if not shutdown_isp_router(script, password, ssid, wifi_password, brand):
        return

    print("El script del router ha terminado. Configurando OpenWrt...")
    # Retirada de la redirección DNS del portal.
    remove_captive_dns_redirect()
    # Desactivación del DHCP de configuración.
    subprocess.run(["uci", "set", "dhcp.wifi.ignore=1"])
    subprocess.run(["uci", "commit", "dhcp"])

    # Lectura del SSID y la clave actuales.
    try:
        orig_ssid = subprocess.check_output(
            ["uci", "-q", "get", "wireless.wifinet1.ssid"]
        ).decode().strip()
        orig_key = subprocess.check_output(
            ["uci", "-q", "get", "wireless.wifinet1.key"]
        ).decode().strip()
    except Exception:
        orig_ssid, orig_key = "Synthetic_SSID", "Synthetic_Password"

    # Configuración del SSID y la clave de la red original.
    print(f"Configurando la red Wi-Fi: {ssid}")
    subprocess.run(["uci", "set", f"wireless.wifinet1.ssid={ssid}"])
    subprocess.run(["uci", "set", "wireless.wifinet1.encryption=psk2"])
    subprocess.run(["uci", "set", f"wireless.wifinet1.key={wifi_password}"])

    # El aislamiento y el descubrimiento se controlan mediante nftables.
    subprocess.run(["uci", "set", "wireless.wifinet1.isolate=0"])
    subprocess.run(["uci", "set", "wireless.wifinet1.bridge_isolate=0"])

    subprocess.run(["uci", "commit", "wireless"])

    # Aplicación de los cambios de DHCP y DNS.
    subprocess.run(["/etc/init.d/dnsmasq", "restart"])

    # Recarga del Wi-Fi para aplicar los cambios y reconectar los clientes.
    print("Recargando el Wi-Fi para aplicar la configuración...")
    subprocess.run(["wifi", "reload"])

    # Inicio del controlador.
    print("Iniciando controlador SDN...")
    try:
        controller = launch_detached(
            "/root/tfg/controlador_aut.py",
            "/tmp/tfg-controller.log",
        )
    except OSError as exc:
        print(f"No se pudo lanzar el controlador: {exc}")
        return

    # Se comprueba que el proceso supera los errores inmediatos de arranque.
    time.sleep(2)
    exit_code = controller.poll()
    if exit_code is not None:
        print(
            "El controlador terminó durante el arranque "
            f"(código {exit_code})."
        )
        return

    # El marcador evita repetir el portal en los siguientes arranques.
    mark_setup_complete()

    # Inicio del servidor web de OpenWrt.
    print("Iniciando el panel de OpenWrt y cerrando el portal...")
    subprocess.run(["/etc/init.d/uhttpd", "start"])

    time.sleep(2)
    os._exit(0)


# Rutas del portal.

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def catch_all(path):
    """Redirige al formulario las peticiones recibidas por el portal."""
    return redirect("/setup", code=302)

@app.route('/setup', methods=['GET', 'POST'])
def setup():
    if request.method == 'GET':
        # Formulario de configuración.
        return render_template_string(HTML_TEMPLATE)
    
    elif request.method == 'POST':
        # Datos enviados desde el formulario.
        router_brand = request.form.get('router_brand')
        password = request.form.get('password')
        ssid = request.form.get('ssid')
        wifi_password = request.form.get('wifi_password')
        
        print(f"Configuración recibida para {router_brand}...")
        
        # Selección del script correspondiente al router.
        base_dir = "/root/tfg/Scripts_Finales"
        
        if router_brand == "glinet":
            script_path = os.path.join(base_dir, "GL_iNet/conmutar_glinet.py")
        elif router_brand == "mercusys":
            script_path = os.path.join(base_dir, "Mercusys_TPLink/conmutar_mercusys.py")
        elif router_brand == "xiaomi":
            script_path = os.path.join(base_dir, "Xiaomi_MiWiFi/conmutar_xiaomi.py")
        elif router_brand == "zte_h298a":
            script_path = os.path.join(base_dir, "ZTE_H298A/conmutar_zte_requests.py")
        elif router_brand == "zte_legacy":
            script_path = os.path.join(base_dir, "ZTE_Legacy/conmutar_zte_legacy.py")
        else:
            script_path = None
            
        import threading
        threading.Thread(
            target=finalize_takeover,
            args=(script_path, password, ssid, wifi_password, router_brand),
        ).start()
        
        # La respuesta se envía antes de que termine la migración.
        return render_template_string(SUCCESS_TEMPLATE)

def main():
    print("Deteniendo uHTTPd para liberar el puerto 80...")
    try:
        subprocess.run(["/etc/init.d/uhttpd", "stop"], check=True, timeout=10)
    except (OSError, subprocess.SubprocessError) as exc:
        print(f"No se pudo detener uHTTPd: {exc}")
        return 1

    previous_sigint = signal.signal(signal.SIGINT, stop_portal)
    previous_sigterm = signal.signal(signal.SIGTERM, stop_portal)
    try:
        reset_router_state()
        print("Iniciando el portal de configuración en el puerto 80...")
        app.run(host='0.0.0.0', port=80, debug=False, use_reloader=False)
    finally:
        cleanup_captive_dns()
        signal.signal(signal.SIGINT, previous_sigint)
        signal.signal(signal.SIGTERM, previous_sigterm)
    return 0


def launch_portal():
    if "--background" in sys.argv[1:]:
        return main()
    try:
        process = launch_detached(
            os.path.abspath(__file__), "/tmp/tfg-portal.log", "--background"
        )
    except OSError as exc:
        print(f"No se pudo lanzar el portal: {exc}")
        return 1
    print(f"Portal lanzado en segundo plano (PID {process.pid}).")
    print("Consulta el arranque y los errores en /tmp/tfg-portal.log")
    return 0


if __name__ == '__main__':
    raise SystemExit(launch_portal())
