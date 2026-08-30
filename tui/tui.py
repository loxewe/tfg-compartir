import threading
import time
import json
import os
import platform
from datetime import datetime
from collections import Counter
from scapy.all import sniff, Ether, IP, TCP, UDP, ICMP, DNS, DHCP, BOOTP, ARP, conf
from rich.live import Live
from rich.table import Table
from rich.panel import Panel
from rich.layout import Layout
from rich.console import Console
from rich.text import Text
from rich.align import Align

# Configuración de Scapy para OpenWrt.
conf.noresolve = True

# Ubicación de la base de datos.
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if os.path.exists(os.path.join(BASE_DIR, "database.json")):
    ARCHIVO_BBDD = os.path.join(BASE_DIR, "database.json")
elif os.path.exists(os.path.join(BASE_DIR, "..", "database.json")):
    ARCHIVO_BBDD = os.path.abspath(os.path.join(BASE_DIR, "..", "database.json"))
else:
    ARCHIVO_BBDD = "database.json"

# Datos compartidos entre la captura y la interfaz.
stats_lock = threading.RLock()
RUTA_INTERFACES = "/sys/class/net"
macs_locales = set()
network_stats = {
    "devices": {},  
    "protocols": Counter(),
    "logs": [
        "[INFO] Monitor de red iniciado.",
        f"[INFO] Base de datos: {ARCHIVO_BBDD}"
    ],
    "total_packets": 0
}

# Historial de paquetes para el gráfico.
history_packets = [0] * 40
last_total_packets = 0

# Registro de eventos.
def log_event(msg, alert=False):
    t_now = datetime.now().strftime("%H:%M:%S")
    prefix = "ALERTA" if alert else "INFO"
    with stats_lock:
        network_stats["logs"].append(f"[{t_now}] {prefix}: {msg}")
        if len(network_stats["logs"]) > 20:
            network_stats["logs"].pop(0)

def actualizar_macs_locales():
    """Excluye las MAC de la Raspberry, incluidas sus MACVLAN."""
    try:
        interfaces = os.listdir(RUTA_INTERFACES)
    except OSError:
        return

    encontradas = set()
    for interfaz in interfaces:
        ruta = os.path.join(RUTA_INTERFACES, interfaz, "address")
        try:
            with open(ruta, encoding="ascii") as archivo:
                mac = archivo.read().strip().lower()
        except OSError:
            continue
        if mac and mac != "00:00:00:00:00:00":
            encontradas.add(mac)

    with stats_lock:
        macs_locales.update(encontradas)
        for mac in macs_locales:
            network_stats["devices"].pop(mac, None)


# Lectura del inventario de dispositivos.
def actualizar_desde_bbdd():
    if not os.path.exists(ARCHIVO_BBDD):
        return
    try:
        with open(ARCHIVO_BBDD, "r") as f:
            bbdd = json.load(f)
            with stats_lock:
                registradas = {mac.lower() for mac in bbdd}
                for mac, dispositivo in network_stats["devices"].items():
                    if mac not in registradas:
                        dispositivo["status"] = "DESCONOCIDO"
                        dispositivo["iface"] = "sin_registrar"

                for mac, info in bbdd.items():
                    mac_l = mac.lower()
                    if mac_l in macs_locales:
                        continue
                    iface_val = info.get("nombre_vlan", "macvlan_auto")
                    ip_val = info.get("ip_cliente", "Pendiente...")
                    # Registro en BBDD, no permisos ni conectividad real.
                    estado = "REGISTRADO"
                    
                    if mac_l not in network_stats["devices"]:
                        network_stats["devices"][mac_l] = {
                            "ip": ip_val,
                            "iface": iface_val,
                            "status": estado,
                            "bytes": 0,
                            "pkts": 0
                        }
                    else:
                        network_stats["devices"][mac_l]["iface"] = iface_val
                        network_stats["devices"][mac_l]["status"] = estado
                        network_stats["devices"][mac_l]["ip"] = ip_val
    except Exception:
        pass

# Procesamiento de paquetes capturados.
def procesar_paquete_real(pkt):
    pkt_len = len(pkt)
    
    with stats_lock:
        network_stats["total_packets"] += 1

        # Clasificación por protocolo y puerto.
        if pkt.haslayer(DNS):
            network_stats["protocols"]["DNS"] += 1
        elif pkt.haslayer(DHCP) or pkt.haslayer(BOOTP):
            network_stats["protocols"]["DHCP"] += 1
            if pkt.haslayer(Ether):
                log_event(f"Actividad DHCP para MAC {pkt[Ether].src}")
        elif pkt.haslayer(ICMP):
            network_stats["protocols"]["ICMP"] += 1
        elif pkt.haslayer(TCP):
            dport = pkt[TCP].dport
            sport = pkt[TCP].sport
            if dport == 443 or sport == 443:
                network_stats["protocols"]["HTTPS"] += 1
            elif dport == 80 or sport == 80:
                network_stats["protocols"]["HTTP"] += 1
            elif dport in [22, 23] or sport in [22, 23]:
                network_stats["protocols"]["SSH/Telnet"] += 1
                if pkt.haslayer(IP):
                    # Registrar solo el SYN inicial de cada conexión.
                    if pkt[TCP].flags == 'S':
                        log_event(f"Intento de conexión SSH/Telnet desde {pkt[IP].src}, puerto {dport}.", alert=True)
            else:
                network_stats["protocols"]["TCP Otros"] += 1
        elif pkt.haslayer(UDP):
            network_stats["protocols"]["UDP Otros"] += 1
        elif pkt.haslayer(ARP):
            network_stats["protocols"]["ARP"] += 1

        # Tráfico enviado y recibido por cliente, sin contar las MAC locales.
        # Entre dos clientes, el paquete cuenta para ambos, pero solo una vez
        # en total_packets. Por eso la suma de filas puede superar el total.
        if pkt.haslayer(Ether):
            mac_src = pkt[Ether].src.lower()
            mac_dst = pkt[Ether].dst.lower()

            if mac_src not in network_stats["devices"] and mac_src not in macs_locales:
                # Puede ser una MACVLAN creada desde el último refresco.
                # Comprobar antes de generar una alerta de desconocido.
                actualizar_macs_locales()
            
            if (
                mac_src not in macs_locales
                and not mac_src.startswith(("ff:ff", "33:33", "01:00"))
            ):
                if mac_src not in network_stats["devices"]:
                    ip_val = pkt[IP].src if pkt.haslayer(IP) else "Pendiente..."
                    network_stats["devices"][mac_src] = {
                        "ip": ip_val,
                        "iface": "sin_registrar",
                        "status": "DESCONOCIDO",
                        "bytes": 0,
                        "pkts": 0
                    }
                    log_event(f"Dispositivo no registrado detectado [{mac_src}].", alert=True)

                network_stats["devices"][mac_src]["bytes"] += pkt_len
                network_stats["devices"][mac_src]["pkts"] += 1
                if (
                    pkt.haslayer(IP)
                    and network_stats["devices"][mac_src]["status"] == "DESCONOCIDO"
                    and network_stats["devices"][mac_src]["ip"] == "Pendiente..."
                ):
                    network_stats["devices"][mac_src]["ip"] = pkt[IP].src
                    
            if mac_dst not in macs_locales and mac_dst in network_stats["devices"]:
                network_stats["devices"][mac_dst]["bytes"] += pkt_len
                network_stats["devices"][mac_dst]["pkts"] += 1

def background_sniffer():
    interfaces_to_try = ["phy0-ap0", "eth0", "br-lan", None]
    while True:
        captured = False
        for iface in interfaces_to_try:
            try:
                iface_desc = iface if iface else "interfaz predeterminada"
                log_event(f"Iniciando captura en {iface_desc}...")
                if iface:
                    sniff(iface=iface, prn=procesar_paquete_real, store=0)
                else:
                    sniff(prn=procesar_paquete_real, store=0)
                captured = True
                break
            except Exception as e:
                log_event(f"No se pudo capturar en {iface if iface else 'default'}: {str(e)}", alert=True)
                time.sleep(1)
        if not captured:
            time.sleep(5)

# Métricas del sistema.
def obtener_estadisticas_sistema():
    # Leer carga del sistema en Linux sin paquetes extra
    if platform.system() != "Linux":
        return "Carga CPU: N/A | RAM: N/A"
    
    try:
        with open('/proc/loadavg', 'r') as f:
            load = f.read().split()[0]
        
        with open('/proc/meminfo', 'r') as f:
            lines = f.readlines()
            total = int(lines[0].split()[1])
            free = int(lines[2].split()[1])
            mem_pct = 100 - (free / total * 100)
            
        return f"Carga CPU: {load}  |  RAM: {mem_pct:.1f}%"
    except:
        return "Error al leer las métricas del sistema"

# Paneles de la interfaz.

def actualizar_sparkline():
    global last_total_packets, history_packets
    with stats_lock:
        current_total = network_stats["total_packets"]
        diff = current_total - last_total_packets
        last_total_packets = current_total
        
        history_packets.append(diff)
        if len(history_packets) > 40:
            history_packets.pop(0)

def generar_panel_grafico():
    ticks = "  ▂▃▄▅▆▇█"
    m = max(history_packets) if max(history_packets) > 0 else 1
    
    spark = ""
    for val in history_packets:
        idx = int((val / m) * 8)
        spark += ticks[idx]
        
    texto_grafico = Text(f"{spark}", style="bold magenta")
    texto_info = Text(f"\nPaquetes por segundo (Max: {m} p/s)", style="dim white")
    
    content = Align.center(texto_grafico + texto_info, vertical="middle")
    return Panel(content, title="[bold white]Tráfico en tiempo real[/bold white]", border_style="magenta")

def generar_tabla_dispositivos():
    table = Table(expand=True, border_style="cyan", row_styles=["", "dim"])
    table.add_column("MAC", style="bold white", width=18)
    table.add_column("IP", style="green", width=15)
    table.add_column("Interfaz virtual", style="blue", width=16)
    table.add_column("Registro", justify="center", width=14)
    table.add_column("Tráfico", justify="right", style="magenta", width=12)
    table.add_column("Paquetes", justify="right", style="yellow", width=10)

    devices_copy = dict(network_stats["devices"])
    
    # Ordenar por paquetes descendente para ver los más activos
    sorted_devices = sorted(devices_copy.items(), key=lambda x: x[1]['pkts'], reverse=True)
    
    for mac, data in sorted_devices:
        status = data["status"]
        if status == "REGISTRADO":
            status_txt = Text("REGISTRADO", style="bold green")
        else:
            status_txt = Text("DESCONOCIDO", style="bold red")

        # Formato de tráfico (KB o MB)
        kb = data['bytes'] / 1024
        if kb > 1024:
            trafico = f"{kb/1024:.1f} MB"
        else:
            trafico = f"{kb:.1f} KB"
            
        table.add_row(mac, str(data["ip"]), data["iface"], status_txt, trafico, str(data["pkts"]))
    
    return Panel(table, title="[bold white]Dispositivos[/bold white]", border_style="cyan")

def generar_panel_protocolos():
    table = Table(expand=True, show_header=False, box=None)
    table.add_column("Proto", style="bold cyan")
    table.add_column("Count", style="white", justify="right")
    
    protocols_copy = Counter(network_stats["protocols"])
    for proto, count in protocols_copy.most_common(7):
        table.add_row(proto, f"{count:,}")
        
    return Panel(table, title="[bold white]Protocolos[/bold white]", border_style="blue")

def generar_panel_logs():
    log_text = Text()
    logs_copy = list(network_stats["logs"][-7:])
    for log_msg in logs_copy:
        if "ALERTA" in log_msg or "Fallo" in log_msg or "ERROR" in log_msg:
            log_text.append(log_msg + "\n", style="bold red")
        elif "INFO" in log_msg:
            log_text.append(log_msg + "\n", style="cyan")
        else:
            log_text.append(log_msg + "\n", style="dim white")
            
    return Panel(log_text, title="[bold white]Eventos[/bold white]", border_style="green")

def construir_layout_principal():
    layout = Layout()
    layout.split_column(
        Layout(name="header", size=3),
        Layout(name="dashboard_top", size=7),
        Layout(name="body", ratio=1),
        Layout(name="footer", size=9)
    )
    
    layout["dashboard_top"].split_row(
        Layout(name="sparkline", ratio=2),
        Layout(name="side_stats", ratio=1)
    )
    
    with stats_lock:
        sys_stats = obtener_estadisticas_sistema()
        title_text = f" [bold cyan]Monitor de red[/bold cyan] | [white]Paquetes capturados: [bold yellow]{network_stats['total_packets']:,}[/bold yellow][/white] | {sys_stats} "
        
        layout["header"].update(Panel(title_text, style="bold white", border_style="blue"))
        layout["sparkline"].update(generar_panel_grafico())
        layout["side_stats"].update(generar_panel_protocolos())
        layout["body"].update(generar_tabla_dispositivos())
        layout["footer"].update(generar_panel_logs())
        
    return layout

# Ejecución principal.
if __name__ == "__main__":
    console = Console()
    
    actualizar_macs_locales()
    actualizar_desde_bbdd()
    
    t = threading.Thread(target=background_sniffer, daemon=True)
    t.start()
    
    console.clear()
    console.print("[yellow]Iniciando monitor de red...[/yellow]")
    time.sleep(1)
    
    try:
        with Live(construir_layout_principal(), refresh_per_second=4, screen=True) as live:
            while True:
                actualizar_macs_locales()
                actualizar_desde_bbdd()
                actualizar_sparkline()
                live.update(construir_layout_principal())
                time.sleep(1) # Refresco cada segundo para el sparkline y la BBDD
    except KeyboardInterrupt:
        console.print("\n[bold green]Monitor detenido.[/bold green]")
