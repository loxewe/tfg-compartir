import json
import os
import threading
import tempfile
import time
import re
from scapy.all import *
from interfaces_creator import (
    crear_macvlan,
    eliminar_macvlan,
)
from policy_manager import (
    configurar_politicas_base,
    eliminar_dispositivo,
    recargar_politicas,
    registrar_dispositivo,
)

INTERFACE = "phy0-ap0"
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "database.json")

# Sincronización del inventario y de las operaciones de red.
db_lock = threading.RLock()
os_lock = threading.Lock()
en_creacion = set()
pending_requests = {}
PENDING_REQUEST_TTL = 60
POLICY_RELOAD_INTERVAL = 2

try:
    with open(DB_PATH, 'r') as f:
        DISPOSITIVOS = json.load(f)
        for mac in DISPOSITIVOS:
            DISPOSITIVOS[mac]["creada"] = False
except FileNotFoundError:
    print("AVISO: No se encuentra database.json, se creará uno nuevo.")
    DISPOSITIVOS = {}

def guardar_bbdd():
    # La llamada debe mantener adquirido db_lock.
    fd, temp_path = tempfile.mkstemp(dir=os.path.dirname(DB_PATH), text=True)
    with os.fdopen(fd, 'w') as f:
        json.dump(DISPOSITIVOS, f, indent=4)
    os.replace(temp_path, DB_PATH)

def es_mac_valida(mac):
    return re.match(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$", mac) is not None

def nuevo_dispositivo(mac): 
    nombre_vlan = f"v_{mac.replace(':', '')}"

    with db_lock:
        subredes_usadas = set(int(d["ip_gateway"].split(".")[2]) for d in DISPOSITIVOS.values())
        siguiente_red = 10
        while siguiente_red in subredes_usadas:
            siguiente_red += 1
        
        if siguiente_red > 254:
            print(f"No quedan subredes disponibles para {mac}")
            return False

        ip_gateway = f"192.168.{siguiente_red}.1"
        ip_cliente = f"192.168.{siguiente_red}.100"
        DISPOSITIVOS[mac] = {
            "nombre_vlan": nombre_vlan,
            "ip_gateway": ip_gateway,
            "ip_cliente": ip_cliente,
            "creada": False
        }
        guardar_bbdd()
    
    print(f"Nuevo dispositivo registrado: {mac} en subred {siguiente_red}")
    return True


def craft_dhcp_response(pkt, msg_type_str, device_info):
    ether = Ether(dst=pkt[Ether].src, src=get_if_hwaddr(INTERFACE))
    ip = IP(src=device_info["ip_gateway"], dst="255.255.255.255")
    udp = UDP(sport=67, dport=68)
    
    yiaddr_val = "0.0.0.0" if msg_type_str == "nak" else device_info["ip_cliente"]
    
    bootp = BOOTP(op=2, yiaddr=yiaddr_val, siaddr=device_info["ip_gateway"],
            chaddr=pkt[BOOTP].chaddr, xid=pkt[BOOTP].xid)
    dhcp = DHCP(options=[
        ("message-type", msg_type_str),
        ("server_id", device_info["ip_gateway"]),
        ("subnet_mask", "255.255.255.0"),
        ("router", device_info["ip_gateway"]),
        ("name_server", "8.8.8.8"),
        ("lease_time", 3600),
        "end"
    ])
    return ether / ip / udp / bootp / dhcp


def aprovisionar_dispositivo(mac, device):
    """Crea la red y completa cualquier DHCP Request que estaba esperando."""
    provisioning_started = time.monotonic()
    try:
        print(f"Creando MACVLAN en segundo plano para {mac}...")
        with os_lock:
            exito = crear_macvlan(
                device["nombre_vlan"],
                device["ip_gateway"],
            )
            if exito:
                exito = registrar_dispositivo(
                    mac,
                    device["ip_cliente"],
                    device["ip_gateway"],
                )
            if not exito:
                eliminar_macvlan(device["nombre_vlan"])

        if not exito:
            print(f"Falló la creación de MACVLAN para {mac}")
            with db_lock:
                pending_requests.pop(mac, None)
            return

        request_pkt = None
        with db_lock:
            DISPOSITIVOS[mac]["creada"] = True
            guardar_bbdd()

            req_data = pending_requests.pop(mac, None)
            if req_data is not None:
                request_age = time.monotonic() - req_data["time"]
                if request_age < PENDING_REQUEST_TTL:
                    request_pkt = req_data["pkt"]
                else:
                    print(f"La petición DHCP pendiente ha caducado para {mac}")

        elapsed = time.monotonic() - provisioning_started
        print(
            f"Red MACVLAN y políticas listas para {mac} "
            f"en {elapsed:.2f} s"
        )
        if request_pkt is not None:
            print(f"Enviando el ACK de la petición pendiente para {mac}")
            ack_pkt = craft_dhcp_response(request_pkt, "ack", device)
            sendp(ack_pkt, iface=INTERFACE, verbose=False)
    finally:
        with db_lock:
            en_creacion.discard(mac)


def iniciar_aprovisionamiento(mac):
    """Reserva y lanza una sola reconstrucción para la MAC indicada."""
    with db_lock:
        device = DISPOSITIVOS.get(mac)
        if device is None or device["creada"] or mac in en_creacion:
            return False
        en_creacion.add(mac)
        device_snapshot = dict(device)

    try:
        threading.Thread(
            target=aprovisionar_dispositivo,
            args=(mac, device_snapshot),
            daemon=True,
        ).start()
    except RuntimeError as error:
        with db_lock:
            en_creacion.discard(mac)
        print(f"No se pudo iniciar el aprovisionamiento de {mac}: {error}")
        return False
    return True


def dhcp(pkt):
    if DHCP not in pkt or BOOTP not in pkt or Ether not in pkt:
        return

    # Solo se procesan mensajes DHCP enviados por clientes.
    if pkt[BOOTP].op != 1:
        return

    mac_origen = pkt[Ether].src.lower()
    if not es_mac_valida(mac_origen):
        return
        
    with db_lock:
        if mac_origen not in DISPOSITIVOS:
            if not nuevo_dispositivo(mac_origen):
                return # No se continúa si no hay una asignación disponible.

        device = DISPOSITIVOS[mac_origen]

    msg_type = None
    requested_ip = None
    for opt in pkt[DHCP].options:
        if isinstance(opt, tuple):
            if opt[0] == "message-type":
                msg_type = opt[1]
            elif opt[0] == "requested_addr":
                requested_ip = opt[1]

    if msg_type == 1: # Discover
        print(f"DHCP Discover de {mac_origen}.")
        # La oferta se envía antes de iniciar el aprovisionamiento.
        offer_pkt = craft_dhcp_response(pkt, "offer", device)
        sendp(offer_pkt, iface=INTERFACE, verbose=False)

        iniciar_aprovisionamiento(mac_origen)

    elif msg_type == 3: # Request
        ciaddr = pkt[BOOTP].ciaddr
        client_asking_ip = requested_ip if requested_ip else ciaddr

        if (
            client_asking_ip
            and client_asking_ip != "0.0.0.0"
            and client_asking_ip != device["ip_cliente"]
        ):
            print(f"DHCP NAK: {mac_origen} solicitó IP incorrecta ({client_asking_ip}).")
            nak_pkt = craft_dhcp_response(pkt, "nak", device)
            sendp(nak_pkt, iface=INTERFACE, verbose=False)
        else:
            with db_lock:
                creada = device["creada"]
                if not creada:
                    pending_requests[mac_origen] = {
                        "pkt": pkt,
                        "time": time.monotonic(),
                    }

            # El ACK espera a que la red del dispositivo esté preparada.
            if creada:
                print(f"DHCP ACK: confirmación de IP ({device['ip_cliente']}) para {mac_origen}")
                ack_pkt = craft_dhcp_response(pkt, "ack", device)
                sendp(ack_pkt, iface=INTERFACE, verbose=False)
                with db_lock:
                    pending_requests.pop(mac_origen, None)
            else:
                print(f"DHCP Request de {mac_origen} pendiente hasta que termine la creación de la MACVLAN.")
                iniciar_aprovisionamiento(mac_origen)

    elif msg_type == 7: # Release
        print(f"DHCP Release: {mac_origen} ha enviado una liberación de su dirección IP.")
        with db_lock:
            DISPOSITIVOS[mac_origen]["creada"] = False
            pending_requests.pop(mac_origen, None)
            guardar_bbdd()

        def bg_eliminar():
            with os_lock:
                eliminar_dispositivo(mac_origen)
                eliminar_macvlan(device["nombre_vlan"])

        threading.Thread(target=bg_eliminar, daemon=True).start()

def vigilar_politicas(stop_event):
    """Comprueba el JSON sin competir con el aprovisionamiento de la red."""
    while not stop_event.wait(POLICY_RELOAD_INTERVAL):
        with os_lock:
            recargar_politicas()


def main():
    if not configurar_politicas_base():
        raise SystemExit("No se pudo configurar el gestor de políticas Layer 2/3.")

    stop_event = threading.Event()
    threading.Thread(
        target=vigilar_politicas, args=(stop_event,), daemon=True
    ).start()
    print("Recarga automática de policies.json cada 2 segundos.")
    print("Esperando peticiones DHCP...")
    try:
        sniff(iface=INTERFACE, filter="udp and (port 67 or 68)", prn=dhcp, store=0)
    finally:
        stop_event.set()


if __name__ == "__main__":
    main()
