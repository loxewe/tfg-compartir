import ipaddress
import re
import subprocess


PARENT_INTERFACE = "phy0-ap0"
DEVICE_ZONE_SECTION = "tfg_devices"
DEVICE_ZONE_NAME = "tfg_devices"
WAN_ZONE_NAME = "wan"
PEER_POLICY_MARK = "0x100/0x100"

_INTERFACE_NAME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9_]{0,14}$")


def _run(command, allow_fail=False, capture_output=False):
    """Ejecuta un comando sin shell y devuelve su resultado."""
    result = subprocess.run(
        command,
        capture_output=capture_output,
        text=capture_output,
        check=False,
    )
    if result.returncode != 0 and not allow_fail:
        print(f"Error al ejecutar: {' '.join(command)}")
        return None
    return result


def _validar_interfaz(nombre_interfaz):
    if not _INTERFACE_NAME_RE.fullmatch(nombre_interfaz):
        raise ValueError(f"Nombre de interfaz no válido: {nombre_interfaz!r}")


def _validar_gateway(ip_gateway):
    gateway = ipaddress.ip_address(ip_gateway)
    if gateway.version != 4 or not gateway.is_private:
        raise ValueError(f"Gateway IPv4 privado no válido: {ip_gateway!r}")


def _buscar_seccion_zona(nombre_zona):
    """Obtiene la sección UCI asociada al nombre lógico de una zona."""
    result = _run(
        ["uci", "-q", "show", "firewall"],
        capture_output=True,
    )
    if result is None:
        return None

    tipos = set()
    nombres = {}
    for line in result.stdout.splitlines():
        type_match = re.fullmatch(r"firewall\.(.+)=zone", line)
        if type_match:
            tipos.add(type_match.group(1))
            continue

        name_match = re.fullmatch(
            r"firewall\.(.+)\.name=(?:'([^']+)'|\"([^\"]+)\"|(.+))",
            line,
        )
        if name_match:
            nombres[name_match.group(1)] = next(
                value for value in name_match.groups()[1:] if value is not None
            )

    for section in tipos:
        if nombres.get(section) == nombre_zona:
            return section
    return None


def configurar_firewall_base(nombre_zona_wan=WAN_ZONE_NAME):
    """Configura forwarding IPv4, aislamiento entre clientes y NAT hacia WAN."""
    wan_section = _buscar_seccion_zona(nombre_zona_wan)
    if wan_section is None:
        print(f"No se encontró la zona WAN '{nombre_zona_wan}'.")
        return False

    commands = [
        (["sysctl", "-w", "net.ipv4.ip_forward=1"], False),
        (["uci", "-q", "delete", f"firewall.{DEVICE_ZONE_SECTION}"], True),
        (["uci", "set", f"firewall.{DEVICE_ZONE_SECTION}=zone"], False),
        (["uci", "set", f"firewall.{DEVICE_ZONE_SECTION}.name={DEVICE_ZONE_NAME}"], False),
        (["uci", "set", f"firewall.{DEVICE_ZONE_SECTION}.input=REJECT"], False),
        (["uci", "set", f"firewall.{DEVICE_ZONE_SECTION}.output=ACCEPT"], False),
        (["uci", "set", f"firewall.{DEVICE_ZONE_SECTION}.forward=REJECT"], False),
        (["uci", "set", f"firewall.{DEVICE_ZONE_SECTION}.family=ipv4"], False),
        (["uci", "-q", "delete", "firewall.tfg_devices_wan"], True),
        (["uci", "set", "firewall.tfg_devices_wan=forwarding"], False),
        (["uci", "set", f"firewall.tfg_devices_wan.src={DEVICE_ZONE_NAME}"], False),
        (["uci", "set", f"firewall.tfg_devices_wan.dest={nombre_zona_wan}"], False),
        (["uci", "set", "firewall.tfg_devices_wan.family=ipv4"], False),
        (["uci", "-q", "delete", "firewall.tfg_allow_dhcp"], True),
        (["uci", "set", "firewall.tfg_allow_dhcp=rule"], False),
        (["uci", "set", "firewall.tfg_allow_dhcp.name=Allow-TFG-DHCP"], False),
        (["uci", "set", f"firewall.tfg_allow_dhcp.src={DEVICE_ZONE_NAME}"], False),
        (["uci", "set", "firewall.tfg_allow_dhcp.proto=udp"], False),
        (["uci", "set", "firewall.tfg_allow_dhcp.dest_port=67"], False),
        (["uci", "set", "firewall.tfg_allow_dhcp.family=ipv4"], False),
        (["uci", "set", "firewall.tfg_allow_dhcp.target=ACCEPT"], False),
        (["uci", "-q", "delete", "firewall.tfg_allow_marked_peers"], True),
        (["uci", "set", "firewall.tfg_allow_marked_peers=rule"], False),
        (
            [
                "uci",
                "set",
                "firewall.tfg_allow_marked_peers.name=Allow-TFG-Policy-Peers",
            ],
            False,
        ),
        (
            ["uci", "set", f"firewall.tfg_allow_marked_peers.src={DEVICE_ZONE_NAME}"],
            False,
        ),
        (
            ["uci", "set", f"firewall.tfg_allow_marked_peers.dest={DEVICE_ZONE_NAME}"],
            False,
        ),
        (["uci", "set", "firewall.tfg_allow_marked_peers.proto=all"], False),
        (["uci", "set", "firewall.tfg_allow_marked_peers.family=ipv4"], False),
        (
            ["uci", "set", f"firewall.tfg_allow_marked_peers.mark={PEER_POLICY_MARK}"],
            False,
        ),
        (["uci", "set", "firewall.tfg_allow_marked_peers.target=ACCEPT"], False),
        (["uci", "set", f"firewall.{wan_section}.masq=1"], False),
        (["uci", "commit", "firewall"], False),
        (["/etc/init.d/firewall", "reload"], False),
    ]

    for command, allow_fail in commands:
        if _run(command, allow_fail=allow_fail) is None and not allow_fail:
            _run(["uci", "revert", "firewall"], allow_fail=True)
            return False

    print("Firewall L3 listo: dispositivos aislados con salida únicamente a WAN.")
    return True


def eliminar_macvlan(nombre_vlan):
    """Elimina de forma idempotente una MACVLAN y su configuración UCI."""
    try:
        _validar_interfaz(nombre_vlan)
    except ValueError as error:
        print(f"{error}")
        return False

    commands = [
        ["ifdown", nombre_vlan],
        ["uci", "-q", "del_list", f"firewall.{DEVICE_ZONE_SECTION}.network={nombre_vlan}"],
        ["uci", "-q", "delete", f"network.{nombre_vlan}"],
        ["uci", "commit", "network"],
        ["uci", "commit", "firewall"],
        ["/etc/init.d/firewall", "reload"],
        ["ip", "link", "delete", nombre_vlan],
    ]
    for command in commands:
        _run(command, allow_fail=True)

    print(f"Infraestructura {nombre_vlan} eliminada.")
    return True


def crear_macvlan(nombre_vlan, ip_gateway):
    """Crea una red por dispositivo y la incorpora a la zona L3 aislada."""
    try:
        _validar_interfaz(nombre_vlan)
        _validar_gateway(ip_gateway)
    except ValueError as error:
        print(f"{error}")
        return False

    print(f"Creando infraestructura {nombre_vlan}...")
    _run(["ip", "link", "delete", nombre_vlan], allow_fail=True)
    _run(["uci", "-q", "delete", f"network.{nombre_vlan}"], allow_fail=True)
    _run(
        [
            "uci",
            "-q",
            "del_list",
            f"firewall.{DEVICE_ZONE_SECTION}.network={nombre_vlan}",
        ],
        allow_fail=True,
    )

    commands = [
        [
            "ip",
            "link",
            "add",
            "link",
            PARENT_INTERFACE,
            "name",
            nombre_vlan,
            "type",
            "macvlan",
            "mode",
            "bridge",
        ],
        ["ip", "link", "set", nombre_vlan, "up"],
        ["uci", "set", f"network.{nombre_vlan}=interface"],
        ["uci", "set", f"network.{nombre_vlan}.device={nombre_vlan}"],
        ["uci", "set", f"network.{nombre_vlan}.proto=static"],
        ["uci", "set", f"network.{nombre_vlan}.ipaddr={ip_gateway}"],
        ["uci", "set", f"network.{nombre_vlan}.netmask=255.255.255.0"],
        [
            "uci",
            "add_list",
            f"firewall.{DEVICE_ZONE_SECTION}.network={nombre_vlan}",
        ],
        ["uci", "commit", "network"],
        ["uci", "commit", "firewall"],
        ["ifup", nombre_vlan],
        ["/etc/init.d/firewall", "reload"],
    ]

    for command in commands:
        if _run(command) is None:
            print(f"Falló la creación de {nombre_vlan}; iniciando limpieza.")
            eliminar_macvlan(nombre_vlan)
            return False

    print(f"Red {nombre_vlan} activa y aislada a nivel IP.")
    return True
