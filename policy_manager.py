import copy
import ipaddress
import json
import os
import re
import subprocess
import tempfile
import threading

from interfaces_creator import configurar_firewall_base


AP_INTERFACE = "phy0-ap0"
L2_TABLE_NAME = "tfg_l2"
L3_TABLE_NAME = "tfg_l3"
PEER_MARK = "0x100"
POLICY_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "policies.json"
)

DEFAULT_POLICY = {
    "internet": True,
    "inter_device": False,
    "mdns": True,
    "ssdp": True,
    "broadcast": "block",
}
_BOOLEAN_FIELDS = {"internet", "inter_device", "mdns", "ssdp"}
_BROADCAST_ACTIONS = {"allow", "block", "log"}
_MAC_RE = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")

_L2_SET_TYPES = {
    "client_macs": "ether_addr",
    "mac_ip_bindings": "ether_addr . ipv4_addr",
    "mac_arp_senders": "ether_addr . ether_addr",
    "arp_source_bindings": "ether_addr . ipv4_addr",
    "arp_targets": "ether_addr . ipv4_addr",
    "peer_allowed_macs": "ether_addr",
    "mdns_allowed_macs": "ether_addr",
    "ssdp_allowed_macs": "ether_addr",
    "discovery_allowed_macs": "ether_addr",
    "broadcast_allowed_macs": "ether_addr",
    "broadcast_logged_macs": "ether_addr",
}
_L3_SET_TYPES = {
    "client_ips": "ipv4_addr",
    "device_subnets": "ipv4_addr",
    "internet_blocked_ips": "ipv4_addr",
    "peer_allowed_ips": "ipv4_addr",
}


class PolicyConfigurationError(ValueError):
    pass


def _normalize_mac(mac):
    normalized = mac.lower()
    if not _MAC_RE.fullmatch(normalized):
        raise PolicyConfigurationError(f"Dirección MAC no válida: {mac!r}")
    return normalized




def _normalize_policy(policy, base=None):
    if not isinstance(policy, dict):
        raise PolicyConfigurationError("Cada política debe ser un objeto JSON.")
    normalized = dict(DEFAULT_POLICY if base is None else base)
    unknown = set(policy) - set(DEFAULT_POLICY)
    if unknown:
        raise PolicyConfigurationError(
            f"Campos de política desconocidos: {sorted(unknown)}"
        )
    for field in _BOOLEAN_FIELDS:
        if field in policy:
            if not isinstance(policy[field], bool):
                raise PolicyConfigurationError(f"{field} debe ser booleano.")
            normalized[field] = policy[field]
    if "broadcast" in policy:
        action = policy["broadcast"]
        if not isinstance(action, str) or action not in _BROADCAST_ACTIONS:
            raise PolicyConfigurationError(
                "broadcast debe ser 'allow', 'block' o 'log'."
            )
        normalized["broadcast"] = action
    return normalized


def _validate_assignment(mac, client_ip, gateway_ip):
    normalized_mac = _normalize_mac(mac)
    client = ipaddress.ip_address(client_ip)
    gateway = ipaddress.ip_address(gateway_ip)
    if client.version != 4 or gateway.version != 4:
        raise PolicyConfigurationError("Solo se admite direccionamiento IPv4.")
    if not client.is_private or not gateway.is_private:
        raise PolicyConfigurationError("Cliente y gateway deben usar IPv4 privada.")
    client_network = ipaddress.ip_network(f"{client}/24", strict=False)
    gateway_network = ipaddress.ip_network(f"{gateway}/24", strict=False)
    if client_network != gateway_network or client == gateway:
        raise PolicyConfigurationError(
            "Cliente y gateway deben ser distintos y pertenecer a la misma /24."
        )
    return normalized_mac, str(client), str(gateway), str(client_network)


def _set_declarations(set_types, interval_sets=()):
    lines = []
    for name, nft_type in set_types.items():
        flags = " flags interval;" if name in interval_sets else ""
        lines.append(f"    set {name} {{ type {nft_type};{flags} }}")
    return lines




def render_base_ruleset(
    l2_table=L2_TABLE_NAME,
    l3_table=L3_TABLE_NAME,
    interface=AP_INTERFACE,
    management_ip=None,
    management_router_ip=None,
):
    """Renderiza las reglas permanentes; la política vive en sets dinámicos."""
    management_rules = []
    if management_ip and management_router_ip:
        management_rules = [
            f"        ether type arp arp saddr ip {management_ip} "
            f"arp daddr ip {management_router_ip} counter accept",
            f"        ether type ip ip saddr {management_ip} counter accept",
        ]
    lines = [f"table netdev {l2_table} {{"]
    lines.extend(_set_declarations(_L2_SET_TYPES))
    lines.extend(
        [
            "    chain ingress {",
            (
                "        type filter hook ingress "
                f'device "{interface}" priority -500; policy accept;'
            ),
            "        ether type 0x888e counter accept",
            *management_rules,
            "        ether type ip udp sport 68 udp dport 67 counter accept",
            "        ether saddr != @client_macs counter drop",
            "        ether type ip udp sport 67 udp dport 68 counter drop",
            "        ether type ip ether saddr . ip saddr != @mac_ip_bindings counter drop",
            (
                "        ether type arp ether saddr . arp saddr ether "
                "!= @mac_arp_senders counter drop"
            ),
            (
                "        ether type arp ether saddr . arp saddr ip "
                "!= @arp_source_bindings counter drop"
            ),
            "        ether type arp ether saddr . arp daddr ip != @arp_targets counter drop",
            "        ether type arp counter accept",
            "        ether saddr != @peer_allowed_macs ether daddr @client_macs counter drop",
            (
                "        ether saddr @mdns_allowed_macs ether type ip "
                "ip daddr 224.0.0.251 udp dport 5353 counter accept"
            ),
            (
                "        ether saddr @ssdp_allowed_macs ether type ip "
                "ip daddr 239.255.255.250 udp dport 1900 counter accept"
            ),
            (
                "        ether saddr @discovery_allowed_macs ether type ip "
                "ip protocol igmp counter accept"
            ),
            (
                "        ether saddr @broadcast_logged_macs "
                "ether daddr ff:ff:ff:ff:ff:ff limit rate 10/second "
                'log prefix "TFG-L2-BCAST " counter accept'
            ),
            (
                "        ether saddr @broadcast_allowed_macs "
                "ether daddr ff:ff:ff:ff:ff:ff counter accept"
            ),
            "        ether type ip6 counter drop",
            "        ether type ip ip daddr 224.0.0.0/4 counter drop",
            "        ether daddr ff:ff:ff:ff:ff:ff counter drop",
            (
                "        ether daddr & 01:00:00:00:00:00 == "
                "01:00:00:00:00:00 counter drop"
            ),
            "    }",
            "}",
            "",
            f"table inet {l3_table} {{",
        ]
    )
    lines.extend(_set_declarations(_L3_SET_TYPES, interval_sets={"device_subnets"}))
    lines.extend(
        [
            "    chain forward {",
            "        type filter hook forward priority -50; policy accept;",
            (
                "        ip saddr @peer_allowed_ips ip daddr @device_subnets "
                f"meta mark set {PEER_MARK}"
            ),
            (
                "        ip saddr @client_ips ip daddr @device_subnets "
                "ip saddr != @peer_allowed_ips counter drop"
            ),
            (
                "        ip saddr @internet_blocked_ips "
                "ip daddr != @device_subnets counter drop"
            ),
            "    }",
            "}",
            "",
        ]
    )
    return "\n".join(lines)


def _desired_sets(active_devices):
    desired = {
        ("netdev", L2_TABLE_NAME, name): set() for name in _L2_SET_TYPES
    }
    desired.update(
        {("inet", L3_TABLE_NAME, name): set() for name in _L3_SET_TYPES}
    )
    for mac, device in active_devices.items():
        client = device["client_ip"]
        gateway = device["gateway_ip"]
        subnet = device["subnet"]
        policy = device["policy"]
        desired[("netdev", L2_TABLE_NAME, "client_macs")].add(mac)
        desired[("netdev", L2_TABLE_NAME, "mac_ip_bindings")].add(
            f"{mac} . {client}"
        )
        desired[("netdev", L2_TABLE_NAME, "mac_arp_senders")].add(
            f"{mac} . {mac}"
        )
        arp_sources = desired[("netdev", L2_TABLE_NAME, "arp_source_bindings")]
        arp_sources.update({f"{mac} . 0.0.0.0", f"{mac} . {client}"})
        arp_targets = desired[("netdev", L2_TABLE_NAME, "arp_targets")]
        arp_targets.update({f"{mac} . {client}", f"{mac} . {gateway}"})
        if policy["inter_device"]:
            desired[("netdev", L2_TABLE_NAME, "peer_allowed_macs")].add(mac)
            desired[("inet", L3_TABLE_NAME, "peer_allowed_ips")].add(client)
        if policy["mdns"]:
            desired[("netdev", L2_TABLE_NAME, "mdns_allowed_macs")].add(mac)
        if policy["ssdp"]:
            desired[("netdev", L2_TABLE_NAME, "ssdp_allowed_macs")].add(mac)
        if policy["mdns"] or policy["ssdp"]:
            desired[("netdev", L2_TABLE_NAME, "discovery_allowed_macs")].add(mac)
        if policy["broadcast"] == "allow":
            desired[("netdev", L2_TABLE_NAME, "broadcast_allowed_macs")].add(mac)
        elif policy["broadcast"] == "log":
            desired[("netdev", L2_TABLE_NAME, "broadcast_logged_macs")].add(mac)
        desired[("inet", L3_TABLE_NAME, "client_ips")].add(client)
        desired[("inet", L3_TABLE_NAME, "device_subnets")].add(subnet)
        if not policy["internet"]:
            desired[("inet", L3_TABLE_NAME, "internet_blocked_ips")].add(client)
    return desired


def render_set_update(previous_active, next_active):
    """Genera una única transacción nft con solamente los elementos cambiados."""
    previous = _desired_sets(previous_active)
    desired = _desired_sets(next_active)
    lines = []
    for family, table, set_name in sorted(desired):
        removed = sorted(
            previous[(family, table, set_name)] - desired[(family, table, set_name)]
        )
        added = sorted(
            desired[(family, table, set_name)] - previous[(family, table, set_name)]
        )
        if removed:
            lines.append(
                f"delete element {family} {table} {set_name} "
                f"{{ {', '.join(removed)} }}"
            )
        if added:
            lines.append(
                f"add element {family} {table} {set_name} "
                f"{{ {', '.join(added)} }}"
            )
    return "\n".join(lines) + ("\n" if lines else "")


class PolicyManager:
    def __init__(self, policy_path=POLICY_PATH):
        self.policy_path = policy_path
        self._lock = threading.RLock()
        self._active = {}
        self._document = self._load_document()
        self._reload_error = None

    def _load_document(self, required=False):
        if not required and not os.path.exists(self.policy_path):
            return {
                "default": dict(DEFAULT_POLICY),
                "management_ip": None,
                "management_router_ip": None,
                "devices": {},
            }
        try:
            with open(self.policy_path, "r", encoding="utf-8") as stream:
                raw = json.load(stream)
        except (OSError, ValueError) as error:
            raise PolicyConfigurationError(
                f"No se pudo cargar {self.policy_path}: {error}"
            ) from error
        if not isinstance(raw, dict):
            raise PolicyConfigurationError("La raíz de policies.json debe ser un objeto.")
        default = _normalize_policy(raw.get("default", {}))
        management_ip = raw.get("management_ip")
        management_router_ip = raw.get("management_router_ip")
        if bool(management_ip) != bool(management_router_ip):
            raise PolicyConfigurationError(
                "management_ip y management_router_ip deben definirse juntos."
            )
        raw_devices = raw.get("devices", {})
        if not isinstance(raw_devices, dict):
            raise PolicyConfigurationError("devices debe ser un objeto indexado por MAC.")
        devices = {}
        for mac, policy in raw_devices.items():
            normalized_mac = _normalize_mac(mac)
            if not isinstance(policy, dict):
                raise PolicyConfigurationError(
                    f"La política de {normalized_mac} debe ser un objeto."
                )
            devices[normalized_mac] = _normalize_policy(policy, base=default)
        return {
            "default": default,
            "management_ip": management_ip,
            "management_router_ip": management_router_ip,
            "devices": devices,
        }

    def _save_document(self):
        directory = os.path.dirname(self.policy_path) or "."
        fd, temporary_path = tempfile.mkstemp(dir=directory, text=True)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                json.dump(self._document, stream, indent=4, sort_keys=True)
                stream.write("\n")
            os.replace(temporary_path, self.policy_path)
        except OSError:
            try:
                os.unlink(temporary_path)
            except OSError:
                pass
            raise

    def get_policy(self, mac):
        normalized_mac = _normalize_mac(mac)
        with self._lock:
            policy = self._document["devices"].get(
                normalized_mac, self._document["default"]
            )
            return dict(policy)

    def reload_policies(self):
        """Recarga permisos sin reiniciar servicios ni reescribir el archivo."""
        with self._lock:
            try:
                document = self._load_document(required=True)
                if any(
                    document[key] != self._document[key]
                    for key in ("management_ip", "management_router_ip")
                ):
                    raise PolicyConfigurationError(
                        "Cambiar las IP de gestión requiere reiniciar el controlador."
                    )
            except PolicyConfigurationError as error:
                detail = str(error)
                if detail != self._reload_error:
                    print(f"Recarga rechazada; se mantienen las políticas: {detail}")
                self._reload_error = detail
                return False

            self._reload_error = None
            if document == self._document:
                return True

            desired = copy.deepcopy(self._active)
            for mac, device in desired.items():
                device["policy"] = dict(
                    document["devices"].get(mac, document["default"])
                )
            transaction = render_set_update(self._active, desired)
            # El estado en memoria solo cambia si nft aplica la transacción.
            if transaction and self._run_nft(["nft", "-f", "-"], transaction) is None:
                print("Recarga no aplicada; se reintentará sin cambiar las políticas.")
                return False
            self._active = desired
            self._document = document
        print("policies.json recargado: políticas aplicadas sin reiniciar.")
        return True

    @staticmethod
    def _run_nft(command, ruleset=None, allow_fail=False):
        try:
            result = subprocess.run(
                command,
                input=ruleset,
                capture_output=True,
                text=True,
                check=False,
            )
        except OSError as error:
            if not allow_fail:
                print(f"No se pudo ejecutar nft: {error}")
            return None
        if result.returncode != 0:
            if not allow_fail:
                detail = result.stderr.strip() or "error no especificado"
                print(f"nftables rechazó la política: {detail}")
            return None
        return result

    def _tables_available_locked(self):
        for family, table in (("netdev", L2_TABLE_NAME), ("inet", L3_TABLE_NAME)):
            if self._run_nft(
                ["nft", "list", "table", family, table], allow_fail=True
            ) is None:
                return False
        return True

    def _install_base_locked(self):
        check_ruleset = render_base_ruleset(
            l2_table=f"{L2_TABLE_NAME}_check",
            l3_table=f"{L3_TABLE_NAME}_check",
            management_ip=self._document["management_ip"],
            management_router_ip=self._document["management_router_ip"],
        )
        if self._run_nft(["nft", "-c", "-f", "-"], check_ruleset) is None:
            return False
        self._run_nft(
            ["nft", "delete", "table", "netdev", L2_TABLE_NAME],
            allow_fail=True,
        )
        self._run_nft(
            ["nft", "delete", "table", "inet", L3_TABLE_NAME],
            allow_fail=True,
        )
        ruleset = render_base_ruleset(
            management_ip=self._document["management_ip"],
            management_router_ip=self._document["management_router_ip"],
        )
        if self._run_nft(["nft", "-f", "-"], ruleset) is None:
            return False
        initial_sets = render_set_update({}, self._active)
        return not initial_sets or self._run_nft(
            ["nft", "-f", "-"], initial_sets
        ) is not None

    def _apply_transition_locked(self, previous_active, next_active):
        if not self._tables_available_locked():
            self._active = copy.deepcopy(previous_active)
            if not self._install_base_locked():
                return False
        transaction = render_set_update(previous_active, next_active)
        if transaction and self._run_nft(["nft", "-f", "-"], transaction) is None:
            return False
        self._active = copy.deepcopy(next_active)
        return True

    def initialize(self):
        with self._lock:
            self._active.clear()
            if not configurar_firewall_base():
                return False
            if not self._install_base_locked():
                return False
        print("Gestor de políticas L2/L3 iniciado.")
        if self._document["management_ip"]:
            print("Excepción IP de gestión instalada.")
        return True

    def register_device(self, mac, client_ip, gateway_ip):
        try:
            normalized_mac, client, gateway, subnet = _validate_assignment(
                mac, client_ip, gateway_ip
            )
        except PolicyConfigurationError as error:
            print(f"{error}")
            return False
        with self._lock:
            policy = self.get_policy(normalized_mac)
            previous = copy.deepcopy(self._active)
            desired = copy.deepcopy(previous)
            desired[normalized_mac] = {
                "client_ip": client,
                "gateway_ip": gateway,
                "subnet": subnet,
                "policy": policy,
            }
            if not self._apply_transition_locked(previous, desired):
                return False
        print(f"Políticas L2/L3 actualizadas para {normalized_mac}.")
        return True

    def remove_device(self, mac):
        try:
            normalized_mac = _normalize_mac(mac)
        except PolicyConfigurationError as error:
            print(f"{error}")
            return False
        with self._lock:
            previous = copy.deepcopy(self._active)
            desired = copy.deepcopy(previous)
            desired.pop(normalized_mac, None)
            if not self._apply_transition_locked(previous, desired):
                return False
        print(f"Elementos de política retirados para {normalized_mac}.")
        return True

    def update_policy(self, mac, **changes):
        try:
            normalized_mac = _normalize_mac(mac)
        except PolicyConfigurationError as error:
            print(f"{error}")
            return False
        with self._lock:
            try:
                current = self.get_policy(normalized_mac)
                updated = _normalize_policy(changes, base=current)
            except PolicyConfigurationError as error:
                print(f"{error}")
                return False
            previous_document = copy.deepcopy(self._document)
            previous_active = copy.deepcopy(self._active)
            desired_active = copy.deepcopy(previous_active)
            self._document["devices"][normalized_mac] = updated
            if normalized_mac in desired_active:
                desired_active[normalized_mac]["policy"] = dict(updated)
                if not self._apply_transition_locked(previous_active, desired_active):
                    self._document = previous_document
                    return False
            try:
                self._save_document()
            except OSError as error:
                print(f"No se pudo guardar la política: {error}")
                self._document = previous_document
                if normalized_mac in previous_active:
                    self._apply_transition_locked(desired_active, previous_active)
                return False
        return True


_MANAGER = PolicyManager()


def configurar_politicas_base():
    return _MANAGER.initialize()


def registrar_dispositivo(mac, client_ip, gateway_ip):
    return _MANAGER.register_device(mac, client_ip, gateway_ip)


def eliminar_dispositivo(mac):
    return _MANAGER.remove_device(mac)


def actualizar_politica(mac, **changes):
    return _MANAGER.update_policy(mac, **changes)


def recargar_politicas():
    return _MANAGER.reload_policies()
