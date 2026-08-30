import importlib
import sys
import types
from unittest.mock import Mock, patch

import pytest


class DHCP:
    pass


class BOOTP:
    pass


class Ether:
    pass


class IP:
    pass


class UDP:
    pass


class FakePacket:
    def __init__(self, mac, requested_ip):
        self.layers = {
            DHCP: types.SimpleNamespace(
                options=[
                    ("message-type", 3),
                    ("requested_addr", requested_ip),
                ]
            ),
            BOOTP: types.SimpleNamespace(op=1, ciaddr="0.0.0.0"),
            Ether: types.SimpleNamespace(src=mac),
        }

    def __contains__(self, layer):
        return layer in self.layers

    def __getitem__(self, layer):
        return self.layers[layer]


def import_controller_without_scapy():
    fake_all = types.ModuleType("scapy.all")
    fake_all.__all__ = [
        "DHCP",
        "BOOTP",
        "Ether",
        "IP",
        "UDP",
        "sendp",
    ]
    fake_all.DHCP = DHCP
    fake_all.BOOTP = BOOTP
    fake_all.Ether = Ether
    fake_all.IP = IP
    fake_all.UDP = UDP
    fake_all.sendp = lambda *args, **kwargs: None
    fake_scapy = types.ModuleType("scapy")
    fake_scapy.all = fake_all

    sys.modules.pop("controlador_aut", None)
    with patch.dict(
        sys.modules,
        {"scapy": fake_scapy, "scapy.all": fake_all},
    ):
        return importlib.import_module("controlador_aut")


def test_request_after_restart_starts_provisioning_and_sends_deferred_ack():
    controller = import_controller_without_scapy()
    mac = "02:00:00:00:00:01"
    device = {
        "nombre_vlan": "v_020000000001",
        "ip_gateway": "192.168.10.1",
        "ip_cliente": "192.168.10.100",
        "creada": False,
    }
    first_request = FakePacket(mac, device["ip_cliente"])
    latest_request = FakePacket(mac, device["ip_cliente"])
    created_threads = []
    sent_packets = []

    class FakeThread:
        def __init__(self, target, args, daemon):
            self.target = target
            self.args = args
            self.daemon = daemon
            created_threads.append(self)

        def start(self):
            return None

    controller.DISPOSITIVOS = {mac: device}
    controller.en_creacion.clear()
    controller.pending_requests.clear()

    with (
        patch.object(controller.threading, "Thread", FakeThread),
        patch.object(controller, "crear_macvlan", return_value=True),
        patch.object(controller, "registrar_dispositivo", return_value=True),
        patch.object(controller, "guardar_bbdd"),
        patch.object(controller, "craft_dhcp_response", return_value="ACK"),
        patch.object(
            controller,
            "sendp",
            side_effect=lambda packet, **kwargs: sent_packets.append(packet),
        ),
    ):
        controller.dhcp(first_request)
        controller.dhcp(latest_request)

        assert len(created_threads) == 1
        assert controller.pending_requests[mac]["pkt"] is latest_request
        assert mac in controller.en_creacion

        created_threads[0].target(*created_threads[0].args)

    assert controller.DISPOSITIVOS[mac]["creada"] is True
    assert mac not in controller.en_creacion
    assert mac not in controller.pending_requests
    assert sent_packets == ["ACK"]


def test_invalid_requested_address_does_not_start_provisioning():
    controller = import_controller_without_scapy()
    mac = "02:00:00:00:00:01"
    controller.DISPOSITIVOS = {
        mac: {
            "nombre_vlan": "v_020000000001",
            "ip_gateway": "192.168.10.1",
            "ip_cliente": "192.168.10.100",
            "creada": False,
        }
    }
    controller.en_creacion.clear()
    controller.pending_requests.clear()
    packet = FakePacket(mac, "192.168.99.100")

    with (
        patch.object(controller, "iniciar_aprovisionamiento") as start,
        patch.object(controller, "craft_dhcp_response", return_value="NAK"),
        patch.object(controller, "sendp"),
    ):
        controller.dhcp(packet)

    start.assert_not_called()
    assert mac not in controller.pending_requests


def test_policy_watcher_retries_under_network_lock_until_stopped():
    controller = import_controller_without_scapy()
    stop_event = Mock()
    stop_event.wait.side_effect = [False, False, True]

    def reload():
        assert controller.os_lock.locked()
        return False

    with patch.object(controller, "recargar_politicas", side_effect=reload) as reload:
        controller.vigilar_politicas(stop_event)

    assert reload.call_count == 2
    assert not controller.os_lock.locked()


def test_main_stops_policy_watcher_when_capture_fails():
    controller = import_controller_without_scapy()
    stop_event = Mock()
    with (
        patch.object(controller, "configurar_politicas_base", return_value=True),
        patch.object(controller.threading, "Event", return_value=stop_event),
        patch.object(controller.threading, "Thread") as thread,
        patch.object(controller, "sniff", create=True, side_effect=RuntimeError("capture")),
        pytest.raises(RuntimeError, match="capture"),
    ):
        controller.main()

    thread.assert_called_once_with(
        target=controller.vigilar_politicas, args=(stop_event,), daemon=True
    )
    thread.return_value.start.assert_called_once()
    stop_event.set.assert_called_once()


def test_main_does_not_start_watcher_if_base_policies_fail():
    controller = import_controller_without_scapy()
    with (
        patch.object(controller, "configurar_politicas_base", return_value=False),
        patch.object(controller.threading, "Thread") as thread,
        patch.object(controller, "sniff", create=True) as sniff,
        pytest.raises(SystemExit),
    ):
        controller.main()
    thread.assert_not_called()
    sniff.assert_not_called()
