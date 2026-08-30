"""Pruebas del monitor sin capturas, servicios ni dependencias de la Raspberry."""

import importlib.util
import io
import json
import sys
import types
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import MagicMock, mock_open, patch

import pytest


CLIENTE = "02:00:00:00:00:01"
GATEWAY = "02:00:00:00:00:02"
OTRO_CLIENTE = "02:00:00:00:00:03"
IP_CLIENTE = "192.168.10.100"
IP_REMOTA = "203.0.113.10"


@pytest.fixture
def tui(monkeypatch):
    # Solo sustituimos las dependencias externas; ejecutamos el módulo real.
    scapy_all = types.ModuleType("scapy.all")
    for name in ("Ether", "IP", "TCP", "UDP", "ICMP", "DNS", "DHCP", "BOOTP", "ARP"):
        setattr(scapy_all, name, type(name, (), {}))
    scapy_all.sniff = MagicMock()
    scapy_all.conf = types.SimpleNamespace()
    scapy = types.ModuleType("scapy")
    scapy.all = scapy_all
    monkeypatch.setitem(sys.modules, "scapy", scapy)
    monkeypatch.setitem(sys.modules, "scapy.all", scapy_all)

    monkeypatch.setitem(sys.modules, "rich", types.ModuleType("rich"))
    for name in ("Live", "Table", "Panel", "Layout", "Console", "Text", "Align"):
        module = types.ModuleType(f"rich.{name.lower()}")
        setattr(module, name, MagicMock())
        monkeypatch.setitem(sys.modules, module.__name__, module)

    path = Path(__file__).resolve().parents[1] / "tui" / "tui.py"
    spec = importlib.util.spec_from_file_location("tui_under_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.network_stats["logs"].clear()
    return module


class Paquete:
    def __init__(self, tui, origen, destino, ip_origen=IP_CLIENTE, tamano=100):
        self.layers = {
            tui.Ether: types.SimpleNamespace(src=origen, dst=destino),
            tui.IP: types.SimpleNamespace(src=ip_origen),
            tui.TCP: types.SimpleNamespace(sport=443, dport=50000),
        }
        self.tamano = tamano

    def haslayer(self, layer):
        return layer in self.layers

    def __getitem__(self, layer):
        return self.layers[layer]

    def __len__(self):
        return self.tamano


@contextmanager
def interfaces_locales(tui, direcciones):
    """Simula /sys/class/net; None representa una interfaz que desaparece."""
    def abrir(ruta, **kwargs):
        direccion = direcciones[Path(ruta).parent.name]
        if direccion is None:
            raise FileNotFoundError(ruta)
        return io.StringIO(direccion + "\n")

    with (
        patch.object(tui.os, "listdir", return_value=list(direcciones)),
        patch.object(tui, "open", side_effect=abrir, create=True),
    ):
        yield


def sincronizar(tui, documento):
    with (
        patch.object(tui.os.path, "exists", return_value=True),
        patch.object(tui, "open", mock_open(read_data=json.dumps(documento)), create=True),
    ):
        tui.actualizar_desde_bbdd()


def registrar(tui, mac=CLIENTE, creada=True, ip=IP_CLIENTE):
    sincronizar(tui, {
        mac: {"ip_cliente": ip, "nombre_vlan": "v_prueba", "creada": creada},
    })


def test_lectura_local_normaliza_y_limpia_filas(tui):
    local = "02:00:00:00:00:ab"
    tui.network_stats["devices"][local] = {"status": "DESCONOCIDO"}
    with interfaces_locales(tui, {
        "v_prueba": local.upper(), "lo": "00:00:00:00:00:00", "borrada": None,
    }):
        tui.actualizar_macs_locales()
    assert tui.macs_locales == {local}
    assert local not in tui.network_stats["devices"]


def test_fallo_de_lectura_conserva_macs_conocidas(tui):
    tui.macs_locales.add(GATEWAY)
    with patch.object(tui.os, "listdir", side_effect=OSError):
        tui.actualizar_macs_locales()
    assert tui.macs_locales == {GATEWAY}


def test_macvlan_nueva_no_crea_fila_ni_alerta(tui):
    registrar(tui)
    with interfaces_locales(tui, {}):
        tui.actualizar_macs_locales()
    # La MACVLAN aparece después del refresco y antes de su primer paquete.
    with interfaces_locales(tui, {"v_prueba": GATEWAY}):
        tui.procesar_paquete_real(Paquete(tui, GATEWAY, CLIENTE, IP_REMOTA))
    assert set(tui.network_stats["devices"]) == {CLIENTE}
    assert tui.network_stats["devices"][CLIENTE]["pkts"] == 1
    assert tui.network_stats["devices"][CLIENTE]["ip"] == IP_CLIENTE
    assert tui.network_stats["logs"] == []


def test_cliente_suma_envio_y_recepcion_sin_duplicar_total(tui):
    registrar(tui)
    tui.macs_locales.add(GATEWAY)
    tui.procesar_paquete_real(Paquete(tui, CLIENTE, GATEWAY, tamano=100))
    tui.procesar_paquete_real(Paquete(tui, GATEWAY, CLIENTE, IP_REMOTA, tamano=200))
    dispositivo = tui.network_stats["devices"][CLIENTE]
    assert dispositivo["pkts"] == 2
    assert dispositivo["bytes"] == 300
    assert tui.network_stats["total_packets"] == 2
    assert tui.network_stats["protocols"]["HTTPS"] == 2
    assert set(tui.network_stats["devices"]) == {CLIENTE}


def test_entre_clientes_cuenta_para_ambos_y_una_vez_en_total(tui):
    sincronizar(tui, {CLIENTE: {}, OTRO_CLIENTE: {}})
    tui.procesar_paquete_real(Paquete(tui, CLIENTE, OTRO_CLIENTE))
    assert tui.network_stats["devices"][CLIENTE]["pkts"] == 1
    assert tui.network_stats["devices"][OTRO_CLIENTE]["pkts"] == 1
    assert tui.network_stats["total_packets"] == 1


def test_desconocido_real_se_muestra_y_alerta_solo_una_vez(tui):
    with interfaces_locales(tui, {"v_prueba": GATEWAY}):
        for _ in range(2):
            tui.procesar_paquete_real(Paquete(tui, CLIENTE, GATEWAY))
    dispositivo = tui.network_stats["devices"][CLIENTE]
    assert dispositivo["status"] == "DESCONOCIDO"
    assert dispositivo["iface"] == "sin_registrar"
    assert dispositivo["ip"] == IP_CLIENTE
    assert dispositivo["pkts"] == 2
    assert len(tui.network_stats["logs"]) == 1


@pytest.mark.parametrize("creada", [True, False])
def test_registro_no_depende_de_creada(tui, creada):
    registrar(tui, creada=creada)
    assert tui.network_stats["devices"][CLIENTE]["status"] == "REGISTRADO"


def test_bbdd_corrige_ip_sin_perder_contadores(tui):
    with interfaces_locales(tui, {}):
        tui.procesar_paquete_real(Paquete(tui, CLIENTE, GATEWAY, IP_REMOTA))
    registrar(tui)
    dispositivo = tui.network_stats["devices"][CLIENTE]
    assert dispositivo["status"] == "REGISTRADO"
    assert dispositivo["ip"] == IP_CLIENTE
    assert dispositivo["pkts"] == 1
    registrar(tui, ip="192.168.11.100")
    assert dispositivo["ip"] == "192.168.11.100"


def test_ip_registrada_no_se_sustituye_por_ip_del_paquete(tui):
    registrar(tui, ip="Pendiente...")
    tui.procesar_paquete_real(Paquete(tui, CLIENTE, GATEWAY, IP_REMOTA))
    assert tui.network_stats["devices"][CLIENTE]["ip"] == "Pendiente..."


def test_borrado_de_bbdd_pasa_a_desconocido(tui):
    registrar(tui)
    sincronizar(tui, {})
    dispositivo = tui.network_stats["devices"][CLIENTE]
    assert dispositivo["status"] == "DESCONOCIDO"
    assert dispositivo["iface"] == "sin_registrar"


def test_bbdd_no_reintroduce_mac_local(tui):
    tui.macs_locales.add(GATEWAY)
    registrar(tui, mac=GATEWAY)
    assert tui.network_stats["devices"] == {}


def test_tabla_muestra_registro_en_lugar_de_permisos(tui):
    registrar(tui)
    with interfaces_locales(tui, {}):
        tui.procesar_paquete_real(Paquete(tui, OTRO_CLIENTE, CLIENTE))
    tui.generar_tabla_dispositivos()
    columnas = [call.args[0] for call in tui.Table.return_value.add_column.call_args_list]
    etiquetas = [call.args[0] for call in tui.Text.call_args_list]
    assert "Registro" in columnas
    assert "Estado SDN" not in columnas
    assert etiquetas == ["REGISTRADO", "DESCONOCIDO"]


def test_eventos_usan_prefijos_de_texto(tui):
    tui.log_event("Captura iniciada.")
    tui.log_event("Dispositivo desconocido.", alert=True)
    assert tui.network_stats["logs"][0].endswith("INFO: Captura iniciada.")
    assert tui.network_stats["logs"][1].endswith("ALERTA: Dispositivo desconocido.")


def test_protocolos_sin_simbolos_decorativos(tui):
    tui.network_stats["protocols"]["HTTPS"] = 10
    tui.generar_panel_protocolos()
    tui.Table.return_value.add_row.assert_called_once_with("HTTPS", "10")


def test_metricas_sin_emoticonos(tui):
    archivos = [
        io.StringIO("0.50 0.40 0.30 1/100 1"),
        io.StringIO("MemTotal: 1000 kB\nMemFree: 100 kB\nMemAvailable: 800 kB\n"),
    ]
    with (
        patch.object(tui.platform, "system", return_value="Linux"),
        patch.object(tui, "open", side_effect=archivos, create=True),
    ):
        assert tui.obtener_estadisticas_sistema() == "Carga CPU: 0.50  |  RAM: 20.0%"
