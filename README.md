# Plataforma TFG para microsegmentación en OpenWrt

Este proyecto convierte una Raspberry Pi en el punto de control de una red doméstica. La Raspberry recibe las peticiones DHCP, asigna una subred aislada a cada dispositivo y aplica las reglas de comunicación entre dispositivos, acceso a Internet y descubrimiento de servicios.

El código está pensado para ejecutarse en una Raspberry Pi con OpenWrt. Los scripts de los routers se utilizan durante la incorporación inicial para apagar o encender el Wi-Fi del router del operador y dejar a la Raspberry como equipo principal de la red.

## Estructura del proyecto

En la raíz se encuentran los componentes principales:

- `controlador_aut.py` es el proceso principal. Escucha las peticiones DHCP, registra los dispositivos nuevos, inicia su aprovisionamiento y mantiene actualizadas las políticas.
- `interfaces_creator.py` crea y elimina las interfaces MACVLAN, configura sus direcciones y las incorpora al firewall de OpenWrt.
- `policy_manager.py` genera las reglas de `nftables` y actualiza los permisos de cada dispositivo sin reiniciar el controlador.
- `setup_portal.py` sirve el portal inicial para introducir los datos del router y de la red antes de entregar el control a la Raspberry.
- `database.json` contiene las asignaciones de dispositivos, VLAN y direcciones IP. En esta copia está vacío para empezar una instalación nueva.
- `policies.json` contiene la política general y las excepciones por dispositivo.
- `POLITICAS.md` explica cómo modificar las reglas y comprobar que se han aplicado.
- `openwrt/tfg` es el servicio de arranque de OpenWrt y decide si inicia el portal o el controlador.

La carpeta `Scripts_Finales` contiene las integraciones con los routers probados. Cada subcarpeta incluye el script de conmutación y la documentación del protocolo:

- `GL_iNet`: API JSON-RPC de GL.iNet.
- `Mercusys_TPLink`: inicio de sesión y cifrado de Mercusys/TP-Link.
- `Xiaomi_MiWiFi`: autenticación y configuración del Xiaomi Mi Router 4C.
- `ZTE_H298A`: flujo del ZTE H298A.
- `ZTE_Legacy`: flujo de los firmwares antiguos de ZTE.
- `Comparativa_Routers.md`: comparación de las integraciones.

La carpeta `tui` contiene la interfaz de monitorización basada en Rich y Scapy para observar dispositivos, tráfico y estadísticas desde una sesión del router. La carpeta `tests` reúne las pruebas unitarias; las operaciones de red, Scapy y las peticiones HTTP están simuladas para no cambiar ningún router.
