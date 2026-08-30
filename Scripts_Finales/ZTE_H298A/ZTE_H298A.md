# Automatización del Router ZTE ZXHN H298A: Automatización de Red Wi-Fi

Este documento detalla el proceso de análisis, depuración e ingeniería inversa realizado sobre la interfaz web del router de operadora ZTE ZXHN H298A, con el objetivo de automatizar el encendido y apagado de las redes Wi-Fi (2.4GHz y 5GHz). Esta documentación está pensada para ser anexada y explicada en el desarrollo del Trabajo de Fin de Grado (TFG).

---

## 1. Contexto y Requisitos del TFG

El objetivo principal era crear un script automatizado que permitiese gestionar el estado del Wi-Fi del router ZTE desde un nodo controlador (una Raspberry Pi). 
El requisito más restrictivo del ecosistema es que la Raspberry Pi ejecuta **OpenWrt** como sistema operativo. OpenWrt está diseñado para hardware embebido, lo cual descarta el uso de herramientas de automatización de navegadores pesados (como Selenium o Playwright basadas en Chromium), ya que estas librerías no son compatibles con la arquitectura de paquetería optimizada (basada en `musl` libc) de OpenWrt sin virtualización. 

Por tanto, la solución requería de un script nativo y ultraligero que pudiera simular las interacciones a nivel de sockets HTTP utilizando librerías estándar como `requests`.

---

## 2. Primera Fase: Análisis de Tráfico e Interceptación

Para poder emular la interfaz web, el primer paso consistió en interceptar el tráfico legítimo entre un navegador y el router mediante las DevTools (pestaña Network) y scripts de interceptación locales.

### Descubrimientos Criptográficos
Contrario a los routers genéricos que envían peticiones `POST` en texto plano o con autenticación básica (`Basic Auth`), se descubrió que el ZTE ZXHN H298A utiliza un robusto sistema de cifrado asimétrico en la capa de aplicación (JavaScript) antes de que el tráfico siquiera toque la capa de transporte (HTTPS/TLS):

1. **Cifrado RSA del Payload:** Las variables de los formularios no se mandan en texto plano. En su lugar, se formatean como una cadena (ej. `IF_ACTION=Apply&RadioStatus_0=1...`), se les aplica una función hash (SHA-256) y finalmente se cifra dicho hash usando una clave pública **RSA de 2048 bits**.
2. **Cabecera Check:** Este bloque cifrado se codifica en Base64 y se envía en una cabecera HTTP personalizada llamada `Check`.
3. **Ofuscación:** El frontend utiliza librerías ofuscadas (como una variante de `JSEncrypt` modificada por ZTE) distribuidas en múltiples _frames_ para dificultar su lectura.

Para replicar esto en Python, hubo que extraer la clave pública estática codificada en los archivos JavaScript del router (`common_lib.js`) y aplicar el cifrado mediante la librería `pycryptodome` (implementando el esquema de _padding_ `PKCS1 v1.5`).

---

## 3. Segunda Fase: El Flujo de Autenticación (Login)

El proceso de autenticación requiere un _handshake_ múltiple:

1. **Petición GET inicial (`login_entry`):** Se obtiene un token temporal de sesión.
2. **Petición GET al generador de semilla (`login_token`):** El router devuelve un `seed` aleatorio dinámico en formato XML.
3. **Hashing de la contraseña:** La contraseña no viaja ni siquiera cifrada asimétricamente. Se envía un hash dinámico resultado de concatenar la contraseña en texto plano con el `seed` obtenido y pasándolo por **SHA-256**.
4. **Petición POST:** Se envía el hash al endpoint de login junto con el token temporal.

Una vez implementado esto en Python, el servidor respondía con `{"login_need_refresh":true}`, validando las credenciales y abriendo la sesión.

---

## 4. Tercera Fase: El Mecanismo Anti-Bot y el "Page Context"

El problema arquitectónico más grande del desarrollo surgió al intentar enviar el formulario de apagado del Wi-Fi (endpoint `wlan_wlanbasiconoff_lua.lua`) usando la sesión recién autenticada. A pesar de que el cifrado RSA y la autenticación eran perfectos, el servidor abortaba las conexiones o respondía de forma sistemática con un error de seguridad interno: `SessionTimeout`.

### Hipótesis y Diagnóstico con Playwright
Para aislar el problema, se desarrolló un prototipo auxiliar utilizando **Playwright** (automatización visual de un navegador Chromium invisible). A través de Playwright, el encendido/apagado del Wi-Fi funcionaba sin problemas.
Esto demostró que el servidor ZTE no distinguía la huella criptográfica (TLS Fingerprinting), sino que requería un flujo interno orquestado por el motor de ejecución de JavaScript del navegador. 

Se orquestó un script de _sniffing_ (`capture_full.py`) que actuaba de proxy transparente sobre la instancia de Playwright para volcar todas las peticiones a un JSON. Al comparar las trazas del navegador con las del script nativo en Python, se desvelaron los dos mecanismos de defensa del router:

### 1. Sistema de Máquina de Estados (Page Context)
El servidor ZTE no es puramente REST. Mantiene un **estado conversacional en el backend**. Para que el router acepte la recepción de variables para el menú de WLAN, exige que en esa sesión se haya renderizado de antemano el código HTML (las plantillas Server-Side `.lp` de ZTE). 
Si el script de Python mandaba un POST directo al motor `.lua`, el backend lo consideraba manipulación de API (Bot) por no venir precedido de peticiones a `menuView`.

* **Solución:** Simular en el script de Python un rastro de navegación falso realizando peticiones `GET` a los endpoints lógicos (`menuView&_tag=localNetStatus` y `menuView&_tag=wlanBasic`) para registrar la visita en la base de datos temporal del backend.

### 2. CSRF Dinámico en Cascada (Invalidación de Tokens)
Al solicitar los `menuView` descubiertos, el servidor dejaba de arrojar el error `SessionTimeout`, pero emitía un código `-1452: Esta página ha caducado`.
El análisis demostró que, cada vez que el usuario navega a un submenú, el router **invalida el token de sesión** original (`sess_token`). El script estaba intentando enviar el formulario con el token del login, el cual había quedado obsoleto al simular la navegación en el paso anterior (Page Context).

* **Solución:** Inmediatamente después de simular la navegación visual, el script de Python debe realizar una petición al endpoint de inicio para forzar la emisión de un nuevo _token fresco_, que es el que se integrará en el string que será firmado criptográficamente y enviado por POST.

---

## 5. Arquitectura de la Solución Final

Con las piezas del puzle resueltas, el flujo de ejecución nativo programado (`conmutar_zte_requests.py`) actúa de la siguiente manera cronológica y determinista:

1. Extracción de Token Inicial.
2. Extracción de Seed y Login por Hash SHA-256 (Evita la interceptación pasiva).
3. Obtención del token definitivo post-login.
4. **Bypass Anti-Bot:** Peticiones GET a los menús internos simulando el comportamiento humano en la UI para alinear la máquina de estados del backend.
5. **CSRF Refresh:** Obtención del token de sesión de segunda etapa.
6. Ensamblaje del Payload (`IF_ACTION=Apply&RadioStatus_0...`), hashing (SHA-256), y firmado por asimetría RSA (2048-bit).
7. POST final y **Logout** limpio. (El _Logout_ es crítico para evitar que el router limite el número máximo de sesiones abiertas y cause un bloqueo por denegación de servicio a causa del uso automatizado (Cron) desde OpenWrt).

## Conclusión

La solución ha conseguido sobrepasar uno de los mecanismos de mitigación contra bots más opacos en routers ISP domésticos, convirtiéndose de un script inviable por dependencias de sistema a un archivo de Python estándar altamente optimizado, capaz de operar bajo el ecosistema restrictivo de un nodo OpenWrt.
