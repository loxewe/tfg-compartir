# Automatización del Router ZTE (Versión Firmware Legacy/operador)

Este documento expone el análisis del protocolo de un modelo ZTE con un firmware anterior o de distinta operadora (comúnmente asociado a configuraciones como las de operador en la IP 192.168.1.1). A diferencia del modelo avanzado H298A, este router presenta una arquitectura de seguridad web más tradicional, aunque incluye rudimentos tempranos de los sistemas Anti-Bot que posteriormente evolucionarían en los modelos más nuevos.

---

## 1. Proceso de Autenticación (Login) sin Cifrado Asimétrico

En este firmware, la protección de las credenciales en la capa de aplicación es más simple y prescinde por completo del uso de criptografía asimétrica (RSA). El flujo es el siguiente:

1. **Obtención de Token Estático:** Al realizar una petición `GET` a la raíz del panel (`/`), el router sirve código HTML estático. Incrustado en el JavaScript de la página se encuentra una variable global `_sessionTOKEN` numérica, que el cliente debe extraer.
2. **Generación de Semilla (Seed):** El cliente realiza una petición asíncrona a un endpoint específico de login (`function_module/login_module/login_page/logintoken_lua.lua?_={timestamp}`). El servidor devuelve un número aleatorio directamente en el cuerpo HTML/XML.
3. **Hashing del Payload:** El cliente concatena la contraseña introducida por el usuario con el _seed_ obtenido, y le aplica un hash **SHA-256**.
4. **Envío:** El hash resultante se envía por POST a la raíz (`/`) junto con el `_sessionTOKEN`. Si las credenciales son válidas, el servidor responde con un código HTTP `302 Found` (redirección) e inyecta una cookie de sesión (`SID`).

Este enfoque protege la contraseña real (no viaja en texto plano), pero es vulnerable a ataques de repetición (Replay Attacks) a corto plazo si un atacante captura el token y el seed, ya que no existe un cifrado de carga útil ni firma temporal estricta.

---

## 2. Mecanismo de Defensa: CSRF Dinámico Ofuscado

Al igual que en los modelos modernos de ZTE, este router protege sus endpoints lógicos (`.lua`) contra automatizaciones y ataques de Falsificación de Petición en Sitios Cruzados (CSRF). 

Para apagar o encender el Wi-Fi, la lógica de automatización (`conmutar_zte.py`) debe seguir un procedimiento estricto de **Server-Side Rendering (SSR) Tacking**:

### 2.1. Navegación Ficticia (Page Context)
El servidor no permite enviar un POST directo para aplicar cambios en el Wi-Fi. Primero, exige que el usuario cargue visualmente la plantilla HTML del menú inalámbrico.
El script de Python debe realizar una petición `GET` a `getpage.lua?pid=1002&nextpage=Localnet_WlanBasicUser_t.lp`.

Si el script intentase evitar este paso, el servidor rechazaría la petición final o arrojaría un error `404` controlado, ya que la máquina de estados del backend no ha inicializado el contexto "WLAN" para esa sesión.

### 2.2. Extracción de Tokens Efímeros en HTML
Una vez que el servidor renderiza la página `.lp`, inyecta en el código fuente (a menudo ofuscado y escapado con secuencias hexadecimales como `\x32\x31...`) una variable llamada `_sessionTmpToken`. 
Este token temporal es dinámico y de un solo uso para la pestaña en la que se encuentra el usuario.

El script de automatización debe _parsear_ el HTML, limpiar la ofuscación unicode/hexadecimal y extraer este token.

---

## 3. Petición de Cambio de Estado (Wi-Fi Toggle)

Con el token efímero extraído, el script finalmente está autorizado a interactuar con el motor LUA de configuración.

A diferencia del router ZTE avanzado que requiere cifrar toda la petición en Base64/RSA, este firmware acepta las peticiones en formato estándar `application/x-www-form-urlencoded`.

El script ensambla un POST dirigido a `common_page/Localnet_WlanBasicAd_OnOff_lua.lua` con las variables físicas de las radios de 2.4GHz y 5GHz:
* `IF_ACTION=Apply`
* `RadioStatus_0={1 o 0}`
* `RadioStatus_1={1 o 0}`
* `_sessionTOKEN={El token efímero ofuscado que extrajimos del HTML}`

El servidor procesa el formulario estándar y responde con una validación XML simple: `<IF_ERRORSTR>SUCC</IF_ERRORSTR>`.

---

## Conclusión

La arquitectura de este ZTE "Legacy" demuestra la evolución de los firewalls internos en los routers de operadora. Mientras que este modelo dependía de:
* Hashing estático (SHA-256).
* Tokens dinámicos ofuscados inyectados directamente en el código fuente HTML.
* Payload en texto plano.

El modelo posterior (H298A) evolucionaría estos mismos conceptos hacia un estándar mucho más restrictivo (Cifrado RSA del Payload, Headers específicos, y separación estricta entre plantillas visuales `menuView` y endpoints de datos). La comparación entre ambos evidencia una clara tendencia de los fabricantes hacia la fortificación agresiva del frontend web contra la automatización.
