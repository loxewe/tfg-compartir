# Automatización - Xiaomi Mi Router 4C

## 1. Arquitectura y Ecosistema (MiWiFi / LuCI)
El router Xiaomi Mi Router 4C (al igual que gran parte de los routers de Xiaomi) está basado en un firmware propio llamado **MiWiFi**. Internamente, MiWiFi no es más que una versión altamente modificada del sistema libre **OpenWrt**, utilizando la conocida interfaz web **LuCI**.

A diferencia del GL.iNet (que exponía una API JSON-RPC `ubus` limpia), Xiaomi utiliza endpoints RESTful tradicionales dentro del directorio de LuCI (`/cgi-bin/luci/api/`). Sin embargo, ha integrado un mecanismo criptográfico de seguridad en el frontend mucho más complejo para proteger las credenciales de administrador frente a ataques en redes no seguras.

## 2. El Protocolo de Autenticación (Nonce Hashing en Cliente)
La mayor peculiaridad del ecosistema Xiaomi es su implementación del protocolo Desafío-Respuesta (*Challenge-Response*). Mientras que en otros routers el servidor emite el desafío (un *seed* o *token* temporal), **en Xiaomi es el propio cliente (el navegador web) quien genera el desafío** de forma estandarizada.

### Fase 1: Generación del Nonce (El Desafío del Cliente)
El cliente extrae la dirección MAC del router mediante *scraping* o de una variable inyectada en el HTML (`deviceId`) y genera un código efímero llamado `nonce` concatenando 4 elementos:
1. Un `0` (Tipo).
2. La dirección **MAC** del router (ej. `e0:d4:64:23:5f:0f`).
3. El **Timestamp** UNIX de ese milisegundo (ej. `1786475892`).
4. Un **número aleatorio** de 4 cifras.

*Ejemplo de Nonce:* `0_e0:d4:64:23:5f:0f_1786475892_1491`

### Fase 2: La Ecuación Criptográfica (Doble SHA-1)
Dentro del código Javascript ofuscado (`login.html`), Xiaomi esconde una **Llave Maestra Secreta** (*Hardcoded*):
`this.key = 'a2ffa5c9be07488bbb04a3a47d3c5f6a'`

La contraseña del usuario nunca viaja en texto plano, sino que es cifrada a través de una doble pasada por el algoritmo matemático **SHA-1** empleando el `nonce` y la llave maestra:

```javascript
// Hash Intermedio
Hash_1 = SHA1(Contraseña_Admin + Llave_Secreta)

// Hash Final (El que se envía por red)
Hash_Final = SHA1(Nonce + Hash_1)
```

### Fase 3: Validación del Timestamp (El mecanismo Anti-Replay)
El ataque de reenvío (*Replay Attack*) se evita en el servidor. Cuando el router recibe el `nonce` y el `Hash Final`, **extrae el Timestamp** incrustado en el propio string del `nonce`. 
Si la diferencia entre el Timestamp proporcionado por el cliente y el reloj interno de OpenWrt es mayor a un pequeño margen de tolerancia (unos minutos), el router descarta inmediatamente el inicio de sesión. 
Si está en hora, el servidor replica la suma matemática del Hash y, de ser correcta, concede el acceso.

**Respuesta Exitosa del Login:**
```json
{
  "code": 0,
  "token": "a643898605fe20e8a690dc83715f5037",
  "url": "/cgi-bin/luci/;stok=a6438986.../web/home"
}
```
El `token` obtenido es equivalente al `stok` y será el pasaporte obligatorio para todas las peticiones posteriores.

## 3. Automatización de la Interfaz Wi-Fi (Endpoints Reutilizados)
En un router convencional y limpio (como el GL.iNet), se interactúa con una función específica para apagar o encender el componente emisor. 
En Xiaomi, la interfaz web carece de un endpoint específico "Toggle Wi-Fi". El frontend intercepta el clic en el botón de apagado, recopila la configuración entera de la interfaz y re-envía el formulario completo al endpoint maestro **`/api/xqnetwork/set_wifi`**.

**Payload requerido:**
* `wifiIndex`: `1` (Banda de 2.4GHz).
* `on`: `0` o `1` (Apagado / Encendido).
* `ssid`: Nombre de la red.
* `pwd`: Contraseña de la red Wi-Fi (WPA2) en **texto plano**.
* Otras configuraciones estáticas (canal, cifrado, potencia).

*Aviso de Seguridad en Diseño:* El envío de la contraseña del Wi-Fi (`pwd`) en texto plano no se debe a un error de ofuscación, sino a que el router necesita la cadena de texto real para reconstruir el archivo de configuración `hostapd` del OpenWrt y poder validar la llave Preshared Key con los dispositivos clientes en el futuro.

## 4. Comparativa Técnica y Conclusiones para el TFG
La automatización del router Xiaomi presenta lecciones muy interesantes a nivel de arquitectura:
1. **Delegación al Cliente (Fat Client):** Mover la carga de generación del `nonce` al cliente ahorra llamadas HTTP innecesarias al servidor, optimizando la experiencia y protegiendo el router de ataques de saturación.
2. **Cifrado sin Librerías Pesadas:** Utilizar `SHA-1` en cadena frente a cifrados robustos y asimétricos (como el `RSA` empleado en el ZTE H298A) es un compromiso aceptable para una interfaz administrativa local, obteniendo protección contra sniffing sin incurrir en latencias criptográficas o dependencias masivas (JSencrypt, CryptoJS completo).
3. **Reutilización Endpoints (Monolítico):** Demuestra el diseño de una API monolítica, donde se prefiere enviar *payloads* enormes con toda la configuración simultánea en lugar de múltiples peticiones parciales (microservicios), asegurando la atomicidad de las operaciones Wi-Fi pero complicando el *scripting* de terceros.
