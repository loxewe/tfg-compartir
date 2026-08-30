# Automatización - Router GL.iNet

## 1. Introducción al Ecosistema GL.iNet
A diferencia de los routers proporcionados por operadoras tradicionales (como el ZTE H298A) o de marcas comerciales con firmware propietario cerrado (como Mercusys), los routers **GL.iNet** están basados nativamente en el sistema operativo libre **OpenWrt**.

Esto cambia radicalmente el paradigma de seguridad y automatización:
* **No hay scraping HTML:** La interfaz gráfica no mezcla los datos con el código fuente web.
* **Arquitectura Cliente-Servidor Real:** El frontend (Vue.js) se comunica con el backend del router exclusivamente mediante llamadas **JSON-RPC** a través del bus de mensajes interno de OpenWrt, conocido como **`ubus`**.
* Todas las comunicaciones pasan por un único endpoint (URL) centralizado: `http://192.168.8.1/rpc`.

## 2. El Protocolo de Autenticación (Challenge-Response)
GL.iNet implementa un protocolo de seguridad criptográfico avanzado de "Desafío-Respuesta" para evitar que la contraseña viaje en texto plano por la red y para mitigar ataques de reenvío (*Replay Attacks*). 

Este protocolo consta de dos fases a través de peticiones `POST` enviadas al endpoint `/rpc`:

### Fase 1: El Desafío (Challenge)
El cliente inicia la negociación declarando qué usuario desea autenticar.
**Petición (Payload):**
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "challenge",
  "params": {"username": "root"}
}
```
**Respuesta del Router:**
El router responde con los ingredientes criptográficos que el cliente debe usar para generar la firma.
```json
{
  "nonce": "fHiWvd7RDbDXBwvlc7GWBsaTxm6zN409",
  "alg": 5,
  "salt": "ydqhBSQ9cv4nfk1b",
  "hash-method": "sha256"
}
```
* **`nonce`**: Número aleatorio de un solo uso para evitar ataques de reenvío.
* **`alg`**: Identificador del algoritmo (el valor `5` corresponde a *SHA-256 Crypt* en el estándar POSIX de Linux).
* **`salt`**: Sal criptográfica asignada a la contraseña almacenada.

### Fase 2: La Resolución Criptográfica (El Secreto de GL.iNet)
Mediante ingeniería inversa y fuerza bruta asistida en Python, se determinó la fórmula matemática exacta que el frontend de GL.iNet utiliza para resolver este desafío:

1. **Shadow Hash Local:** Se simula la generación de la contraseña hash tal y como se guardaría en el archivo `/etc/shadow` de Linux. Al ser el algoritmo 5, se requiere usar la función `sha256_crypt` con 5000 iteraciones por defecto.
   * `shadow = sha256_crypt(password, salt)`
   * *Resultado intermedio:* `$5$ydqhBSQ...$Iap2NV7...`
2. **Cifrado de Transporte:** Se concatena el nombre de usuario, el shadow hash, y el nonce efímero separados por el carácter `:`. A esta cadena resultante se le aplica un hashing **SHA-256** simple para obtener la firma final de 64 caracteres.
   * `final_hash = sha256("root" + ":" + shadow + ":" + nonce)`

### Fase 3: El Inicio de Sesión (Login)
Una vez resuelto matemáticamente el rompecabezas, se envía el hash final al router.
**Petición (Payload):**
```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "method": "login",
  "params": {
    "username": "root",
    "hash": "0c28b1b2dd41ef56ccff705793f6234065be0be1cedf74bd3965d2d218774e8a"
  }
}
```
**Respuesta del Router:**
```json
{
  "username": "root",
  "sid": "VfzgtgZ2xWKZTUpVQcYytPPjQxO5uKxD"
}
```
El router devuelve el **Session ID (`sid`)**. A partir de este momento, este token debe acompañar a todas las peticiones posteriores dentro del array `params`.

## 3. Automatización de la Interfaz Wi-Fi (ubus RPC)
Una vez autenticados, interactuar con el router GL.iNet es extremadamente sencillo gracias al bus `ubus`.

Las peticiones utilizan el método `call` para invocar módulos internos. En este caso, para apagar o encender el Wi-Fi, se interactúa con el módulo `"wifi"` y su método `"set_config"`.

**Petición (Apagar Wi-Fi 2.4GHz):**
```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "method": "call",
  "params": [
    "VfzgtgZ2xWKZTUpVQcYytPPjQxO5uKxD",  // 1. Token de sesión (SID)
    "wifi",                              // 2. Módulo de destino
    "set_config",                        // 3. Acción a ejecutar
    {                                    // 4. Argumentos
      "iface_name": "wifi2g",
      "enabled": false
    }
  ]
}
```
*Nota: Para los modelos *Dual-Band*, se repetiría exactamente la misma petición cambiando `"iface_name": "wifi2g"` por `"wifi5g"`.*

## 4. Comparativa Técnica y Conclusiones para el TFG
La automatización del router GL.iNet destaca por:
* **Fiabilidad Absoluta:** Al basarse en un protocolo oficial (RPC) pensado explícitamente para integraciones y sistemas integrados, no hay riesgo de que el código falle porque ZTE o Mercusys cambien un nombre de clase CSS en una actualización web.
* **Despliegue Nativo:** El script en Python consume mínimos recursos. Requiere instalar la librería estandarizada `passlib` en OpenWrt, lo cual sustituye la necesidad de arrastrar motores completos de cifrado AES o RSA de múltiples fases como se requería en los routers ofuscados.
* **Seguridad Profesional:** El router confía en el sistema criptográfico nativo de Linux (Shadow hashes) para la autenticación sin sacrificar la API, demostrando que es posible tener un panel de control seguro contra bots y ataques de red sin tener que recurrir a trampas de estado (Page-Context) confusas.
