# Automatización del Router Mercusys (TP-Link): Automatización de Red Wi-Fi

Este documento detalla el proceso de análisis de seguridad e ingeniería inversa realizado sobre la interfaz de administración web de los routers Mercusys (ecosistema TP-Link / `mwlogin.net`). El objetivo de este estudio en el marco del Trabajo de Fin de Grado (TFG) era lograr la automatización del encendido y apagado de las bandas Wi-Fi (2.4GHz y 5GHz) desde una Raspberry Pi mediante un script nativo de Python (`conmutar_router.py`).

---

## 1. Contexto de Seguridad del Ecosistema Mercusys/TP-Link

A diferencia de los routers de operadora tradicionales que suelen depender de autenticación básica o tokens en texto plano, las iteraciones modernas del firmware de Mercusys (basado en arquitectura TP-Link / LuCI modificado) implementan un **Protocolo de Criptografía Híbrida Personalizado** sobre HTTP. 

La interfaz web no envía ninguna petición de configuración en texto plano. En su lugar, el frontend (JavaScript) actúa como un cliente criptográfico completo que negocia claves, cifra cargas útiles simétricamente y firma las peticiones para evitar ataques de intermediario (MitM) y ataques de repetición (Replay Attacks).

---

## 2. Fases de Autenticación y Negociación Criptográfica

Para poder autenticarnos programáticamente mediante Python, fue necesario desensamblar y replicar el flujo matemático exacto que realiza el navegador. Este flujo consta de varias etapas:

### 2.1. Intercambio de Claves RSA (Key Exchange)
El router no utiliza un certificado TLS tradicional para proteger las credenciales en la capa de red. En su lugar, el cliente solicita activamente las claves públicas al servidor:
* **Obtención de Claves de Contraseña:** Se realiza una petición a `/login?form=keys`. El servidor responde con un módulo (`nk`) y un exponente (`ek`) RSA.
* **Cifrado de Credenciales:** La contraseña introducida por el usuario se cifra utilizando este par de claves RSA mediante un algoritmo de _padding_ a medida (`rsa_encrypt_chunk`), troceando la cadena en bloques fijos antes de aplicar la exponenciación modular.

### 2.2. Negociación de Parámetros de Integridad
Inmediatamente después, el cliente solicita parámetros de sesión mediante el endpoint `/login?form=auth`. El router responde con:
* Un número de secuencia (`seq`) base.
* Un nuevo par de claves RSA (`na`, `ea`) destinado exclusivamente para **Firma de Peticiones** (Signature).

### 2.3. Cifrado Simétrico del Payload (AES-CBC)
Para enviar el payload real del login (ej. `password={pwd_rsa}&operation=login`), el script de automatización debe actuar como un generador criptográfico:
1. Genera una **Clave AES de 16 bytes** aleatoria basada en el timestamp del sistema.
2. Genera un **Vector de Inicialización (IV) de 16 bytes** aleatorio.
3. Se cifra el payload utilizando AES en modo CBC con _Padding_ PKCS7. Esto produce el paquete de datos en base64 (`crypted_data`).

### 2.4. Protección contra Ataques de Repetición (Replay)
Para que el servidor verifique que el mensaje no ha sido interceptado o reenviado, el script debe calcular una **Firma operadortal**:
1. Se calcula el hash MD5 de la contraseña original concatenada con "admin" (`h_val`).
2. Se incrementa el número de secuencia sumando la longitud de los datos cifrados (`req_seq = seq + len(crypted_data)`).
3. Se empaquetan las variables: `k={key}&i={iv}&h={h_val}&s={req_seq}`.
4. Se cifra este paquete de verificación utilizando la segunda clave pública RSA (`na`, `ea`) obtenida en el paso 2.2. Este bloque actúa como el `sign` (Firma) de la petición.

El POST de autenticación final requiere enviar exclusivamente los campos de firma (`sign`) y datos encriptados (`data`). Si las matemáticas cuadran, el servidor responde devolviendo el **STOK** (Session Token) cifrado con la clave AES que nosotros mismos generamos.

---

## 3. Automatización del Menú Inalámbrico (WLAN)

Una vez obtenido el `stok` (Token de Sesión de LuCI), todas las peticiones posteriores deben ir dirigidas al endpoint `cgi-bin/luci/;stok={STOK}`.

Sin embargo, a diferencia del router ZTE que utiliza una máquina de estados (Page Context), Mercusys exige que **cada acción de configuración mantenga el canal criptográfico híbrido**:
1. Para apagar el Wi-Fi, se formula la cadena de escritura (ej. `operation=write_spf&wireless_2g_enable=off...`).
2. Se vuelve a cifrar todo el payload con las claves AES locales.
3. Se actualiza el número de secuencia de sesión en memoria para prevenir discrepancias con el servidor.
4. Se vuelve a generar una firma RSA que valida el tamaño de los datos y el hash MD5 local.

El router comprueba la firma y descifra la petición AES, aplicando los cambios en la interfaz de radio, y devuelve un JSON confirmando el apagado de las interfaces físicas (2.4GHz y 5GHz).

---

## 4. Conclusión Tecnológica

El desarrollo del script `conmutar_router.py` para Mercusys demuestra un nivel de seguridad en el frontend (Criptografía Híbrida) que es propio de infraestructuras empresariales, no de un entorno doméstico. El uso de claves asimétricas efímeras para intercambiar claves simétricas generadas por el cliente previene ataques incluso si el tráfico es interceptado sin SSL/TLS. 

La integración exitosa en un entorno ligero de Python (utilizando `pycryptodome` y `requests`) confirma que es posible orquestar redes domóticas seguras en nodos OpenWrt, manteniendo el rendimiento y evitando dependencias pesadas que mermarían las capacidades limitadas de la Raspberry Pi.
