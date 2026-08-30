# Cambiar políticas sin reiniciar

El controlador comprueba `policies.json` cada dos segundos. No hace falta reiniciar
el controlador, el Wi-Fi ni el firewall después de cada cambio. Si está
aprovisionando un dispositivo, la recarga espera a que termine esa operación.

## Puesta en marcha

Copia las versiones actualizadas de `controlador_aut.py` y `policy_manager.py`
a la Raspberry e inicia el controlador actualizado una vez. Un proceso que ya
estaba ejecutándose con el código anterior no incorpora esta función por sí solo.
Esta mejora no instala servicios de arranque ni modifica el portal.

## Editar un dispositivo

En la Raspberry, edita `/root/tfg/policies.json` (si esa es la ruta de instalación).
Dentro del objeto `devices`, añade una entrada como esta, usando la MAC real del
dispositivo en lugar de la MAC ficticia del ejemplo:

```json
"02:00:00:00:00:01": {
    "internet": false
}
```

Conserva el resto del archivo, incluidas las IP de gestión si están configuradas.
Los campos omitidos heredan `default`. Usa `true` y `false`, sin comillas, y no
incluyas comentarios ni comas finales: el archivo debe ser JSON válido.

Opciones disponibles:

- `internet`: `true` o `false`.
- `inter_device`: `true` o `false`; permiso general, no por parejas de dispositivos.
- `mdns` y `ssdp`: `true` o `false`.
- `broadcast`: `"allow"`, `"block"` o `"log"`.

Cambiar `default` actualiza los campos heredados de todos los dispositivos.
Eliminar una entrada de `devices` restaura sus permisos predeterminados; no
elimina el dispositivo. Las políticas de dispositivos aún no conectados se
utilizarán cuando se registren.

## Comprobar el resultado

Si el controlador se lanzó desde el portal, consulta:

```sh
tail -f /tmp/tfg-controller.log
```

Una recarga correcta muestra `policies.json recargado: políticas aplicadas sin
reiniciar.` Comprueba también el tráfico real del dispositivo en la Raspberry.
Para revertir el ejemplo, cambia `internet` a `true` o elimina la excepción.

Un JSON inválido, ilegible o ausente no sustituye las políticas en memoria. Un
fallo de nftables tampoco acepta el nuevo estado y se reintenta en la siguiente
comprobación. El controlador no corrige ni sobrescribe el archivo: debes arreglarlo
antes de volver a arrancar, ya que un archivo inválido puede impedir el inicio.

Las modificaciones de `management_ip` o `management_router_ip` no se recargan:
se rechaza el documento completo hasta restaurarlas o reiniciar deliberadamente
el controlador con la nueva configuración. No vuelvas a lanzar el portal para
aplicar políticas: su función es preparar la instalación.

La TUI sigue siendo un monitor por SSH; no muestra confirmación de estas recargas
ni cambia automáticamente sus etiquetas para representar los permisos efectivos.
