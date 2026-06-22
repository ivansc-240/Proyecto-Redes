# Manual de Usuario — Packet Sniffer

---

## Índice

1. [Requisitos previos](#1-requisitos-previos)
2. [Cómo compilar y ejecutar](#2-cómo-compilar-y-ejecutar)
3. [Interfaz general](#3-interfaz-general)
4. [Barra de menú](#4-barra-de-menú)
5. [Panel 1 — Tabla de paquetes](#5-panel-1--tabla-de-paquetes)
6. [Panel 2 — Detalle del paquete](#6-panel-2--detalle-del-paquete)
7. [Panel 3 — Hex Dump](#7-panel-3--hex-dump)
8. [Sistema IDS — Detección de SYN Flood](#8-sistema-ids--detección-de-syn-flood)
9. [Resaltado de IPs atacantes en la tabla](#9-resaltado-de-ips-atacantes-en-la-tabla)
10. [Reporte automático de incidentes](#10-reporte-automático-de-incidentes)
11. [Exportar a CSV](#11-exportar-a-csv)
12. [Cambio de tema visual](#12-cambio-de-tema-visual)
13. [Código de colores por protocolo](#13-código-de-colores-por-protocolo)
14. [Preguntas frecuentes](#14-preguntas-frecuentes)

---

## 1. Requisitos previos

Antes de ejecutar la aplicación, asegúrate de tener instalado:

- **Npcap** con la opción _"WinPcap API-compatible Mode"_ activada
- **Windows 10 / 11** de 64 bits
- Una tarjeta gráfica con soporte **OpenGL 3.3** o superior

> La aplicación debe ejecutarse **como Administrador**. Sin este permiso, Npcap
> no puede abrir adaptadores de red en modo promiscuo y la lista de interfaces
> aparecerá vacía o la captura fallará silenciosamente.

---

## 2. Cómo compilar y ejecutar

### Compilar
Haz doble clic en `compilacion.bat` o ejecútalo desde la terminal MSYS2 UCRT64:

```bash
./compilacion.bat
```

Si la compilación es exitosa, el mensaje `Compilacion exitosa.` aparecerá en la
consola y la aplicación se lanzará automáticamente.

### Ejecutar manualmente
Haz clic derecho sobre `sniffer.exe` → **Ejecutar como administrador**.

> Ejecutar como Administrador también es necesario para que la aplicación
> pueda escribir los archivos de reporte del IDS (sección 10) en la carpeta
> del ejecutable.

---

## 3. Interfaz general

La ventana ocupa toda la pantalla y se divide en tres paneles fijos:

```
┌─────────────────────────────────────────────────────────┐
│  BARRA DE MENÚ                                          │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  PANEL 1 — Tabla de paquetes          (50% del alto)   │
│                                                         │
├────────────────────────┬────────────────────────────────┤
│  PANEL 2               │  PANEL 3                       │
│  Detalle del paquete   │  Hex Dump      (50% del alto) │
│  (50% del ancho)       │  (50% del ancho)               │
└────────────────────────┴────────────────────────────────┘
```

Los bordes de columna de la tabla son **arrastrables** para ajustar el ancho
de cada columna según tus preferencias.

Cuando el IDS detecta una posible inundación SYN, aparece además un **banner
rojo parpadeante** justo debajo de la barra de menú (ver sección 8) y las
filas de paquetes asociadas a las IPs responsables se resaltan en rojo dentro
del Panel 1 (ver sección 9).

---

## 4. Barra de menú

La barra superior contiene, de izquierda a derecha:

| Elemento | Descripción |
|---|---|
| **Packet Sniffer** | Nombre de la aplicación (indicador visual) |
| **Combo de interfaz** | Lista desplegable con todos los adaptadores de red detectados. Selecciona el adaptador antes de iniciar la captura |
| **> Iniciar** | Inicia la captura en el adaptador seleccionado. Se deshabilita visualmente al estar activo |
| **[] Detener** | Detiene la captura de forma limpia. Aparece solo mientras se captura |
| **\* CAPTURANDO** | Indicador animado (parpadeo sinusoidal) visible solo durante la captura activa |
| **Recargar interfaces** | Vuelve a enumerar los adaptadores de red del sistema. Útil si conectaste un adaptador después de abrir la aplicación |
| **Modo Claro / Modo Oscuro** | Alterna el tema visual entre oscuro y claro |
| **SYN: N/50 (10s)** | Contador del IDS en tiempo real (ver sección 8) |
| **Restablecer** | Reinicia el contador SYN del IDS a cero |

### Flujo básico de uso

1. Selecciona el adaptador de red en el combo
2. Presiona **> Iniciar**
3. Observa los paquetes en la tabla
4. Presiona **[] Detener** cuando termines

---

## 5. Panel 1 — Tabla de paquetes

### Columnas

| Columna | Contenido |
|---|---|
| **#** | Número de secuencia del frame desde el inicio de la captura |
| **Tiempo (s)** | Segundos transcurridos desde que se presionó Iniciar |
| **IP Origen** | Dirección IPv4 de origen (vacío en tramas no-IP como ARP) |
| **IP Destino** | Dirección IPv4 de destino |
| **MAC Origen** | Dirección MAC de origen en formato `XX:XX:XX:XX:XX:XX` |
| **MAC Destino** | Dirección MAC de destino |
| **Protocolo** | Etiqueta del protocolo detectado: TCP, UDP, ICMP, ARP, IPv6 |
| **Puerto** | Puerto origen → Puerto destino (vacío si no aplica) |
| **Bytes** | Longitud total del frame en bytes |

### Selección de paquete

Haz clic en cualquier fila para seleccionarla. Los paneles 2 y 3 se actualizarán
automáticamente mostrando el detalle y el volcado hexadecimal de ese paquete.

### Barra de estado

En la parte superior del panel aparece el contador total de paquetes capturados
desde el último inicio o limpieza. El botón **Limpiar lista** borra todos los
paquetes de memoria (no afecta archivos CSV ya exportados ni reportes del IDS
ya generados).

### Desplazamiento automático

Mientras la captura está activa y el scroll está al fondo, la tabla avanza
automáticamente para mostrar siempre el paquete más reciente. Si subes
manualmente el scroll para revisar paquetes anteriores, el avance automático
se pausa hasta que vuelvas al fondo.

### Filtros

Debajo de la barra de estado hay cuatro controles de filtro que actúan
simultáneamente y en tiempo real sin modificar los datos capturados:

| Filtro | Comportamiento |
|---|---|
| **IP Origen** | Muestra solo paquetes cuya IP origen contenga el texto ingresado (insensible a mayúsculas) |
| **IP Destino** | Igual que el anterior pero para IP destino |
| **Puerto** | Muestra paquetes donde el puerto origen **o** el puerto destino coincidan con el número ingresado |
| **Protocolo** | Desplegable con opciones: Todos, TCP, UDP, ICMP, ARP, IPv6 |

Dejar un campo vacío equivale a sin filtro para ese campo. Los filtros son
acumulativos: un paquete debe satisfacer **todos** los filtros activos para
aparecer en la tabla. El resaltado en rojo de IPs atacantes (sección 9) se
aplica **después** de los filtros, es decir, solo a las filas que ya son
visibles.

---

## 6. Panel 2 — Detalle del paquete

Muestra la disección capa por capa del paquete seleccionado en texto legible.

La disección sigue el modelo OSI de arriba hacia abajo:

```
[Ethernet]
  MAC Origen : AA:BB:CC:DD:EE:FF
  MAC Destino: 11:22:33:44:55:66
  EtherType  : 0x0800

[IPv4]
  IP Origen : 192.168.1.10
  IP Destino: 8.8.8.8
  TTL       : 64
  Protocolo : 6
  Total     : 60 bytes

[TCP]
  Puerto Origen : 54321
  Puerto Destino: 443
  Seq           : 1234567890
  Ack           : 0
  Flags         : SYN
  Ventana       : 65535
```

Si no hay ningún paquete seleccionado, el panel muestra el mensaje
`(Selecciona un paquete en la tabla)`.

---

## 7. Panel 3 — Hex Dump

Muestra el contenido completo del frame seleccionado en formato hexadecimal
y ASCII, usando fuente monoespaciada (Consolas 16 pt).

Formato de cada línea:

```
0000  45 00 00 3c 1c 46 40 00  40 06 00 00 c0 a8 01 0a  |E..<.F@.@.......|
```

- La primera columna es el **offset** en hexadecimal
- La segunda sección muestra los **bytes en hex**, 16 por línea con un espacio
  extra en el centro tras el byte 8
- La tercera sección muestra la **representación ASCII**; los bytes no
  imprimibles se sustituyen por `.`

El panel es de **solo lectura** y tiene scroll vertical independiente.

---

## 8. Sistema IDS — Detección de SYN Flood

La aplicación incluye un sistema pasivo de detección de intrusos (IDS) que
monitorea paquetes TCP con la bandera SYN activa para identificar posibles
ataques de inundación (SYN Flood / DoS). Además de contar los SYN de forma
global, el IDS lleva un registro **por IP origen**, lo que permite no solo
saber que hay un posible ataque, sino también señalar de dónde proviene
(secciones 9 y 10).

### Cómo funciona

- Cada paquete TCP-SYN detectado incrementa un contador interno global
- En paralelo, se incrementa también un contador individual asociado a la IP
  origen de ese paquete
- Ambos contadores se reinician automáticamente cada **10 segundos** (ventana
  de muestreo)
- Si el contador global supera **50 paquetes SYN** dentro de la ventana, se
  activa la alerta: aparece el banner rojo, las IPs más activas se resaltan
  en la tabla (sección 9) y se genera un reporte automático (sección 10)

### Indicador en la barra de menú

El texto **SYN: N/50 (10s)** en la barra superior muestra en todo momento:

- `N` — cantidad de paquetes SYN detectados en la ventana actual (conteo global)
- `50` — umbral de alerta
- `10s` — duración de la ventana de muestreo

El color del texto cambia según el estado:

| Color | Significado |
|---|---|
| Verde | Tráfico SYN normal, sin alerta |
| Rojo | Umbral superado, posible ataque en curso |

### Alerta visual

Cuando el contador supera el umbral, aparece un **banner rojo parpadeante**
debajo de la barra de menú con el mensaje:

```
[!] ALERTA DE SEGURIDAD: Posible ataque DoS / SYN Flood Detectado
```

El banner parpadea a 1 Hz (visible y oculto alternando cada medio segundo)
para maximizar la visibilidad. Desaparece automáticamente cuando el contador
baja del umbral al inicio de una nueva ventana de muestreo.

### Botón Restablecer

El botón **Restablecer** en la barra de menú pone a cero inmediatamente el
contador global y los contadores por IP, e inicia una nueva ventana de
muestreo, apagando la alerta (banner, resaltado en rojo) de forma manual sin
necesidad de esperar los 10 segundos.

> **Nota:** el IDS es de carácter educativo y pasivo. Detecta, resalta y
> reporta, pero no bloquea tráfico. Un alto número de SYN puede tener causas
> legítimas en redes con mucho tráfico (servidores web con muchas conexiones
> simultáneas). Interpreta la alerta en contexto.

---

## 9. Resaltado de IPs atacantes en la tabla

Mientras la alerta del IDS está activa (contador global de SYN por encima del
umbral), el Panel 1 deja de pintar algunas filas con el color habitual de
protocolo y en su lugar las marca con un **fondo rojo** para destacar a las
IPs responsables.

### Cómo se decide qué filas se pintan en rojo

Para cada paquete visible en la tabla (es decir, que ya pasó los filtros
activos), la aplicación revisa cuántos paquetes SYN ha generado su IP origen
dentro de la ventana de muestreo actual. Si esa IP por sí sola acumula **más
de la mitad del umbral de alerta** (25 SYN de los 50 configurados por
defecto), la fila se resalta en rojo. Las filas de paquetes cuya IP origen no
alcanza ese nivel de actividad conservan su color normal por protocolo,
incluso mientras la alerta global está activa.

Esto significa que, durante un SYN Flood con múltiples orígenes mezclados en
el mismo tráfico, solo se iluminan en rojo las IPs que realmente están
contribuyendo de forma significativa al ataque, no todas las filas de la
tabla.

### Cuándo deja de verse el resaltado

El color rojo desaparece de inmediato cuando:

- El contador global de SYN vuelve a estar por debajo del umbral al iniciarse
  una nueva ventana de muestreo, o
- Se presiona el botón **Restablecer** en la barra de menú

En ambos casos las filas vuelven a mostrarse con el color tenue habitual por
protocolo (sección 13).

> El resaltado es exclusivamente visual: no oculta, elimina ni modifica
> ningún paquete. Los datos del Panel 2 y el volcado del Panel 3 siguen
> disponibles con normalidad para cualquier paquete, esté o no resaltado.

---

## 10. Reporte automático de incidentes

Además de la alerta visual, la aplicación genera automáticamente un **reporte
en texto plano** cada vez que el contador global de SYN supera el umbral por
primera vez dentro de una ventana de alerta.

### Cuándo se genera

El reporte se crea exactamente una vez por cada vez que la alerta se dispara.
Mientras el contador permanezca por encima del umbral no se generan reportes
adicionales; si la alerta se apaga y vuelve a activarse más adelante (nueva
ventana, o tras pulsar Restablecer y que el tráfico vuelva a superar el
umbral), se genera un nuevo archivo independiente.

### Dónde se guarda

El archivo se guarda en la **misma carpeta donde se ejecuta `sniffer.exe`**,
con el nombre:

```
reporte_ids_<timestamp_unix>.txt
```

El `timestamp_unix` corresponde al momento exacto en que se disparó la
alerta, lo que evita que un reporte sobrescriba a otro generado en un
incidente anterior.

### Qué contiene

El reporte incluye, en este orden:

1. Un encabezado identificando el tipo de evento (SYN Flood)
2. El timestamp UNIX del incidente
3. La cantidad de paquetes SYN detectados en el momento de generarse el reporte
4. El umbral configurado y la duración de la ventana de muestreo
5. Un **ranking de IPs origen**, ordenado de mayor a menor número de paquetes
   SYN, mostrando cada IP junto con su conteo dentro de la ventana

Ejemplo de contenido:

```
========================================================
   REPORTE DE ALERTA IDS - POSIBLE ATAQUE SYN FLOOD
========================================================

Timestamp (UNIX) : 1750000000
SYN detectados   : 57
Umbral configurado: 50
Ventana de muestreo: 10 segundos

--------------------------------------------------------
  RANKING DE IPs POR CONTEO DE PAQUETES SYN
--------------------------------------------------------
  1. 203.0.113.45  ->  41 paquetes SYN
  2. 198.51.100.7  ->  12 paquetes SYN
  3. 192.0.2.9     ->  4 paquetes SYN
```

Si por alguna razón no hay direcciones IP disponibles asociadas a los SYN
contados (por ejemplo, tramas truncadas), el reporte lo indica explícitamente
en lugar del ranking.

> El reporte es una fotografía del instante en que se disparó la alerta; no
> se actualiza después. Si quieres un reporte con cifras más recientes del
> mismo incidente prolongado, deja que la alerta se apague (Restablecer o fin
> de ventana) y permite que se vuelva a disparar.

---

## 11. Exportar a CSV

El botón **Exportar CSV** guarda en la carpeta del ejecutable un archivo con
el nombre `captura_<timestamp>.csv` que contiene únicamente los paquetes
visibles según los filtros activos en ese momento.

### Columnas del CSV

```
#, Tiempo, IP Origen, IP Destino, Protocolo, Puerto Origen, Puerto Destino, Longitud
```

El archivo puede abrirse directamente en Excel, LibreOffice Calc o cualquier
herramienta de análisis de datos. El tiempo se exporta con 6 decimales de
precisión (microsegundos). El CSV no incluye una columna de "atacante"; para
analizar el incidente con detalle usa el reporte automático de la sección 10
o aplica el filtro de IP Origen sobre las direcciones que aparecieron
resaltadas en rojo.

---

## 12. Cambio de tema visual

El botón **Modo Claro / Modo Oscuro** en la barra de menú alterna entre
los dos temas disponibles. El cambio es inmediato y afecta toda la interfaz.

| Tema | Fondo | Recomendado para |
|---|---|---|
| **Oscuro** (predeterminado) | Gris muy oscuro `#1A1A1F` | Uso prolongado, ambientes con poca luz |
| **Claro** | Gris claro `#F0F0F5` | Presentaciones, ambientes con mucha luz |

---

## 13. Código de colores por protocolo

Las filas de la tabla tienen un color de fondo tenue que identifica visualmente
el protocolo de cada paquete:

| Color | Protocolo |
|---|---|
| Azul claro | TCP |
| Verde claro | UDP |
| Amarillo | ICMP |
| Naranja | ARP |
| Lila | IPv6 |
| Gris neutro | Otros / desconocido |
| **Rojo** | IP origen identificada como responsable de un SYN Flood en curso (sección 9); sustituye temporalmente al color de protocolo de esa fila |

---

## 14. Preguntas frecuentes

**¿Por qué la lista de interfaces aparece vacía?**
Npcap no está instalado o no se activó la opción _WinPcap API-compatible Mode_
durante su instalación. Reinstala Npcap con esa opción activa y reinicia
la aplicación como Administrador.

**¿Por qué al presionar Iniciar no aparecen paquetes?**
Verifica que seleccionaste el adaptador correcto en el combo. Si tienes Wi-Fi
y Ethernet, prueba ambos. También asegúrate de que hay tráfico activo en
la red (abre un navegador, por ejemplo).

**¿Los filtros borran paquetes capturados?**
No. Los filtros son solo visuales. Al limpiar o cambiar los filtros, los
paquetes que no coincidían siguen en memoria y vuelven a aparecer.

**¿Qué pasa si presiono Limpiar lista durante la captura?**
La lista en memoria se vacía y el contador de paquetes se reinicia a cero,
pero la captura continúa activa y los nuevos paquetes siguen llegando
normalmente. El contador del IDS y sus archivos de reporte no se ven
afectados por este botón.

**¿El CSV incluye paquetes ocultos por los filtros?**
No. El CSV exporta exactamente lo que se ve en la tabla en el momento de
presionar el botón, respetando todos los filtros activos.

**¿La alerta de SYN Flood significa que estoy siendo atacado?**
No necesariamente. Servidores web con muchas conexiones simultáneas pueden
generar muchos SYN legítimos. La alerta es un indicador que debe interpretarse
junto con el contexto de la red.

**¿Por qué algunas filas se ven en rojo y otras no, si la alerta está activa?**
Solo se resaltan en rojo las filas cuya IP origen acumula, por sí sola, más
de la mitad del umbral de SYN configurado dentro de la ventana actual. Si la
alerta se disparó por la suma de muchas IPs con poca actividad individual
cada una, es posible que ninguna fila alcance ese nivel y por lo tanto no se
vea resaltado en rojo aunque el banner de alerta esté visible.

**¿Dónde encuentro el reporte generado tras una alerta?**
En la misma carpeta donde está `sniffer.exe`, con el nombre
`reporte_ids_<timestamp_unix>.txt`. Revisa la sección 10 para el detalle de
su contenido.

**¿Se genera un reporte por cada paquete SYN o por cada alerta?**
Por cada alerta. Se genera una sola vez cuando el contador global supera el
umbral por primera vez en una ventana; no se crean reportes adicionales
mientras la alerta siga activa.

**¿Puedo cambiar el umbral o la ventana del IDS?**
Actualmente solo desde el código fuente, modificando las constantes
`SYN_UMBRAL` y `SYN_VENTANA_SEG` antes de recompilar. El umbral usado para
decidir el resaltado por IP (la mitad de `SYN_UMBRAL`) se ajusta
automáticamente junto con `SYN_UMBRAL`.
