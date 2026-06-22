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
8. [Exportar a CSV](#11-exportar-a-csv)
9. [Cambio de tema visual](#12-cambio-de-tema-visual)
10. [Código de colores por protocolo](#13-código-de-colores-por-protocolo)
11. [Preguntas frecuentes](#14-preguntas-frecuentes)

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

## 8. Exportar a CSV

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

## 9. Cambio de tema visual

El botón **Modo Claro / Modo Oscuro** en la barra de menú alterna entre
los dos temas disponibles. El cambio es inmediato y afecta toda la interfaz.

| Tema | Fondo | Recomendado para |
|---|---|---|
| **Oscuro** (predeterminado) | Gris muy oscuro `#1A1A1F` | Uso prolongado, ambientes con poca luz |
| **Claro** | Gris claro `#F0F0F5` | Presentaciones, ambientes con mucha luz |

---

## 10. Código de colores por protocolo

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

## 11. Preguntas frecuentes

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
