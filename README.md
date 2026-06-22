# Packet Sniffer
Herramienta de captura y análisis de tráfico de red en tiempo real con interfaz gráfica,
construida en C++17. Incluye un sistema primitivo de detección de intrusos (IDS) pasivo
capaz de identificar ataques de inundación SYN (SYN Flood / DoS), resaltar visualmente
a las IPs causantes y generar automáticamente un reporte del incidente.

---

## Arquitectura

El proyecto utiliza un modelo de **doble hilo**:

- **Hilo de Captura** — ejecuta `pcap_loop()` de Npcap de forma bloqueante y despacha
  cada frame a la función callback `manejador_paquete`.
- **Hilo de Renderizado (UI)** — hilo principal de la aplicación; dibuja la interfaz
  gráfica a 60 FPS usando Dear ImGui + GLFW3 + OpenGL 3.3 Core.
- Ambos hilos comparten un `std::vector<PaqueteCapturado>` protegido mediante
  `std::mutex` y `std::lock_guard`.
- El IDS mantiene además un mapa `IP origen -> conteo de SYN` (`g_syn_por_ip`)
  protegido por un mutex independiente (`g_mutex_syn`), separado del mutex de
  paquetes para no bloquear la tabla mientras se actualizan las estadísticas
  de detección.

---

## Requisitos de sistema

| Requisito | Versión mínima |
|---|---|
| Windows | 10 / 11 (64 bits) |
| MSYS2 UCRT64 | Cualquier versión reciente |
| g++ | C++17 o superior |
| Npcap Runtime | 1.60 o superior |
| Npcap SDK | 1.13 o superior |
| GLFW3 | 3.3 o superior |
| OpenGL | 3.3 Core |
| Dear ImGui | Rama `master` |

> **Nota:** la aplicación requiere **ejecutarse como Administrador** para que Npcap
> pueda abrir adaptadores de red en modo promiscuo.

---

## Dependencias y cómo instalarlas

### 1. MSYS2 UCRT64

Descarga e instala MSYS2 desde https://www.msys2.org
Una vez instalado, abre la terminal **MSYS2 UCRT64** y actualiza el sistema:

```bash
pacman -Syu
```

### 2. Compilador y herramientas base

Desde la terminal MSYS2 UCRT64:

```bash
pacman -S mingw-w64-ucrt-x86_64-gcc mingw-w64-ucrt-x86_64-make
```

### 3. GLFW3

```bash
pacman -S mingw-w64-ucrt-x86_64-glfw
```

### 4. OpenGL

OpenGL no requiere instalación adicional en Windows. El paquete de MSYS2 que provee los headers es:

```bash
pacman -S mingw-w64-ucrt-x86_64-mesa
```

### 5. Npcap Runtime (obligatorio para ejecutar)

1. Descarga el instalador desde https://npcap.com/#download
2. Ejecuta el instalador **como Administrador**
3. Durante la instalación, activa la casilla:
   **"Install Npcap in WinPcap API-compatible Mode"**

> Sin este paso el `.exe` no podrá abrir ningún adaptador de red.

### 6. Npcap SDK (obligatorio para compilar)

1. Descarga el **Npcap SDK** (archivo `.zip`) desde https://npcap.com/#download
2. Extrae el contenido en `C:/Npcap-sdk`
   La estructura debe quedar así:
   ```
   C:/Npcap-sdk/
   ├── Include/
   │   └── pcap.h  (y otros headers)
   └── Lib/
       └── x64/
           └── wpcap.lib
   ```

### 7. Dear ImGui (rama master)

Dear ImGui **no se instala mediante pacman**; sus fuentes se copian directamente
al proyecto. Descarga la rama `master` desde https://github.com/ocornut/imgui

Los archivos necesarios se colocan así dentro del proyecto:

```
proyecto/
└── imgui/
    ├── imgui.h
    ├── imgui.cpp
    ├── imgui_demo.cpp
    ├── imgui_draw.cpp
    ├── imgui_tables.cpp
    ├── imgui_widgets.cpp
    ├── imgui_internal.h
    ├── imconfig.h
    ├── imstb_rectpack.h
    ├── imstb_textedit.h
    ├── imstb_truetype.h
    └── backends/
        ├── imgui_impl_glfw.h
        ├── imgui_impl_glfw.cpp
        ├── imgui_impl_opengl3.h
        └── imgui_impl_opengl3.cpp
```

> **Importante:** usar exclusivamente la rama `master`. La rama `docking` tiene una
> API diferente e incompatible con este proyecto.

---

## Estructura del proyecto

```
proyecto/
├── sniffer.cpp
├── compilar.bat
├── reporte_ids_<timestamp>.txt   (generado automáticamente, ver abajo)
└── imgui/
    ├── (archivos listados arriba)
    └── backends/
        └── (archivos listados arriba)
```

---

## Compilación

Desde la terminal **MSYS2 UCRT64**, dentro de la carpeta del proyecto:

```bash
g++ -std=c++17 -O2 -o sniffer.exe sniffer.cpp \
    imgui/imgui.cpp \
    imgui/imgui_draw.cpp \
    imgui/imgui_tables.cpp \
    imgui/imgui_widgets.cpp \
    imgui/imgui_demo.cpp \
    imgui/backends/imgui_impl_glfw.cpp \
    imgui/backends/imgui_impl_opengl3.cpp \
    -I"C:/Npcap-sdk/Include" \
    -L"C:/Npcap-sdk/Lib/x64" \
    -lwpcap -lws2_32 -lglfw3 -lopengl32 -lgdi32
```

O si cuentas con el archivo `compilar.bat`, ejecútalo directamente desde la terminal
MSYS2 UCRT64:

```bash
./compilar.bat
```

---

## Errores comunes

| Error | Causa | Solución |
|---|---|---|
| `pcap.h: No such file or directory` | Falta el Npcap SDK | Instala el SDK y verifica `-I"C:/Npcap-sdk/Include"` |
| `undefined reference to pcap_*` | Falta el flag de enlace | Añade `-lwpcap -L"C:/Npcap-sdk/Lib/x64"` |
| El `.exe` compila pero no abre adaptadores | Falta el runtime de Npcap | Instala Npcap con modo WinPcap compatible |
| `glfw3: not found` | GLFW no instalado | `pacman -S mingw-w64-ucrt-x86_64-glfw` |
| Pantalla negra al ejecutar | OpenGL 3.3 no soportado | Actualiza los drivers de tu tarjeta gráfica |
| Sin interfaces de red en la lista | Npcap no está en modo WinPcap | Reinstala Npcap activando la casilla correspondiente |
| No aparece `reporte_ids_*.txt` tras una alerta | Permisos de escritura en la carpeta del `.exe` | Ejecuta desde una carpeta donde el usuario tenga permiso de escritura, o como Administrador |

---

## Funcionalidades

- Captura de tráfico en tiempo real sobre cualquier adaptador de red disponible
- Disección de protocolos: Ethernet, IPv4, TCP, UDP, ICMP, ARP, IPv6
- Tabla de paquetes con colores por protocolo (esquema inspirado en Wireshark)
- Filtrado en tiempo real por IP origen, IP destino, puerto y protocolo
- Panel de detalle decodificado por capas
- Panel de volcado hexadecimal (Hex Dump)
- Exportación a CSV
- Toggle de tema oscuro / claro
- **IDS pasivo**: detección de ataques SYN Flood con alerta visual parpadeante,
  contador por ventana de tiempo configurable y botón de restablecimiento
- **Resaltado de IPs atacantes**: durante una alerta activa, las filas de la tabla
  cuyo origen acumula un número significativo de SYN se pintan en rojo, sustituyendo
  temporalmente el color de protocolo de esa fila
- **Reporte automático de incidentes**: al superarse el umbral de SYN, se genera de
  forma automática un archivo `.txt` con el detalle del evento y el ranking de IPs
  involucradas (ver sección siguiente)

---

## Detección de IPs atacantes en la tabla

Mientras el contador global de SYN de la ventana actual supera el umbral
(`SYN_UMBRAL`, 50 por defecto), la aplicación recorre, por cada fila visible,
el conteo individual de SYN asociado a la IP origen de ese paquete
(`g_syn_por_ip`). Si esa IP acumula más de la mitad del umbral configurado
(`SYN_UMBRAL / 2`, 25 por defecto) dentro de la ventana, la fila completa se
pinta con un fondo rojo (`RGBA 180, 30, 30, 120`), reemplazando el color de
fondo habitual por protocolo. Esto permite identificar a simple vista, dentro
del torrente de tráfico, qué orígenes son responsables del posible ataque sin
tener que aplicar manualmente un filtro de IP.

El resaltado es puramente visual y reversible: en cuanto el contador global
vuelve a estar por debajo del umbral (al iniciar una nueva ventana de muestreo
o tras pulsar **Restablecer**), las filas recuperan su color normal por
protocolo.

---

## Reporte automático de IDS

La primera vez que el contador de SYN de la ventana actual supera el umbral,
la aplicación genera automáticamente un archivo de texto plano con el nombre:

```
reporte_ids_<timestamp_unix>.txt
```

guardado en la carpeta donde se ejecuta `sniffer.exe`. El reporte se genera
una sola vez por evento de alerta: mientras el contador permanezca por encima
del umbral no se crean archivos adicionales; solo se generará un nuevo reporte
si la alerta se apaga (contador bajo el umbral) y vuelve a dispararse
posteriormente.

### Contenido del reporte

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

- **Timestamp (UNIX)**: momento exacto en que se generó el reporte.
- **SYN detectados**: valor del contador global en el instante de la alerta.
- **Umbral configurado / Ventana de muestreo**: valores de `SYN_UMBRAL` y
  `SYN_VENTANA_SEG` vigentes en esa compilación.
- **Ranking de IPs**: todas las IPs origen con al menos un SYN registrado en
  la ventana, ordenadas de mayor a menor conteo. Si no hay datos de IP
  disponibles (por ejemplo, tramas truncadas), se indica explícitamente.

> El reporte es una instantánea del momento de la alerta; no se actualiza
> después de su creación. Para un nuevo reporte, deja que la alerta se apague
> y se vuelva a disparar, o reinicia la aplicación y reproduce el escenario.

---

## Notas de seguridad

- La aplicación debe ejecutarse **como Administrador** en Windows.
- El IDS incluido es de carácter **educativo y pasivo**: detecta, resalta y
  reporta, pero no bloquea tráfico.
- Los archivos `reporte_ids_*.txt` quedan en texto plano sin cifrar en la
  carpeta del ejecutable; pueden contener direcciones IP de terceros. Trátalos
  con la misma confidencialidad que cualquier otro registro de red.
- La captura en modo promiscuo registra **todo el tráfico visible** en el segmento de
  red. Úsala únicamente en redes sobre las que tengas autorización explícita.
