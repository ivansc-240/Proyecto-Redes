# Packet Sniffer con IDS Pasivo
Herramienta de captura y análisis de tráfico de red en tiempo real con interfaz gráfica,
construida en C++17. Incluye un sistema primitivo de detección de intrusos (IDS) pasivo
capaz de identificar ataques de inundación SYN (SYN Flood / DoS).

---

## Arquitectura

El proyecto utiliza un modelo de **doble hilo**:

- **Hilo de Captura** — ejecuta `pcap_loop()` de Npcap de forma bloqueante y despacha
  cada frame a la función callback `manejador_paquete`.
- **Hilo de Renderizado (UI)** — hilo principal de la aplicación; dibuja la interfaz
  gráfica a 60 FPS usando Dear ImGui + GLFW3 + OpenGL 3.3 Core.
- Ambos hilos comparten un `std::vector<PaqueteCapturado>` protegido mediante
  `std::mutex` y `std::lock_guard`.

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

OpenGL viene incluido con los drivers de tu tarjeta gráfica. No requiere instalación
adicional en Windows. El paquete de MSYS2 que provee los headers es:

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

---

## Notas de seguridad

- La aplicación debe ejecutarse **como Administrador** en Windows.
- El IDS incluido es de carácter **educativo y pasivo**: detecta pero no bloquea tráfico.
- La captura en modo promiscuo registra **todo el tráfico visible** en el segmento de
  red. Úsala únicamente en redes sobre las que tengas autorización explícita.
