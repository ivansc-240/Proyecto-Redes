/*
 * sniffer_gui.cpp — Packet Sniffer con interfaz gráfica
 *
 * Arquitectura : Modelo de doble hilo (hilo de captura + hilo de renderizado/UI)
 * Capa de captura: Npcap / libpcap mediante pcap_loop()
 * Capa gráfica : Dear ImGui (rama master) + GLFW 3 + OpenGL 3.3 Core
 * Compilador   : g++ (MSYS2 UCRT64) — C++17
 *
 * Estructura del proyecto requerida:
 *   proyecto/
 *   ├── sniffer_gui.cpp
 *   ├── imgui/
 *   │   ├── imgui.h / imgui.cpp
 *   │   ├── imgui_demo.cpp
 *   │   ├── imgui_draw.cpp
 *   │   ├── imgui_tables.cpp
 *   │   ├── imgui_widgets.cpp
 *   │   ├── imgui_internal.h
 *   │   ├── imconfig.h
 *   │   ├── imstb_rectpack.h
 *   │   ├── imstb_textedit.h
 *   │   ├── imstb_truetype.h
 *   │   └── backends/
 *   │       ├── imgui_impl_glfw.h / imgui_impl_glfw.cpp
 *   │       └── imgui_impl_opengl3.h / imgui_impl_opengl3.cpp
 *   └── (Npcap SDK en C:/Npcap-sdk o instalado mediante MSYS2)
 */

// CABECERAS DE RED DE WINDOWS Y NPCAP
#ifdef _WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #include <windows.h>
#endif
#include <pcap.h>

//CABECERAS ESTÁNDAR DE C++
#include <iostream>
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <thread>
#include <mutex>
#include <atomic>
#include <cstring>
#include <cmath>
#include <algorithm>
#include <unordered_map>
#include <chrono>

// DECLARACIONES SELECTIVAS (Cero riesgo de colisión)
using std::string;
using std::vector;
using std::mutex;
using std::lock_guard;
using std::atomic;
using std::thread;
using std::ostringstream;
using std::ofstream;
using std::chrono::steady_clock;
using std::chrono::duration_cast;
using std::chrono::seconds;
using std::setw;
using std::setfill;
using std::hex;
using std::dec;
using std::fixed;
using std::setprecision;
using std::to_string;
using std::move;
using std::transform;
using std::unordered_map;

// Dear ImGui
#include "imgui/imgui.h"
#include "imgui/backends/imgui_impl_glfw.h"
#include "imgui/backends/imgui_impl_opengl3.h"

// GLFW + OpenGL
#include <GLFW/glfw3.h>


// Cabecera IEEE 802.3 de tamaño fijo (14 bytes). Campos en orden de red.
struct CabeceraEthernet {
    uint8_t  dst[6];
    uint8_t  src[6];
    uint16_t tipo;          // EtherType en orden de bytes de red
};

// Cabecera IPv4 según RFC 791 (mínimo 20 bytes). Longitud real derivada del nibble IHL.
struct CabeceraIPv4 {
    uint8_t  ver_ihl;       // Versión (4 bits) | Longitud de cabecera (4 bits)
    uint8_t  tos;
    uint16_t longitud_total;
    uint16_t id;
    uint16_t flags_frag;
    uint8_t  ttl;
    uint8_t  proto;         // Número de protocolo de capa de transporte (IANA)
    uint16_t checksum;
    uint32_t ip_origen;
    uint32_t ip_destino;
};

// Cabecera TCP según RFC 793 (mínimo 20 bytes). data_offset codifica la longitud en palabras de 32 bits.
struct CabeceraTCP {
    uint16_t puerto_origen;
    uint16_t puerto_destino;
    uint32_t seq;
    uint32_t ack;
    uint8_t  data_offset;   // Desplazamiento de datos (4 bits superiores), reservado (4 bits inferiores)
    uint8_t  flags;         // Bits de control: URG ACK PSH RST SYN FIN
    uint16_t ventana;
    uint16_t checksum;
    uint16_t urgente;
};

// Cabecera UDP según RFC 768 (fija, 8 bytes).
struct CabeceraUDP {
    uint16_t puerto_origen;
    uint16_t puerto_destino;
    uint16_t longitud;      // Longitud de cabecera más carga útil en bytes
    uint16_t checksum;
};

/*
 * PaqueteCapturado — unidad de almacenamiento para un frame capturado.
 *
 * Las instancias se construyen dentro de manejador_paquete() (hilo de captura)
 * y se insertan en g_paquetes bajo g_mutex_paquetes. El acceso posterior de
 * lectura ocurre en el hilo de renderizado, también bajo g_mutex_paquetes.
 * Ningún campo es modificado tras la inserción.
 */
struct PaqueteCapturado {
    int     numero;
    double  marca_tiempo;       // Segundos transcurridos desde el inicio de captura
    string  mac_origen;
    string  mac_destino;
    string  ip_origen;
    string  ip_destino;
    string  protocolo;          // Etiqueta de protocolo: TCP / UDP / ICMP / ARP / IPv6 / …
    int     puerto_origen  = 0;
    int     puerto_destino = 0;
    int     longitud;

    string          info_decodificada;  // Disección capa por capa (Panel 2)
    vector<uint8_t> datos_raw;          // Carga útil completa para el volcado hexadecimal (Panel 3)
};


// g_paquetes es la única estructura compartida entre el hilo de captura y el de renderizado.
// Toda escritura (push_back, clear) y toda lectura iterativa requieren g_mutex_paquetes.
mutex                    g_mutex_paquetes;
vector<PaqueteCapturado> g_paquetes;

// Bandera atómica que indica si la captura está activa. Escrita por el hilo de renderizado
// y leída por ambos hilos. El hilo de captura también la limpia ante errores o fin de bucle.
atomic<bool>             g_capturando{false};

// Número de secuencia monotónico de frames. Incrementado atómicamente en manejador_paquete().
atomic<int>              g_contador_paquetes{0};

// ── IDS Pasivo: SYN Flood ────────────────────────────────────────────
// Contador de paquetes TCP-SYN en la ventana de muestreo activa.
atomic<int>       g_syn_contador{0};

// Marca de tiempo UNIX (segundos) del inicio de la ventana actual.
atomic<long long> g_syn_ultimo_reset{0};

// Umbral: más de 50 SYN en 10 segundos dispara la alerta.
constexpr int     SYN_UMBRAL         = 50;
constexpr int     SYN_VENTANA_SEG    = 10;

// Mapa IP origen -> conteo de SYN. Protegido por g_mutex_syn.
// Separado de g_mutex_paquetes para no bloquear la tabla durante el conteo.
unordered_map<string, int> g_syn_por_ip;
mutex                      g_mutex_syn;

// Toggle de tema visual: true = oscuro, false = claro.
bool g_tema_oscuro = true;

// Handle de pcap propiedad del hilo de captura. El hilo de renderizado lo usa únicamente
// para llamar a pcap_breakloop() al detener. pcap_breakloop() es segura para señales y reentrante.
pcap_t*                  g_dispositivo_cap = nullptr;

// Época de referencia para marcas de tiempo relativas. Escrita antes de lanzar el hilo de captura.
double                   g_inicio_captura = 0.0;

// Interfaz de red disponible en el sistema.
struct InterfazRed {
    string nombre;       // Nombre de dispositivo pcap (ej. \Device\NPF_{GUID})
    string descripcion;  // Descripción legible del adaptador
};
vector<InterfazRed> g_interfaces;
int g_iface_seleccionada = 0;

// Índice en g_paquetes del paquete actualmente seleccionado; -1 significa ninguno.
int g_paquete_seleccionado = -1;


/*
 * EstadoFiltros — configuración de filtros, exclusiva del hilo de renderizado.
 *
 * Se aplica de forma diferida durante la iteración de la tabla mientras se
 * mantiene g_mutex_paquetes. Modificar los filtros no invalida g_paquetes;
 * el efecto es visible en el siguiente frame renderizado.
 *
 * proto_items[0] = "Todos" deshabilita el filtrado por protocolo.
 */
struct EstadoFiltros {
    char ip_origen[64]  = {};
    char ip_destino[64] = {};
    char puerto[16]     = {};

    static constexpr const char* proto_items[] = {
        "Todos", "TCP", "UDP", "ICMP", "ARP", "IPv6"
    };
    int idx_proto = 0;  // Índice en proto_items; 0 = sin filtro de protocolo
};
static EstadoFiltros g_filtros;
// Definición fuera de clase requerida para conformidad de enlace en pre-C++17.
constexpr const char* EstadoFiltros::proto_items[];

// Manejadores de fuentes de ImGui.
ImFont* g_fuente_ui   = nullptr;  // Segoe UI 18 pt — elementos generales de interfaz
ImFont* g_fuente_mono = nullptr;  // Consolas 16 pt — panel Hex Dump (monoespaciada)


// Formatea una dirección MAC de 6 bytes como pares hexadecimales en mayúsculas separados por ':'.
static string mac_a_cadena(const uint8_t* mac) {
    char buf[18];
    snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return buf;
}

// Convierte una dirección IPv4 de 32 bits en orden de red a notación decimal con puntos.
static string ip_a_cadena(uint32_t ip_red) {
    struct in_addr addr;
    addr.s_addr = ip_red;
    char buf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &addr, buf, sizeof(buf));
    return buf;
}

/*
 * volcado_hex — genera un volcado hexadecimal/ASCII formateado de un buffer de bytes.
 *
 * Formato de salida: 16 bytes por línea, compuestos por:
 *   <offset 4 dígitos hex>  <octetos hex separados por espacio, hueco central en byte 8>  |<ASCII>|
 * Los bytes no imprimibles (< 0x20 o >= 0x7F) se sustituyen por '.'.
 */
static string volcado_hex(const uint8_t* datos, int longitud) {
    ostringstream oss;
    for (int i = 0; i < longitud; i += 16) {
        oss << setw(4) << setfill('0') << hex << i << "  ";
        for (int j = 0; j < 16; ++j) {
            if (i + j < longitud)
                oss << setw(2) << setfill('0') << hex << (int)datos[i + j] << " ";
            else
                oss << "   ";
            if (j == 7) oss << " ";  // Hueco central tras el byte 8
        }
        oss << " |";
        for (int j = 0; j < 16 && i + j < longitud; ++j) {
            uint8_t c = datos[i + j];
            oss << (char)(c >= 32 && c < 127 ? c : '.');
        }
        oss << "|\n";
    }
    return oss.str();
}


/*
 * manejador_paquete — callback de pcap invocado por pcap_loop() en cada frame capturado.
 *
 * Contexto de ejecución: hilo de captura.
 * Seguridad de hilos: g_mutex_paquetes se adquiere una sola vez por invocación,
 * al momento de push_back, para minimizar la contención con el hilo de renderizado.
 * Toda la disección se realiza antes de tomar el lock.
 *
 * La disección avanza de arriba hacia abajo por la pila de protocolos:
 *   Capa 2 (Ethernet) → Capa 3 (IPv4 / ARP / IPv6) → Capa 4 (TCP / UDP / ICMP)
 * Los frames truncados que no pueden satisfacer el tamaño mínimo de cabecera para
 * una capa dada se clasifican en la última capa analizada correctamente.
 */
void manejador_paquete(u_char* /*user*/, const struct pcap_pkthdr* pkthdr, const u_char* paquete) {
    if (!g_capturando) return;

    PaqueteCapturado pkt;
    pkt.numero       = ++g_contador_paquetes;
    pkt.marca_tiempo = pkthdr->ts.tv_sec + pkthdr->ts.tv_usec * 1e-6 - g_inicio_captura;
    pkt.longitud     = pkthdr->len;
    pkt.datos_raw.assign(paquete, paquete + pkthdr->caplen);

    ostringstream decodificado;

    // Capa 2: Ethernet
    if (pkthdr->caplen < sizeof(CabeceraEthernet)) {
        pkt.protocolo         = "Ethernet (truncado)";
        pkt.mac_origen        = "??:??:??:??:??:??";
        pkt.mac_destino       = "??:??:??:??:??:??";
        pkt.info_decodificada = "Trama demasiado corta para cabecera Ethernet.";
        lock_guard<mutex> lk(g_mutex_paquetes);
        g_paquetes.push_back(move(pkt));
        return;
    }

    const CabeceraEthernet* eth = reinterpret_cast<const CabeceraEthernet*>(paquete);
    pkt.mac_origen  = mac_a_cadena(eth->src);
    pkt.mac_destino = mac_a_cadena(eth->dst);
    uint16_t tipo_eth = ntohs(eth->tipo);

    decodificado << "[Ethernet]\n";
    decodificado << "  MAC Origen : " << pkt.mac_origen  << "\n";
    decodificado << "  MAC Destino: " << pkt.mac_destino << "\n";
    decodificado << "  EtherType  : 0x" << hex << setw(4) << setfill('0') << tipo_eth << dec << "\n";

    // Capa 3
    const uint8_t* l3     = paquete + sizeof(CabeceraEthernet);
    int            lon_l3 = (int)pkthdr->caplen - (int)sizeof(CabeceraEthernet);

    if (tipo_eth == 0x0800 && lon_l3 >= (int)sizeof(CabeceraIPv4)) {
        // IPv4 — RFC 791
        const CabeceraIPv4* ip  = reinterpret_cast<const CabeceraIPv4*>(l3);
        int                 ihl = (ip->ver_ihl & 0x0F) * 4;  // Longitud de cabecera en bytes
        pkt.ip_origen  = ip_a_cadena(ip->ip_origen);
        pkt.ip_destino = ip_a_cadena(ip->ip_destino);

        decodificado << "\n[IPv4]\n";
        decodificado << "  IP Origen : " << pkt.ip_origen  << "\n";
        decodificado << "  IP Destino: " << pkt.ip_destino << "\n";
        decodificado << "  TTL       : " << (int)ip->ttl   << "\n";
        decodificado << "  Protocolo : " << (int)ip->proto << "\n";
        decodificado << "  Total     : " << ntohs(ip->longitud_total) << " bytes\n";

        const uint8_t* l4     = l3 + ihl;
        int            lon_l4 = lon_l3 - ihl;        

        if (ip->proto == 6 && lon_l4 >= (int)sizeof(CabeceraTCP)) {
            // TCP — RFC 793
            const CabeceraTCP* tcp = reinterpret_cast<const CabeceraTCP*>(l4);
            pkt.puerto_origen  = ntohs(tcp->puerto_origen);
            pkt.puerto_destino = ntohs(tcp->puerto_destino);
            pkt.protocolo      = "TCP";

            uint8_t f = tcp->flags;
            string  flags_str;
            if (f & 0x02) flags_str += "SYN ";
            if (f & 0x02) g_syn_contador.fetch_add(1, std::memory_order_relaxed);
            if (f & 0x02) {
                lock_guard<mutex> lk_syn(g_mutex_syn);
                g_syn_por_ip[pkt.ip_origen]++;
            }
            if (f & 0x10) flags_str += "ACK ";
            if (f & 0x01) flags_str += "FIN ";
            if (f & 0x04) flags_str += "RST ";
            if (f & 0x08) flags_str += "PSH ";
            if (f & 0x20) flags_str += "URG ";
            

            decodificado << "\n[TCP]\n";
            decodificado << "  Puerto Origen : " << pkt.puerto_origen  << "\n";
            decodificado << "  Puerto Destino: " << pkt.puerto_destino << "\n";
            decodificado << "  Seq           : " << ntohl(tcp->seq)    << "\n";
            decodificado << "  Ack           : " << ntohl(tcp->ack)    << "\n";
            decodificado << "  Flags         : " << (flags_str.empty() ? "(ninguno)" : flags_str) << "\n";
            decodificado << "  Ventana       : " << ntohs(tcp->ventana) << "\n";

        } else if (ip->proto == 17 && lon_l4 >= (int)sizeof(CabeceraUDP)) {
            // UDP — RFC 768
            const CabeceraUDP* udp = reinterpret_cast<const CabeceraUDP*>(l4);
            pkt.puerto_origen  = ntohs(udp->puerto_origen);
            pkt.puerto_destino = ntohs(udp->puerto_destino);
            pkt.protocolo      = "UDP";

            decodificado << "\n[UDP]\n";
            decodificado << "  Puerto Origen : " << pkt.puerto_origen  << "\n";
            decodificado << "  Puerto Destino: " << pkt.puerto_destino << "\n";
            decodificado << "  Longitud      : " << ntohs(udp->longitud) << "\n";

        } else if (ip->proto == 1) {
            // ICMP — RFC 792
            pkt.protocolo = "ICMP";
            decodificado << "\n[ICMP]\n";
        } else {
            pkt.protocolo = "IPv4/Proto=" + to_string(ip->proto);
        }

    } else if (tipo_eth == 0x0806) {
        pkt.protocolo = "ARP";
        decodificado << "\n[ARP]\n";
    } else if (tipo_eth == 0x86DD) {
        pkt.protocolo = "IPv6";
        decodificado << "\n[IPv6]\n";
    } else {
        pkt.protocolo = "Ethernet/0x" + [&] {
            ostringstream s;
            s << hex << setw(4) << setfill('0') << tipo_eth;
            return s.str();
        }();
    }

    pkt.info_decodificada = decodificado.str();

    // Sección crítica: inserción en el contenedor compartido.
    lock_guard<mutex> lk(g_mutex_paquetes);
    g_paquetes.push_back(move(pkt));
}

/*
 * hilo_captura_func — punto de entrada del hilo de captura.
 *
 * Abre el adaptador de red seleccionado en modo promiscuo con un timeout de
 * lectura de 100 ms (granularidad suficiente para la respuesta de pcap_breakloop()).
 * Delega la entrega de paquetes a manejador_paquete() mediante pcap_loop().
 *
 * Terminación: el hilo de renderizado establece g_capturando = false y llama a
 * pcap_breakloop(g_dispositivo_cap), lo que provoca que pcap_loop() retorne con
 * PCAP_ERROR_BREAK. El hilo cierra el handle y finaliza limpiamente.
 */
void hilo_captura_func(const string& nombre_iface) {
    char errbuf[PCAP_ERRBUF_SIZE];

    g_dispositivo_cap = pcap_open_live(
        nombre_iface.c_str(),
        65535,  // snaplen: captura frames completos
        1,      // promisc: activa modo promiscuo
        100,    // to_ms: timeout de lectura (ms); controla la latencia de pcap_breakloop()
        errbuf);

    if (!g_dispositivo_cap) {
        g_capturando = false;
        return;
    }

    // Bucle de despacho bloqueante; finaliza con pcap_breakloop() o error interno.
    pcap_loop(g_dispositivo_cap, -1, manejador_paquete, nullptr);

    pcap_close(g_dispositivo_cap);
    g_dispositivo_cap = nullptr;
    g_capturando      = false;
}


// Enumera los adaptadores de red disponibles mediante pcap_findalldevs() y
// rellena g_interfaces. Se invoca al iniciar y desde el botón "Recargar interfaces".
static void cargar_interfaces() {
    g_interfaces.clear();
    char       errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* todos = nullptr;

    if (pcap_findalldevs(&todos, errbuf) == -1) return;

    for (pcap_if_t* d = todos; d != nullptr; d = d->next) {
        InterfazRed ni;
        ni.nombre      = d->name        ? d->name        : "";
        ni.descripcion = d->description ? d->description : "(sin descripción)";
        g_interfaces.push_back(ni);
    }
    pcap_freealldevs(todos);
}


// Devuelve el color RGBA asociado a una etiqueta de protocolo para el fondo de
// fila y resaltado de texto, siguiendo el esquema cromático de Wireshark.
// Retorna gris neutro para protocolos no reconocidos.
static ImVec4 color_protocolo(const string& proto) {
    if (proto == "TCP")  return ImVec4(0.68f, 0.85f, 1.00f, 1.0f);  // Azul claro
    if (proto == "UDP")  return ImVec4(0.68f, 1.00f, 0.68f, 1.0f);  // Verde claro
    if (proto == "ICMP") return ImVec4(1.00f, 0.95f, 0.60f, 1.0f);  // Amarillo
    if (proto == "ARP")  return ImVec4(1.00f, 0.80f, 0.60f, 1.0f);  // Naranja
    if (proto == "IPv6") return ImVec4(0.85f, 0.75f, 1.00f, 1.0f);  // Lila
    return ImVec4(0.85f, 0.85f, 0.85f, 1.0f);                        // Gris neutro
}


// Búsqueda insensible a mayúsculas/minúsculas. Retorna verdadero si 'haystack'
// contiene 'aguja', o si 'aguja' está vacía (coincidencia vacua = sin filtro activo).
static bool icontiene(const string& haystack, const char* aguja) {
    if (!aguja || aguja[0] == '\0') return true;
    string h = haystack, n = aguja;
    transform(h.begin(), h.end(), h.begin(), ::tolower);
    transform(n.begin(), n.end(), n.begin(), ::tolower);
    return h.find(n) != string::npos;
}

/*
 * paquete_cumple_filtros — evalúa todos los predicados activos de EstadoFiltros
 * contra un PaqueteCapturado.
 *
 * Contexto de ejecución: hilo de renderizado, llamado mientras se mantiene g_mutex_paquetes.
 * Orden de evaluación: IP Origen → IP Destino → Puerto → Protocolo.
 * Cortocircuito: retorna falso en el primer predicado fallido.
 *
 * Filtro de puerto: coincide si el valor numérico es igual a puerto_origen o puerto_destino.
 * Filtro de protocolo: desactivado cuando idx_proto == 0 ("Todos"); de lo contrario realiza
 * búsqueda insensible a mayúsculas contra PaqueteCapturado::protocolo.
 */
static bool paquete_cumple_filtros(const PaqueteCapturado& p) {
    if (!icontiene(p.ip_origen,  g_filtros.ip_origen))  return false;
    if (!icontiene(p.ip_destino, g_filtros.ip_destino)) return false;

    if (g_filtros.puerto[0] != '\0') {
        int filtro_puerto = atoi(g_filtros.puerto);
        if (filtro_puerto > 0 && p.puerto_origen != filtro_puerto && p.puerto_destino != filtro_puerto)
            return false;
    }

    if (g_filtros.idx_proto > 0) {
        const char* buscado = EstadoFiltros::proto_items[g_filtros.idx_proto];
        if (!icontiene(p.protocolo, buscado)) return false;
    }

    return true;
}

/*
 * exportar_csv — serializa la lista de paquetes filtrados a un archivo de
 * valores separados por comas en la ruta indicada.
 *
 * Contexto de ejecución: hilo de renderizado; adquiere g_mutex_paquetes internamente.
 * Solo se escriben los paquetes que satisfacen paquete_cumple_filtros() en el
 * momento de la exportación.
 */
static void exportar_csv(const string& ruta) {
    ofstream f(ruta);
    if (!f.is_open()) return;

    f << "#,Tiempo,IP Origen,IP Destino,Protocolo,Puerto Origen,Puerto Destino,Longitud\n";

    lock_guard<mutex> lk(g_mutex_paquetes);
    int fila = 1;
    for (const auto& p : g_paquetes) {
        if (!paquete_cumple_filtros(p)) continue;
        f << fila++         << ","
          << fixed << setprecision(6) << p.marca_tiempo << ","
          << p.ip_origen    << ","
          << p.ip_destino   << ","
          << p.protocolo    << ","
          << p.puerto_origen  << ","
          << p.puerto_destino << ","
          << p.longitud       << "\n";
    }
}


/*
 * renderizar_tabla_paquetes — renderiza el Panel 1 (superior, ancho completo).
 *
 * Contiene:
 *   - Barra de estado: contador total de paquetes capturados y botón "Limpiar lista".
 *   - Barra de filtros: campos InputText para IP Origen, IP Destino, Puerto;
 *     Combo para selección de protocolo; botón "Exportar CSV".
 *   - Tabla ImGui de 9 columnas con color de fondo por protocolo.
 *
 * Lógica de filtrado: paquete_cumple_filtros() se evalúa por fila bajo g_mutex_paquetes;
 * las filas no coincidentes se omiten con continue, sin modificar g_paquetes.
 *
 * Desplazamiento automático: cuando la captura está activa y el viewport está al
 * (o cerca del) fondo del scroll, SetScrollHereY(1.0f) mantiene visible el paquete más reciente.
 */
static void renderizar_tabla_paquetes(ImVec2 tamanio) {
    ImGui::BeginChild("PacketTable", tamanio, true);

    // Barra de estado
    ImGui::PushStyleColor(ImGuiCol_Text,
    g_tema_oscuro ? ImVec4(0.9f, 0.9f, 0.9f, 1.0f)   // gris claro sobre oscuro
                  : ImVec4(0.1f, 0.1f, 0.1f, 1.0f));  // gris oscuro sobre claro
    ImGui::Text("  Paquetes capturados: %d", g_contador_paquetes.load());
    ImGui::PopStyleColor();

    ImGui::SameLine(tamanio.x - 90);
    if (ImGui::SmallButton("Limpiar lista")) {
        lock_guard<mutex> lk(g_mutex_paquetes);
        g_paquetes.clear();
        g_contador_paquetes    = 0;
        g_paquete_seleccionado = -1;
    }

    // Barra de filtros
    ImGui::PushStyleColor(ImGuiCol_FrameBg,
    g_tema_oscuro ? ImVec4(0.15f, 0.15f, 0.18f, 1.0f)    // oscuro
                  : ImVec4(0.88f, 0.88f, 0.92f, 1.0f));  // claro

    ImGui::SetNextItemWidth(130);
    ImGui::InputText("##f_ip_origen", g_filtros.ip_origen, sizeof(g_filtros.ip_origen));
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("Filtrar por IP Origen");
    ImGui::SameLine();
    ImGui::TextDisabled("IP Origen");

    ImGui::SameLine(0, 12);
    ImGui::SetNextItemWidth(130);
    ImGui::InputText("##f_ip_destino", g_filtros.ip_destino, sizeof(g_filtros.ip_destino));
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("Filtrar por IP Destino");
    ImGui::SameLine();
    ImGui::TextDisabled("IP Destino");

    ImGui::SameLine(0, 12);
    ImGui::SetNextItemWidth(70);
    ImGui::InputText("##f_puerto", g_filtros.puerto, sizeof(g_filtros.puerto),
                     ImGuiInputTextFlags_CharsDecimal);
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("Filtrar por Puerto (origen o destino)");
    ImGui::SameLine();
    ImGui::TextDisabled("Puerto");

    ImGui::SameLine(0, 12);
    ImGui::SetNextItemWidth(90);
    ImGui::Combo("##f_proto", &g_filtros.idx_proto,
                 EstadoFiltros::proto_items,
                 IM_ARRAYSIZE(EstadoFiltros::proto_items));
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("Filtrar por Protocolo");

    ImGui::PopStyleColor();

    // Botón Exportar CSV
    ImGui::SameLine(0, 16);
    ImGui::PushStyleColor(ImGuiCol_Button, g_tema_oscuro ? ImVec4(0.15f, 0.40f, 0.15f, 1.0f) : ImVec4(0.20f, 0.60f, 0.20f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, g_tema_oscuro ? ImVec4(0.20f, 0.55f, 0.20f, 1.0f) : ImVec4(0.25f, 0.72f, 0.25f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_ButtonActive, g_tema_oscuro ? ImVec4(0.10f, 0.45f, 0.10f, 1.0f) : ImVec4(0.15f, 0.55f, 0.15f, 1.0f));
    if (ImGui::Button("Exportar CSV")) {
        ostringstream nombre_archivo;
        nombre_archivo << "captura_" << (int)glfwGetTime() << ".csv";
        exportar_csv(nombre_archivo.str());
        ImGui::SetTooltip("Guardado: %s", nombre_archivo.str().c_str());
    }
    ImGui::PopStyleColor(3);

    ImGui::Separator();

    // Tabla principal de paquetes
    static ImGuiTableFlags flags_tabla =
        ImGuiTableFlags_BordersInnerV   |
        ImGuiTableFlags_BordersOuterH   |
        ImGuiTableFlags_RowBg           |
        ImGuiTableFlags_ScrollY         |
        ImGuiTableFlags_Resizable       |
        ImGuiTableFlags_SizingStretchSame;

    if (ImGui::BeginTable("pkttable", 9, flags_tabla)) {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("#",               ImGuiTableColumnFlags_WidthFixed,   45);
        ImGui::TableSetupColumn("Tiempo (s)",      ImGuiTableColumnFlags_WidthFixed,   75);
        ImGui::TableSetupColumn("IP Origen",       ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("IP Destino",      ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("MAC Origen",      ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("MAC Destino",     ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("Protocolo",       ImGuiTableColumnFlags_WidthFixed,   70);
        ImGui::TableSetupColumn("Puerto",          ImGuiTableColumnFlags_WidthFixed,   75);
        ImGui::TableSetupColumn("Bytes",           ImGuiTableColumnFlags_WidthFixed,   55);
        ImGui::TableHeadersRow();

        // Se mantiene el lock durante toda la iteración; paquete_cumple_filtros() también
        // se invoca bajo este lock al acceder a los elementos de g_paquetes por referencia.
        lock_guard<mutex> lk(g_mutex_paquetes);
        for (int i = 0; i < (int)g_paquetes.size(); ++i) {
            const auto& p = g_paquetes[i];

            // Filtro visual: omite filas que no satisfacen todos los predicados activos.
            if (!paquete_cumple_filtros(p)) continue;

            ImGui::TableNextRow();

            // ── IDS: Color de fondo rojo para IPs atacantes, protocolo para el resto ──
            bool es_atacante = false;
            if (g_syn_contador.load(std::memory_order_relaxed) > SYN_UMBRAL
                && !p.ip_origen.empty()) {
                lock_guard<mutex> lk_syn(g_mutex_syn);
                auto it = g_syn_por_ip.find(p.ip_origen);
                if (it != g_syn_por_ip.end() && it->second > (SYN_UMBRAL / 2))
                    es_atacante = true;
            }

            if (es_atacante) {
                ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0,
                    IM_COL32(180, 30, 30, 120));
            } else {
                ImVec4 col_fila = color_protocolo(p.protocolo);
                ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0,
                    ImGui::ColorConvertFloat4ToU32(
                        ImVec4(col_fila.x, col_fila.y, col_fila.z, 0.35f)));
            }

            ImGui::TableSetColumnIndex(0);
            char etiq_sel[32];
            snprintf(etiq_sel, sizeof(etiq_sel), "%d##row%d", p.numero, i);
            bool es_sel = (g_paquete_seleccionado == i);
            if (ImGui::Selectable(etiq_sel, es_sel,
                ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowOverlap,
                ImVec2(0, 0)))
            {
                g_paquete_seleccionado = i;
            }

            ImGui::TableSetColumnIndex(1);  ImGui::Text("%.4f", p.marca_tiempo);
            ImGui::TableSetColumnIndex(2);  ImGui::TextUnformatted(p.ip_origen.empty()  ? "-" : p.ip_origen.c_str());
            ImGui::TableSetColumnIndex(3);  ImGui::TextUnformatted(p.ip_destino.empty() ? "-" : p.ip_destino.c_str());
            ImGui::TableSetColumnIndex(4);  ImGui::TextUnformatted(p.mac_origen.c_str());
            ImGui::TableSetColumnIndex(5);  ImGui::TextUnformatted(p.mac_destino.c_str());

            ImGui::TableSetColumnIndex(6);
            ImGui::PushStyleColor(ImGuiCol_Text, color_protocolo(p.protocolo));
            ImGui::TextUnformatted(p.protocolo.c_str());
            ImGui::PopStyleColor();

            ImGui::TableSetColumnIndex(7);
            if (p.puerto_origen || p.puerto_destino)
                ImGui::Text("%d -> %d", p.puerto_origen, p.puerto_destino);
            else
                ImGui::TextUnformatted("-");

            ImGui::TableSetColumnIndex(8);  ImGui::Text("%d", p.longitud);
        }

        // Desplazamiento automático: avanza el viewport al fondo cuando llegan nuevos
        // paquetes durante la captura activa y el usuario no ha desplazado manualmente hacia arriba.
        if (g_capturando && ImGui::GetScrollY() >= ImGui::GetScrollMaxY() - 20)
            ImGui::SetScrollHereY(1.0f);

        ImGui::EndTable();
    }
    ImGui::EndChild();
}

/*
 * renderizar_panel_decodificado — renderiza el Panel 2 (inferior izquierdo).
 *
 * Muestra la disección de protocolo legible (PaqueteCapturado::info_decodificada)
 * para el paquete actualmente seleccionado. Adquiere g_mutex_paquetes durante la
 * lectura para protegerse de push_back() concurrentes en el hilo de captura.
 */
static void renderizar_panel_decodificado(ImVec2 tamanio) {
    ImGui::BeginChild("DetallePanel", tamanio, true);
    ImGui::TextColored(ImVec4(0.4f, 0.9f, 0.6f, 1.0f), "Detalle del paquete");
    ImGui::Separator();

    lock_guard<mutex> lk(g_mutex_paquetes);
    if (g_paquete_seleccionado >= 0 && g_paquete_seleccionado < (int)g_paquetes.size()) {
        const auto& p = g_paquetes[g_paquete_seleccionado];
        ImGui::TextColored(ImVec4(0.8f, 0.8f, 0.3f, 1.0f),
            "Paquete #%d  |  %d bytes  |  %.4f s",
            p.numero, p.longitud, p.marca_tiempo);
        ImGui::Separator();
        ImGui::TextUnformatted(p.info_decodificada.c_str());
    } else {
        ImGui::TextDisabled("(Selecciona un paquete en la tabla)");
    }
    ImGui::EndChild();
}

/*
 * renderizar_panel_hex — renderiza el Panel 3 (inferior derecho).
 *
 * Produce un volcado_hex() de los bytes raw del paquete seleccionado y lo muestra
 * en un widget InputText multilínea de solo lectura usando la fuente monoespaciada
 * (g_fuente_mono). Adquiere g_mutex_paquetes para la lectura.
 */
static void renderizar_panel_hex(ImVec2 tamanio) {
    ImGui::BeginChild("HexPanel", tamanio, true);
    ImGui::TextColored(ImVec4(0.4f, 0.7f, 1.0f, 1.0f), "Hex Dump");
    ImGui::Separator();

    lock_guard<mutex> lk(g_mutex_paquetes);
    if (g_paquete_seleccionado >= 0 && g_paquete_seleccionado < (int)g_paquetes.size()) {
        const auto& p = g_paquetes[g_paquete_seleccionado];
        if (!p.datos_raw.empty()) {
            string dump = volcado_hex(p.datos_raw.data(), (int)p.datos_raw.size());
            ImGui::PushFont(g_fuente_mono ? g_fuente_mono : ImGui::GetIO().Fonts->Fonts[0]);
            ImGui::InputTextMultiline("##hexdump",
                const_cast<char*>(dump.c_str()), dump.size() + 1,
                ImVec2(-1, -1),
                ImGuiInputTextFlags_ReadOnly);
            ImGui::PopFont();
        }
    } else {
        ImGui::TextDisabled("(Selecciona un paquete en la tabla)");
    }
    ImGui::EndChild();
}


// Manejador de errores de GLFW registrado mediante glfwSetErrorCallback().
static void callback_error_glfw(int error, const char* desc) {
    fprintf(stderr, "GLFW Error %d: %s\n", error, desc);
}

// Genera un reporte .txt del evento de SYN Flood detectado.
// Incluye timestamp, conteo total, umbral y ranking de IPs atacantes.
// Se llama automaticamente cuando el contador supera el umbral por primera vez.
static void generar_reporte_ids() {
    // Nombre de archivo con timestamp para no sobreescribir reportes anteriores
    long long ahora = duration_cast<seconds>(
        steady_clock::now().time_since_epoch()).count();
    string ruta = "reporte_ids_" + to_string(ahora) + ".txt";

    ofstream f(ruta);
    if (!f.is_open()) return;

    // Encabezado
    f << "========================================================\n";
    f << "   REPORTE DE ALERTA IDS - POSIBLE ATAQUE SYN FLOOD\n";
    f << "========================================================\n\n";
    f << "Timestamp (UNIX) : " << ahora << "\n";
    f << "SYN detectados   : " << g_syn_contador.load(std::memory_order_relaxed) << "\n";
    f << "Umbral configurado: " << SYN_UMBRAL << "\n";
    f << "Ventana de muestreo: " << SYN_VENTANA_SEG << " segundos\n\n";

    // Ranking de IPs atacantes
    f << "--------------------------------------------------------\n";
    f << "  RANKING DE IPs POR CONTEO DE PAQUETES SYN\n";
    f << "--------------------------------------------------------\n";

    // Copiar el mapa a un vector para ordenarlo sin mantener el lock
    vector<std::pair<string, int>> ranking;
    {
        lock_guard<mutex> lk_syn(g_mutex_syn);
        ranking.assign(g_syn_por_ip.begin(), g_syn_por_ip.end());
    }

    // Ordenar de mayor a menor conteo
    std::sort(ranking.begin(), ranking.end(),
        [](const auto& a, const auto& b){ return a.second > b.second; });

    if (ranking.empty()) {
        f << "  (Sin datos de IP disponibles)\n";
    } else {
        int pos = 1;
        for (const auto& par : ranking) {
            f << "  " << pos++ << ". " << par.first
              << "  ->  " << par.second << " paquetes SYN\n";
        }
    }
}

// Aplica el tema oscuro o claro con los ajustes de color del proyecto.
// Llamar cada vez que g_tema_oscuro cambie.
static void aplicar_tema(bool oscuro) {
    if (oscuro) {
        ImGui::StyleColorsDark();
        ImGuiStyle& e = ImGui::GetStyle();
        e.Colors[ImGuiCol_WindowBg]      = ImVec4(0.10f, 0.10f, 0.12f, 1.0f);
        e.Colors[ImGuiCol_Header]        = ImVec4(0.20f, 0.40f, 0.60f, 0.6f);
        e.Colors[ImGuiCol_HeaderHovered] = ImVec4(0.25f, 0.50f, 0.75f, 0.8f);
        e.Colors[ImGuiCol_HeaderActive]  = ImVec4(0.30f, 0.55f, 0.80f, 1.0f);
    } else {
        ImGui::StyleColorsLight();
        ImGuiStyle& e = ImGui::GetStyle();
        e.Colors[ImGuiCol_WindowBg]      = ImVec4(0.94f, 0.94f, 0.96f, 1.0f);
        e.Colors[ImGuiCol_Header]        = ImVec4(0.50f, 0.70f, 0.90f, 0.6f);
        e.Colors[ImGuiCol_HeaderHovered] = ImVec4(0.40f, 0.65f, 0.88f, 0.8f);
        e.Colors[ImGuiCol_HeaderActive]  = ImVec4(0.30f, 0.55f, 0.80f, 1.0f);
    }
    // Preserva los radios de esquina del proyecto en ambos temas.
    ImGuiStyle& e = ImGui::GetStyle();
    e.WindowRounding    = 4.0f;
    e.FrameRounding     = 3.0f;
    e.ScrollbarRounding = 3.0f;
}

/*
 * main — inicializa la capa de plataforma (WinSock2, GLFW, OpenGL 3.3 Core),
 * configura Dear ImGui, carga fuentes y ejecuta el bucle de renderizado.
 *
 * Resumen del bucle de renderizado:
 *   1. glfwPollEvents() — procesa eventos del sistema operativo y la ventana.
 *   2. ImGui NewFrame — inicia la construcción del frame.
 *   3. Ventana host de pantalla completa con disposición manual de ChildWindows.
 *   4. Barra de menú: selector de interfaz, botones Iniciar/Detener, recarga.
 *   5. Disposición de paneles: renderizar_tabla_paquetes (50% de alto), luego
 *      renderizar_panel_decodificado + renderizar_panel_hex en paralelo (50% de alto).
 *   6. ImGui::Render() + ImGui_ImplOpenGL3_RenderDrawData() — envío a GPU.
 *   7. glfwSwapBuffers() — presentación en pantalla.
 *
 * Secuencia de apagado:
 *   Señaliza al hilo de captura con g_capturando = false + pcap_breakloop(),
 *   lo une y destruye los recursos de ImGui y GLFW en orden de dependencia.
 */

int main() {
#ifdef _WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
#endif

    cargar_interfaces();

    // Inicialización de GLFW
    glfwSetErrorCallback(callback_error_glfw);
    if (!glfwInit()) return 1;

    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 3);
    glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE);

    GLFWwindow* ventana = glfwCreateWindow(1280, 800, "Packet Sniffer — GUI", nullptr, nullptr);
    if (!ventana) { glfwTerminate(); return 1; }

    glfwMakeContextCurrent(ventana);
    glfwSwapInterval(1);  // Sincronización vertical

    // Inicialización de Dear ImGui
    IMGUI_CHECKVERSION();
    ImGui::CreateContext();

    ImGuiIO& io = ImGui::GetIO();
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
    // Nota: ImGuiConfigFlags_DockingEnable solo está disponible en la rama docking.
    // Se usa disposición manual con ChildWindows para compatibilidad con la rama master.

    // Tema inicial: oscuro.
    aplicar_tema(g_tema_oscuro);

    ImGui_ImplGlfw_InitForOpenGL(ventana, true);
    ImGui_ImplOpenGL3_Init("#version 330");

    // Carga de fuentes: deben añadirse al atlas antes de la primera llamada a NewFrame().
    // Si los archivos TTF no están disponibles, las variables de fuente apuntan a Fonts[0].
    {
        ImGuiIO& io_fuentes = ImGui::GetIO();

        // Fuente de interfaz: Segoe UI 18 pt — proporcional, para todos los widgets generales.
        g_fuente_ui = io_fuentes.Fonts->AddFontFromFileTTF(
            "C:/Windows/Fonts/segoeui.ttf", 18.0f);
        if (!g_fuente_ui)
            g_fuente_ui = io_fuentes.Fonts->Fonts[0];

        // Fuente monoespaciada: Consolas 16 pt — usada exclusivamente en el panel Hex Dump.
        g_fuente_mono = io_fuentes.Fonts->AddFontFromFileTTF(
            "C:/Windows/Fonts/consola.ttf", 16.0f);
        if (!g_fuente_mono)
            g_fuente_mono = io_fuentes.Fonts->Fonts[0];

        // Construye el atlas de texturas en GPU. Debe completarse antes de la primera llamada
        // a CreateFontsTexture() o antes del primer uso del renderer.
        io_fuentes.Fonts->Build();
    }

    // Hilo de captura declarado aquí; se lanza condicionalmente al presionar el botón.
    thread hilo_captura;

    // Bucle principal de renderizado
    while (!glfwWindowShouldClose(ventana)) {
        glfwPollEvents();

        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();

        // Se activa la fuente de interfaz para todo el frame; se desactiva tras la ventana host.
        if (g_fuente_ui) ImGui::PushFont(g_fuente_ui);

        // Ventana host de pantalla completa (sin barra de título ni decoraciones)
        {
            ImGuiViewport* vp = ImGui::GetMainViewport();
            ImGui::SetNextWindowPos(vp->Pos);
            ImGui::SetNextWindowSize(vp->Size);
            ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding,  0.0f);
            ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0.0f);
            ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding,   ImVec2(6, 6));

            ImGuiWindowFlags flags_host =
                ImGuiWindowFlags_NoTitleBar            |
                ImGuiWindowFlags_NoCollapse            |
                ImGuiWindowFlags_NoResize              |
                ImGuiWindowFlags_NoMove                |
                ImGuiWindowFlags_NoBringToFrontOnFocus |
                ImGuiWindowFlags_NoNavFocus            |
                ImGuiWindowFlags_NoScrollbar           |
                ImGuiWindowFlags_NoScrollWithMouse     |
                ImGuiWindowFlags_MenuBar;

            ImGui::Begin("MainHost", nullptr, flags_host);
            ImGui::PopStyleVar(3);

            // Barra de menú
            if (ImGui::BeginMenuBar()) {
                ImGui::TextColored(g_tema_oscuro ? 
                ImVec4(0.4f, 0.9f, 0.6f, 1.0f)   // verde sobre oscuro
                : ImVec4(0.0f, 0.45f, 0.20f, 1.0f), // verde oscuro sobre claro                         
                "Packet Sniffer");
                ImGui::Separator();

                // Combo de selección de interfaz de red
                ImGui::SetNextItemWidth(340);
                if (!g_interfaces.empty()) {
                    string vista_previa = g_interfaces[g_iface_seleccionada].descripcion.substr(0, 45);
                    if (ImGui::BeginCombo("##iface", vista_previa.c_str())) {
                        for (int i = 0; i < (int)g_interfaces.size(); ++i) {
                            string etiq = g_interfaces[i].descripcion + "##iface" + to_string(i);
                            bool es_sel = (g_iface_seleccionada == i);
                            if (ImGui::Selectable(etiq.c_str(), es_sel))
                                g_iface_seleccionada = i;
                            if (es_sel) ImGui::SetItemDefaultFocus();
                        }
                        ImGui::EndCombo();
                    }
                } else {
                    ImGui::TextDisabled("(Sin interfaces disponibles)");
                }

                ImGui::Spacing();

                // Botón Iniciar / Detener captura
                if (!g_capturando) {
                    ImGui::PushStyleColor(ImGuiCol_Button,        ImVec4(0.1f, 0.5f, 0.1f, 1.0f));
                    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.2f, 0.7f, 0.2f, 1.0f));
                    ImGui::PushStyleColor(ImGuiCol_ButtonActive,  ImVec4(0.1f, 0.6f, 0.1f, 1.0f));
                    if (ImGui::Button("  > Iniciar  ")) {
                        if (!g_interfaces.empty()) {
                            g_inicio_captura = glfwGetTime();
                            g_capturando     = true;
                            string nombre_iface = g_interfaces[g_iface_seleccionada].nombre;
                            if (hilo_captura.joinable()) hilo_captura.join();
                            hilo_captura = thread(hilo_captura_func, nombre_iface);
                        }
                    }
                    ImGui::PopStyleColor(3);
                } else {
                    ImGui::PushStyleColor(ImGuiCol_Button,        ImVec4(0.6f, 0.1f, 0.1f, 1.0f));
                    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.8f, 0.2f, 0.2f, 1.0f));
                    ImGui::PushStyleColor(ImGuiCol_ButtonActive,  ImVec4(0.7f, 0.1f, 0.1f, 1.0f));
                    if (ImGui::Button("  [] Detener  ")) {
                        g_capturando = false;
                        if (g_dispositivo_cap) pcap_breakloop(g_dispositivo_cap);
                        if (hilo_captura.joinable()) hilo_captura.join();
                    }
                    ImGui::PopStyleColor(3);

                    // Indicador de actividad animado: modulación sinusoidal de alfa a 4 Hz.
                    ImGui::SameLine();
                    float t     = (float)glfwGetTime();
                    float alpha = 0.5f + 0.5f * std::sin(t * 4.0f);
                    ImGui::PushStyleColor(ImGuiCol_Text,
                    g_tema_oscuro ? ImVec4(0.2f, 1.0f, 0.3f, alpha) // verde fosforescente sobre oscuro
                    : ImVec4(0.0f, 0.50f, 0.15f, alpha));           // verde oscuro sobre claro 
                    ImGui::Text("* CAPTURANDO");
                    ImGui::PopStyleColor();
                }

                ImGui::Spacing();
                ImGui::Separator();
                if (ImGui::SmallButton("Recargar interfaces")) cargar_interfaces();

                ImGui::SameLine();
                ImGui::Separator();
                // Icono cambia según el tema activo para retroalimentación visual inmediata.
                const char* etiq_tema = g_tema_oscuro ? "  Modo Claro" : "  Modo Oscuro";
                if (ImGui::SmallButton(etiq_tema)) {
                    g_tema_oscuro = !g_tema_oscuro;
                    aplicar_tema(g_tema_oscuro);
                }

                // ── IDS: reseteo de ventana de muestreo ─────────────────────────
                {
                    long long ahora  = duration_cast<seconds>(
                        steady_clock::now().time_since_epoch()).count();
                    long long ultimo = g_syn_ultimo_reset.load(std::memory_order_relaxed);

                    if (ultimo == 0)
                        g_syn_ultimo_reset.store(ahora, std::memory_order_relaxed);
                    else if (ahora - ultimo >= SYN_VENTANA_SEG) {
                        g_syn_contador.store(0, std::memory_order_relaxed);
                        g_syn_ultimo_reset.store(ahora, std::memory_order_relaxed);
                        lock_guard<mutex> lk_syn(g_mutex_syn);
                        g_syn_por_ip.clear();
                    }
                }

                // ── IDS: widget de estado + botón de reseteo ────────────────────
                ImGui::Separator();
                int syn_actual = g_syn_contador.load(std::memory_order_relaxed);
                bool alerta_activa = syn_actual > SYN_UMBRAL;

                // Genera el reporte automaticamente la primera vez que se supera
                // el umbral en esta ventana. La bandera evita generar uno por frame.
                static bool reporte_generado = false;
                if (alerta_activa && !reporte_generado) {
                    generar_reporte_ids();
                    reporte_generado = true;
                }
                if (!alerta_activa) reporte_generado = false;

                ImGui::TextColored(
                    alerta_activa
                    ? ImVec4(0.9f, 0.1f, 0.1f, 1.0f)
                    : (g_tema_oscuro ? ImVec4(0.5f, 0.9f, 0.5f, 1.0f)
                                     : ImVec4(0.0f, 0.45f, 0.10f, 1.0f)),
                    "SYN: %d/%d (%ds)", syn_actual, SYN_UMBRAL, SYN_VENTANA_SEG);
                ImGui::SameLine();
                if (ImGui::SmallButton("Restablecer")) {
                    g_syn_contador.store(0, std::memory_order_relaxed);
                    g_syn_ultimo_reset.store(
                        duration_cast<seconds>(
                            steady_clock::now().time_since_epoch()).count(),
                        std::memory_order_relaxed);
                    lock_guard<mutex> lk_syn(g_mutex_syn);
                    g_syn_por_ip.clear();
                }
                ImGui::EndMenuBar();
            }

            // ── IDS: banner de alerta parpadeante ───────────────────────────────
            if (g_syn_contador.load(std::memory_order_relaxed) > SYN_UMBRAL) {
                // Parpadeo a 1 Hz: visible el 50 % del tiempo
                bool visible = std::fmod((float)glfwGetTime(), 1.0f) > 0.5f;
                if (visible) {
                    ImVec2 pos = ImGui::GetCursorScreenPos();
                    float  w   = ImGui::GetContentRegionAvail().x;
                    ImGui::GetWindowDrawList()->AddRectFilled(
                        pos, ImVec2(pos.x + w, pos.y + 36.0f),
                        IM_COL32(200, 0, 0, 255));
                    ImGui::SetCursorScreenPos(ImVec2(pos.x + 8.0f, pos.y + 8.0f));
                    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1, 1, 1, 1));
                    ImGui::Text("  [!] ALERTA DE SEGURIDAD: Posible ataque DoS / SYN Flood Detectado");
                    ImGui::PopStyleColor();
                    ImGui::SetCursorScreenPos(ImVec2(pos.x, pos.y + 40.0f)); // avanza el cursor
                } else {
                    ImGui::Dummy(ImVec2(0.0f, 36.0f)); // reserva espacio para no saltar el layout
                }
            }

            // Disposición de 3 paneles con ChildWindows
            ImVec2 disponible = ImGui::GetContentRegionAvail();
            float  pad        = 4.0f;
            float  alto_sup   = disponible.y * 0.50f;
            float  alto_inf   = disponible.y - alto_sup - pad;
            float  ancho_med  = (disponible.x - pad) * 0.50f;

            // Panel 1: tabla de paquetes (ancho completo, mitad superior)
            renderizar_tabla_paquetes(ImVec2(disponible.x, alto_sup));

            ImGui::SetCursorPosY(ImGui::GetCursorPosY() + pad);

            // Panel 2: detalle decodificado (mitad inferior izquierda)
            renderizar_panel_decodificado(ImVec2(ancho_med, alto_inf));

            ImGui::SameLine(0.0f, pad);

            // Panel 3: Hex Dump (mitad inferior derecha)
            renderizar_panel_hex(ImVec2(ancho_med, alto_inf));

            ImGui::End(); // MainHost
        }

        if (g_fuente_ui) ImGui::PopFont();

        // Envío a GPU
        ImGui::Render();
        int ancho_fb, alto_fb;
        glfwGetFramebufferSize(ventana, &ancho_fb, &alto_fb);
        glViewport(0, 0, ancho_fb, alto_fb);
        glClearColor(0.08f, 0.08f, 0.10f, 1.0f);
        glClear(GL_COLOR_BUFFER_BIT);
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
        glfwSwapBuffers(ventana);
    }

    // Secuencia de apagado: señalizar y unir el hilo de captura antes de liberar
    // recursos de ImGui y GLFW.
    if (g_capturando) {
        g_capturando = false;
        if (g_dispositivo_cap) pcap_breakloop(g_dispositivo_cap);
    }
    if (hilo_captura.joinable()) hilo_captura.join();

    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplGlfw_Shutdown();
    ImGui::DestroyContext();
    glfwDestroyWindow(ventana);
    glfwTerminate();

#ifdef _WIN32
    WSACleanup();
#endif
    return 0;
}