/*
 * Packet Sniffer - GUI
 * Backend: Npcap + Dear ImGui + GLFW + OpenGL3
 * Compilador: g++ (MSYS2 UCRT64)
 *
 * Estructura de archivos requerida en la carpeta del proyecto:
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
 *   │   ├── backends/
 *   │   │   ├── imgui_impl_glfw.h / imgui_impl_glfw.cpp
 *   │   │   └── imgui_impl_opengl3.h / imgui_impl_opengl3.cpp
 *   └── (Npcap SDK en C:/Npcap-sdk o via MSYS2)
 */

// ─── Cabeceras estándar ───────────────────────────────────────────────────────
#include <iostream>
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include <thread>
#include <mutex>
#include <atomic>
#include <cstring>
#include <cmath>    // sinf

// ─── Npcap / libpcap ─────────────────────────────────────────────────────────
#include <pcap.h>

// ─── Cabeceras de protocolos de red ──────────────────────────────────────────
#ifdef _WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
#else
  #include <netinet/in.h>
  #include <arpa/inet.h>
#endif

// ─── Dear ImGui ──────────────────────────────────────────────────────────────
#include "imgui/imgui.h"
#include "imgui/backends/imgui_impl_glfw.h"
#include "imgui/backends/imgui_impl_opengl3.h"

// ─── GLFW + OpenGL ───────────────────────────────────────────────────────────
#include <GLFW/glfw3.h>

// ═════════════════════════════════════════════════════════════════════════════
// ESTRUCTURAS DE DATOS
// ═════════════════════════════════════════════════════════════════════════════

// Cabecera Ethernet (14 bytes)
struct EthernetHeader {
    uint8_t  dst[6];
    uint8_t  src[6];
    uint16_t type;
};

// Cabecera IPv4 (Mínimo 20 bytes)
struct IPv4Header {
    uint8_t  ver_ihl;
    uint8_t  tos;
    uint16_t total_len;
    uint16_t id;
    uint16_t flags_frag;
    uint8_t  ttl;
    uint8_t  proto;
    uint16_t checksum;
    uint32_t src_ip;
    uint32_t dst_ip;
};

// Cabecera TCP (mínimo 20 bytes)
struct TCPHeader {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack;
    uint8_t  data_offset;
    uint8_t  flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent;
};

// Cabecera UDP (8 bytes)
struct UDPHeader {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t checksum;
};

// ─── Paquete capturado (una fila en la tabla) ─────────────────────────────────
struct CapturedPacket {
    int      number;
    double   timestamp;     // segundos desde inicio de captura
    std::string src_mac;
    std::string dst_mac;
    std::string src_ip;
    std::string dst_ip;
    std::string protocol;   // Ethernet / IPv4 / TCP / UDP / ARP / ...
    int      src_port = 0;
    int      dst_port = 0;
    int      length;

    // Datos decodificados (Área 2)
    std::string decoded_info;

    // Datos raw (Área 3)
    std::vector<uint8_t> raw_data;
};

// ═════════════════════════════════════════════════════════════════════════════
// ESTADO GLOBAL (protegido por mutex donde aplica)
// ═════════════════════════════════════════════════════════════════════════════

std::mutex              g_packets_mutex;
std::vector<CapturedPacket> g_packets;          // lista de paquetes capturados
std::atomic<bool>       g_capturing{false};     // flag de captura activa
std::atomic<int>        g_packet_counter{0};
pcap_t*                 g_capdev = nullptr;     // handle de captura (hilo secundario)
double                  g_capture_start = 0.0;  // timestamp de referencia

// Interfaces disponibles
struct NetInterface {
    std::string name;
    std::string description;
};
std::vector<NetInterface> g_interfaces;
int g_selected_iface = 0;

// Paquete seleccionado en la tabla
int g_selected_packet = -1;

// ═════════════════════════════════════════════════════════════════════════════
// HELPERS: formateo de direcciones
// ═════════════════════════════════════════════════════════════════════════════

static std::string mac_to_str(const uint8_t* mac) {
    char buf[18];
    snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return buf;
}

static std::string ip_to_str(uint32_t ip_net) {
    struct in_addr addr;
    addr.s_addr = ip_net;
    char buf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &addr, buf, sizeof(buf));
    return buf;
}

// Genera el volcado hex/ASCII de un buffer (Área 3)
static std::string hex_dump(const uint8_t* data, int len) {
    std::ostringstream oss;
    for (int i = 0; i < len; i += 16) {
        // Offset
        oss << std::setw(4) << std::setfill('0') << std::hex << i << "  ";
        // Hex
        for (int j = 0; j < 16; ++j) {
            if (i + j < len)
                oss << std::setw(2) << std::setfill('0') << std::hex
                    << (int)data[i + j] << " ";
            else
                oss << "   ";
            if (j == 7) oss << " ";
        }
        oss << " |";
        // ASCII
        for (int j = 0; j < 16 && i + j < len; ++j) {
            uint8_t c = data[i + j];
            oss << (char)(c >= 32 && c < 127 ? c : '.');
        }
        oss << "|\n";
    }
    return oss.str();
}

// ═════════════════════════════════════════════════════════════════════════════
// CALLBACK DE CAPTURA (ejecutado en el hilo secundario)
// ═════════════════════════════════════════════════════════════════════════════

void packet_handler(u_char* /*user*/, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    if (!g_capturing) return;

    CapturedPacket pkt;
    pkt.number    = ++g_packet_counter;
    pkt.timestamp = pkthdr->ts.tv_sec + pkthdr->ts.tv_usec * 1e-6 - g_capture_start;
    pkt.length    = pkthdr->len;
    pkt.raw_data.assign(packet, packet + pkthdr->caplen);

    std::ostringstream decoded;

    // ── Capa 2: Ethernet ──────────────────────────────────────────────────
    if (pkthdr->caplen < sizeof(EthernetHeader)) {
        pkt.protocol = "Ethernet (truncado)";
        pkt.src_mac  = "??:??:??:??:??:??";
        pkt.dst_mac  = "??:??:??:??:??:??";
        pkt.decoded_info = "Paquete demasiado corto para cabecera Ethernet";
        std::lock_guard<std::mutex> lk(g_packets_mutex);
        g_packets.push_back(std::move(pkt));
        return;
    }

    const EthernetHeader* eth = reinterpret_cast<const EthernetHeader*>(packet);
    pkt.src_mac = mac_to_str(eth->src);
    pkt.dst_mac = mac_to_str(eth->dst);
    uint16_t eth_type = ntohs(eth->type);

    decoded << "[Ethernet]\n";
    decoded << "  Src MAC : " << pkt.src_mac << "\n";
    decoded << "  Dst MAC : " << pkt.dst_mac << "\n";
    decoded << "  EtherType: 0x" << std::hex << std::setw(4)
            << std::setfill('0') << eth_type << std::dec << "\n";

    // ── Capa 3 ────────────────────────────────────────────────────────────
    const uint8_t* l3 = packet + sizeof(EthernetHeader);
    int l3_len = (int)pkthdr->caplen - (int)sizeof(EthernetHeader);

    if (eth_type == 0x0800 && l3_len >= (int)sizeof(IPv4Header)) {
        // IPv4
        const IPv4Header* ip = reinterpret_cast<const IPv4Header*>(l3);
        int ihl = (ip->ver_ihl & 0x0F) * 4;
        pkt.src_ip = ip_to_str(ip->src_ip);
        pkt.dst_ip = ip_to_str(ip->dst_ip);

        decoded << "\n[IPv4]\n";
        decoded << "  Src IP  : " << pkt.src_ip << "\n";
        decoded << "  Dst IP  : " << pkt.dst_ip << "\n";
        decoded << "  TTL     : " << (int)ip->ttl << "\n";
        decoded << "  Proto   : " << (int)ip->proto << "\n";
        decoded << "  Total   : " << ntohs(ip->total_len) << " bytes\n";

        const uint8_t* l4 = l3 + ihl;
        int l4_len = l3_len - ihl;

        if (ip->proto == 6 && l4_len >= (int)sizeof(TCPHeader)) {
            // TCP
            const TCPHeader* tcp = reinterpret_cast<const TCPHeader*>(l4);
            pkt.src_port = ntohs(tcp->src_port);
            pkt.dst_port = ntohs(tcp->dst_port);
            pkt.protocol = "TCP";

            // Flags
            uint8_t f = tcp->flags;
            std::string flags;
            if (f & 0x02) flags += "SYN ";
            if (f & 0x10) flags += "ACK ";
            if (f & 0x01) flags += "FIN ";
            if (f & 0x04) flags += "RST ";
            if (f & 0x08) flags += "PSH ";
            if (f & 0x20) flags += "URG ";

            decoded << "\n[TCP]\n";
            decoded << "  Src Port: " << pkt.src_port << "\n";
            decoded << "  Dst Port: " << pkt.dst_port << "\n";
            decoded << "  Seq     : " << ntohl(tcp->seq) << "\n";
            decoded << "  Ack     : " << ntohl(tcp->ack) << "\n";
            decoded << "  Flags   : " << (flags.empty() ? "(ninguno)" : flags) << "\n";
            decoded << "  Window  : " << ntohs(tcp->window) << "\n";

        } else if (ip->proto == 17 && l4_len >= (int)sizeof(UDPHeader)) {
            // UDP
            const UDPHeader* udp = reinterpret_cast<const UDPHeader*>(l4);
            pkt.src_port = ntohs(udp->src_port);
            pkt.dst_port = ntohs(udp->dst_port);
            pkt.protocol = "UDP";

            decoded << "\n[UDP]\n";
            decoded << "  Src Port: " << pkt.src_port << "\n";
            decoded << "  Dst Port: " << pkt.dst_port << "\n";
            decoded << "  Length  : " << ntohs(udp->length) << "\n";

        } else if (ip->proto == 1) {
            pkt.protocol = "ICMP";
            decoded << "\n[ICMP]\n";
        } else {
            pkt.protocol = "IPv4/Proto=" + std::to_string(ip->proto);
        }

    } else if (eth_type == 0x0806) {
        pkt.protocol = "ARP";
        decoded << "\n[ARP]\n";
    } else if (eth_type == 0x86DD) {
        pkt.protocol = "IPv6";
        decoded << "\n[IPv6]\n";
    } else {
        pkt.protocol = "Ethernet/0x" + [&]{
            std::ostringstream s;
            s << std::hex << std::setw(4) << std::setfill('0') << eth_type;
            return s.str();
        }();
    }

    pkt.decoded_info = decoded.str();

    std::lock_guard<std::mutex> lk(g_packets_mutex);
    g_packets.push_back(std::move(pkt));
}

// ─── Hilo de captura ──────────────────────────────────────────────────────────
void capture_thread_func(const std::string& iface_name) {
    char errbuf[PCAP_ERRBUF_SIZE];

    g_capdev = pcap_open_live(iface_name.c_str(),
                               65535,
                               1,      // promiscuo
                               100,    // timeout corto para poder interrumpir
                               errbuf);
    if (!g_capdev) {
        g_capturing = false;
        return;
    }

    // pcap_loop sale cuando g_capturing se ponga a false mediante pcap_breakloop
    pcap_loop(g_capdev, -1, packet_handler, nullptr);

    pcap_close(g_capdev);
    g_capdev = nullptr;
    g_capturing = false;
}

// ═════════════════════════════════════════════════════════════════════════════
// CARGA DE INTERFACES
// ═════════════════════════════════════════════════════════════════════════════

static void load_interfaces() {
    g_interfaces.clear();
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* alldevs = nullptr;

    if (pcap_findalldevs(&alldevs, errbuf) == -1) return;

    for (pcap_if_t* d = alldevs; d != nullptr; d = d->next) {
        NetInterface ni;
        ni.name        = d->name ? d->name : "";
        ni.description = d->description ? d->description : "(sin descripción)";
        g_interfaces.push_back(ni);
    }
    pcap_freealldevs(alldevs);
}

// ═════════════════════════════════════════════════════════════════════════════
// COLOR POR PROTOCOLO (estilo Wireshark)
// ═════════════════════════════════════════════════════════════════════════════

static ImVec4 proto_color(const std::string& proto) {
    if (proto == "TCP")  return ImVec4(0.68f, 0.85f, 1.00f, 1.0f); // azul claro
    if (proto == "UDP")  return ImVec4(0.68f, 1.00f, 0.68f, 1.0f); // verde claro
    if (proto == "ICMP") return ImVec4(1.00f, 0.95f, 0.60f, 1.0f); // amarillo
    if (proto == "ARP")  return ImVec4(1.00f, 0.80f, 0.60f, 1.0f); // naranja
    if (proto == "IPv6") return ImVec4(0.85f, 0.75f, 1.00f, 1.0f); // lila
    return ImVec4(0.85f, 0.85f, 0.85f, 1.0f);                       // gris
}

// ═════════════════════════════════════════════════════════════════════════════
// RENDER DE LAS TRES ÁREAS
// ═════════════════════════════════════════════════════════════════════════════

static void render_packet_table(ImVec2 size) {
    ImGui::BeginChild("PacketTable", size, true);

    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.9f, 0.9f, 0.9f, 1.0f));
    ImGui::Text("  Paquetes capturados: %d", g_packet_counter.load());
    ImGui::PopStyleColor();
    ImGui::SameLine(size.x - 90);
    if (ImGui::SmallButton("Limpiar lista")) {
        std::lock_guard<std::mutex> lk(g_packets_mutex);
        g_packets.clear();
        g_packet_counter = 0;
        g_selected_packet = -1;
    }
    ImGui::Separator();

    static ImGuiTableFlags table_flags =
        ImGuiTableFlags_BordersInnerV |
        ImGuiTableFlags_BordersOuterH |
        ImGuiTableFlags_RowBg         |
        ImGuiTableFlags_ScrollY       |
        ImGuiTableFlags_Resizable     |
        ImGuiTableFlags_SizingStretchSame;

    if (ImGui::BeginTable("pkttable", 9, table_flags)) {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("#",        ImGuiTableColumnFlags_WidthFixed, 45);
        ImGui::TableSetupColumn("Tiempo(s)", ImGuiTableColumnFlags_WidthFixed, 75);
        ImGui::TableSetupColumn("Src IP",   ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("Dst IP",   ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("Src MAC",  ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("Dst MAC",  ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("Proto",    ImGuiTableColumnFlags_WidthFixed, 60);
        ImGui::TableSetupColumn("Puerto",   ImGuiTableColumnFlags_WidthFixed, 75);
        ImGui::TableSetupColumn("Bytes",    ImGuiTableColumnFlags_WidthFixed, 55);
        ImGui::TableHeadersRow();

        std::lock_guard<std::mutex> lk(g_packets_mutex);
        for (int i = 0; i < (int)g_packets.size(); ++i) {
            const auto& p = g_packets[i];
            ImGui::TableNextRow();

            // Fondo de color por protocolo
            ImVec4 row_col = proto_color(p.protocol);
            ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0,
                ImGui::ColorConvertFloat4ToU32(ImVec4(row_col.x, row_col.y, row_col.z, 0.35f)));

            ImGui::TableSetColumnIndex(0);
            char sel_label[32];
            snprintf(sel_label, sizeof(sel_label), "%d##row%d", p.number, i);
            bool is_sel = (g_selected_packet == i);
            if (ImGui::Selectable(sel_label, is_sel,
                ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowOverlap,
                ImVec2(0, 0)))
            {
                g_selected_packet = i;
            }

            ImGui::TableSetColumnIndex(1);
            ImGui::Text("%.4f", p.timestamp);
            ImGui::TableSetColumnIndex(2);
            ImGui::TextUnformatted(p.src_ip.empty() ? "-" : p.src_ip.c_str());
            ImGui::TableSetColumnIndex(3);
            ImGui::TextUnformatted(p.dst_ip.empty() ? "-" : p.dst_ip.c_str());
            ImGui::TableSetColumnIndex(4);
            ImGui::TextUnformatted(p.src_mac.c_str());
            ImGui::TableSetColumnIndex(5);
            ImGui::TextUnformatted(p.dst_mac.c_str());
            ImGui::TableSetColumnIndex(6);
            ImGui::PushStyleColor(ImGuiCol_Text, proto_color(p.protocol));
            ImGui::TextUnformatted(p.protocol.c_str());
            ImGui::PopStyleColor();
            ImGui::TableSetColumnIndex(7);
            if (p.src_port || p.dst_port)
                ImGui::Text("%d->%d", p.src_port, p.dst_port);
            else
                ImGui::TextUnformatted("-");
            ImGui::TableSetColumnIndex(8);
            ImGui::Text("%d", p.length);
        }

        // Auto-scroll al final cuando llegan paquetes nuevos
        if (g_capturing && ImGui::GetScrollY() >= ImGui::GetScrollMaxY() - 20)
            ImGui::SetScrollHereY(1.0f);

        ImGui::EndTable();
    }
    ImGui::EndChild();
}

static void render_decoded_panel(ImVec2 size) {
    ImGui::BeginChild("DecodedPanel", size, true);
    ImGui::TextColored(ImVec4(0.4f, 0.9f, 0.6f, 1.0f), "Detalle del paquete");
    ImGui::Separator();

    std::lock_guard<std::mutex> lk(g_packets_mutex);
    if (g_selected_packet >= 0 && g_selected_packet < (int)g_packets.size()) {
        const auto& p = g_packets[g_selected_packet];
        ImGui::TextColored(ImVec4(0.8f, 0.8f, 0.3f, 1.0f),
            "Paquete #%d  |  %d bytes  |  %.4f s",
            p.number, p.length, p.timestamp);
        ImGui::Separator();
        ImGui::TextUnformatted(p.decoded_info.c_str());
    } else {
        ImGui::TextDisabled("(Selecciona un paquete en la tabla)");
    }
    ImGui::EndChild();
}

static void render_hex_panel(ImVec2 size) {
    ImGui::BeginChild("HexPanel", size, true);
    ImGui::TextColored(ImVec4(0.4f, 0.7f, 1.0f, 1.0f), "Vista Hex / ASCII");
    ImGui::Separator();

    std::lock_guard<std::mutex> lk(g_packets_mutex);
    if (g_selected_packet >= 0 && g_selected_packet < (int)g_packets.size()) {
        const auto& p = g_packets[g_selected_packet];
        if (!p.raw_data.empty()) {
            std::string dump = hex_dump(p.raw_data.data(), (int)p.raw_data.size());
            ImGui::PushFont(ImGui::GetIO().Fonts->Fonts.Size > 1
                            ? ImGui::GetIO().Fonts->Fonts[1]  // fuente monospace si hay 2
                            : ImGui::GetIO().Fonts->Fonts[0]);
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

// ═════════════════════════════════════════════════════════════════════════════
// CALLBACK DE ERROR DE GLFW
// ═════════════════════════════════════════════════════════════════════════════

static void glfw_error_callback(int error, const char* desc) {
    fprintf(stderr, "GLFW Error %d: %s\n", error, desc);
}

// ═════════════════════════════════════════════════════════════════════════════
// MAIN
// ═════════════════════════════════════════════════════════════════════════════

int main() {
#ifdef _WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2,2), &wsa);
#endif

    // ── Cargar interfaces antes de abrir la ventana ───────────────────────
    load_interfaces();

    // ── Inicializar GLFW ─────────────────────────────────────────────────
    glfwSetErrorCallback(glfw_error_callback);
    if (!glfwInit()) return 1;

    // OpenGL 3.3 core
    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 3);
    glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE);

    GLFWwindow* window = glfwCreateWindow(1280, 800, "Packet Sniffer — GUI", nullptr, nullptr);
    if (!window) { glfwTerminate(); return 1; }

    glfwMakeContextCurrent(window);
    glfwSwapInterval(1);   // VSync

    // ── Inicializar ImGui ─────────────────────────────────────────────────
    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
    // Nota: ImGuiConfigFlags_DockingEnable solo existe en la rama "docking" de ImGui.
    // Usamos layout manual con ChildWindows para compatibilidad con la rama master.

    // Tema oscuro estilo Wireshark
    ImGui::StyleColorsDark();
    ImGuiStyle& style = ImGui::GetStyle();
    style.WindowRounding  = 4.0f;
    style.FrameRounding   = 3.0f;
    style.ScrollbarRounding = 3.0f;
    style.Colors[ImGuiCol_WindowBg] = ImVec4(0.10f, 0.10f, 0.12f, 1.0f);
    style.Colors[ImGuiCol_Header]   = ImVec4(0.20f, 0.40f, 0.60f, 0.6f);
    style.Colors[ImGuiCol_HeaderHovered] = ImVec4(0.25f, 0.50f, 0.75f, 0.8f);
    style.Colors[ImGuiCol_HeaderActive]  = ImVec4(0.30f, 0.55f, 0.80f, 1.0f);

    ImGui_ImplGlfw_InitForOpenGL(window, true);
    ImGui_ImplOpenGL3_Init("#version 330");

    // Fuentes: añade una fuente monospace para el hex dump (opcional)
    // io.Fonts->AddFontFromFileTTF("C:/Windows/Fonts/consola.ttf", 13.0f);

    // ── Hilo de captura ──────────────────────────────────────────────────
    std::thread capture_thread;

    // ── Bucle principal ───────────────────────────────────────────────────
    while (!glfwWindowShouldClose(window)) {
        glfwPollEvents();

        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();

        // ── Ventana principal full-screen (layout manual, sin DockSpace) ──
        {
            ImGuiViewport* vp = ImGui::GetMainViewport();
            ImGui::SetNextWindowPos(vp->Pos);
            ImGui::SetNextWindowSize(vp->Size);
            ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 0.0f);
            ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0.0f);
            ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(6, 6));

            ImGuiWindowFlags host_flags =
                ImGuiWindowFlags_NoTitleBar          |
                ImGuiWindowFlags_NoCollapse          |
                ImGuiWindowFlags_NoResize            |
                ImGuiWindowFlags_NoMove              |
                ImGuiWindowFlags_NoBringToFrontOnFocus |
                ImGuiWindowFlags_NoNavFocus          |
                ImGuiWindowFlags_NoScrollbar         |
                ImGuiWindowFlags_NoScrollWithMouse   |
                ImGuiWindowFlags_MenuBar;

            ImGui::Begin("MainHost", nullptr, host_flags);
            ImGui::PopStyleVar(3);

            // ── Barra de menú / controles ─────────────────────────────────
            if (ImGui::BeginMenuBar()) {
                ImGui::TextColored(ImVec4(0.4f, 0.9f, 0.6f, 1.0f), "Packet Sniffer");
                ImGui::Separator();

                // Combo de interfaces
                ImGui::SetNextItemWidth(340);
                if (!g_interfaces.empty()) {
                    std::string preview = g_interfaces[g_selected_iface].description.substr(0, 45);
                    if (ImGui::BeginCombo("##iface", preview.c_str())) {
                        for (int i = 0; i < (int)g_interfaces.size(); ++i) {
                            std::string label = g_interfaces[i].description +
                                                "##iface" + std::to_string(i);
                            bool is_sel = (g_selected_iface == i);
                            if (ImGui::Selectable(label.c_str(), is_sel))
                                g_selected_iface = i;
                            if (is_sel) ImGui::SetItemDefaultFocus();
                        }
                        ImGui::EndCombo();
                    }
                } else {
                    ImGui::TextDisabled("(Sin interfaces)");
                }

                ImGui::Spacing();

                // Botón Iniciar / Detener
                if (!g_capturing) {
                    ImGui::PushStyleColor(ImGuiCol_Button,        ImVec4(0.1f, 0.5f, 0.1f, 1.0f));
                    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.2f, 0.7f, 0.2f, 1.0f));
                    ImGui::PushStyleColor(ImGuiCol_ButtonActive,  ImVec4(0.1f, 0.6f, 0.1f, 1.0f));
                    if (ImGui::Button("  > Iniciar  ")) {
                        if (!g_interfaces.empty()) {
                            g_capture_start = glfwGetTime();
                            g_capturing = true;
                            std::string iface = g_interfaces[g_selected_iface].name;
                            if (capture_thread.joinable()) capture_thread.join();
                            capture_thread = std::thread(capture_thread_func, iface);
                        }
                    }
                    ImGui::PopStyleColor(3);
                } else {
                    ImGui::PushStyleColor(ImGuiCol_Button,        ImVec4(0.6f, 0.1f, 0.1f, 1.0f));
                    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.8f, 0.2f, 0.2f, 1.0f));
                    ImGui::PushStyleColor(ImGuiCol_ButtonActive,  ImVec4(0.7f, 0.1f, 0.1f, 1.0f));
                    if (ImGui::Button("  [] Detener  ")) {
                        g_capturing = false;
                        if (g_capdev) pcap_breakloop(g_capdev);
                        if (capture_thread.joinable()) capture_thread.join();
                    }
                    ImGui::PopStyleColor(3);
                    // Indicador de actividad parpadeante
                    ImGui::SameLine();
                    float t = (float)glfwGetTime();
                    float alpha = 0.5f + 0.5f * std::sin(t * 4.0f);
                    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.2f, 1.0f, 0.3f, alpha));
                    ImGui::Text("* CAPTURANDO");
                    ImGui::PopStyleColor();
                }

                ImGui::Spacing();
                ImGui::Separator();
                if (ImGui::SmallButton("Recargar interfaces")) load_interfaces();

                ImGui::EndMenuBar();
            }

            // ── Layout manual en 3 zonas usando ChildWindows ─────────────
            // Calculamos el espacio disponible dentro de la ventana host
            ImVec2 avail = ImGui::GetContentRegionAvail();
            float pad     = 4.0f;
            float top_h   = avail.y * 0.50f;   // 50 % arriba  → tabla
            float bot_h   = avail.y - top_h - pad; // 50 % abajo → detalle + hex
            float half_w  = (avail.x - pad) * 0.50f;

            // ── Área 1: Tabla de paquetes (arriba, ancho completo) ────────
            render_packet_table(ImVec2(avail.x, top_h));

            ImGui::SetCursorPosY(ImGui::GetCursorPosY() + pad);

            // ── Área 2: Detalle decodificado (abajo izquierda) ────────────
            render_decoded_panel(ImVec2(half_w, bot_h));

            ImGui::SameLine(0.0f, pad);

            // ── Área 3: Hex dump (abajo derecha) ──────────────────────────
            render_hex_panel(ImVec2(half_w, bot_h));

            ImGui::End(); // MainHost
        }

        // ── Render final ──────────────────────────────────────────────────
        ImGui::Render();
        int display_w, display_h;
        glfwGetFramebufferSize(window, &display_w, &display_h);
        glViewport(0, 0, display_w, display_h);
        glClearColor(0.08f, 0.08f, 0.10f, 1.0f);
        glClear(GL_COLOR_BUFFER_BIT);
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
        glfwSwapBuffers(window);
    }

    // ── Cleanup ───────────────────────────────────────────────────────────
    if (g_capturing) {
        g_capturing = false;
        if (g_capdev) pcap_breakloop(g_capdev);
    }
    if (capture_thread.joinable()) capture_thread.join();

    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplGlfw_Shutdown();
    ImGui::DestroyContext();
    glfwDestroyWindow(window);
    glfwTerminate();

#ifdef _WIN32
    WSACleanup();
#endif
    return 0;
}
