/*
 * Packet Sniffer - Fase 1 (Interactiva)
 * Basado en la estructura de "Building a packet sniffer" - Talalio (Medium)
 * Adaptado para Npcap en Windows con g++ (MSYS2 UCRT64)
 */

#include <iostream>
#include <pcap.h>   // Header principal de Npcap/libpcap

using namespace std;

// CALLBACK: función que pcap_loop invoca por cada paquete.
void manejador_paquetes(u_char *datos_usuario,
                    const struct pcap_pkthdr *cabecera_paquete,
                    const u_char *paquete)
{
    // Imprime el tamaño del paquete capturado
    cout << "Paquete capturado: " << cabecera_paquete->len << " bytes" << endl;
}

// MAIN
int main()
{
    char buffer_error[PCAP_ERRBUF_SIZE];
    pcap_if_t *todas_interfaces;
    pcap_if_t *dispositivo;
    pcap_t    *manejador_captura;

    // 1. Enumerar interfaces de red disponibles.
    if (pcap_findalldevs(&todas_interfaces, buffer_error) == -1) {
        cerr << "Error al buscar dispositivos: " << buffer_error << endl;
        return 1;
    }

    cout << "=== Interfaces de red disponibles ===" << endl;
    int indice = 0;
    for (dispositivo = todas_interfaces; dispositivo != nullptr; dispositivo = dispositivo->next) {
        cout << "[" << indice++ << "] " << dispositivo->name;
        if (dispositivo->description)
            cout << "  ->  " << dispositivo->description;
        cout << endl;
    }

    if (indice == 0) {
        cerr << "No se encontraron interfaces. ¿Está Npcap instalado?" << endl;
        return 1;
    }

    // 2. Selección de interfaz por parte del usuario
    int seleccion;
    cout << "\nIngresa el numero de la interfaz que deseas usar (0 - " << (indice - 1) << "): ";
    cin >> seleccion;

    // Validación básica de la entrada
    if (seleccion < 0 || seleccion >= indice) {
        cerr << "Seleccion invalida. Saliendo del programa..." << endl;
        pcap_freealldevs(todas_interfaces);
        return 1;
    }

    // Navegar en la lista enlazada hasta el dispositivo seleccionado
    dispositivo = todas_interfaces;
    for (int i = 0; i < seleccion; i++) {
        dispositivo = dispositivo->next;
    }

    cout << "\nPreparando interfaz: " << dispositivo->description << endl;

    // 3. Abrir la interfaz en modo promiscuo.
    manejador_captura = pcap_open_live(dispositivo->name,
                             65535,   // snaplen: captura el paquete completo
                             1,       // 1 = modo promiscuo activado
                             1000,    // timeout de lectura en ms
                             buffer_error);

    if (manejador_captura == nullptr) {
        cerr << "No se pudo abrir la interfaz: " << buffer_error << endl;
        pcap_freealldevs(todas_interfaces);
        return 1;
    }

    // Liberar memoria de la lista de dispositivos.
    pcap_freealldevs(todas_interfaces);

    // 4. Selección de cantidad de paquetes a capturar
    int cantidad_paquetes;
    cout << "¿Cuantos paquetes deseas capturar?: ";
    cin >> cantidad_paquetes;

    if (cantidad_paquetes <= 0) {
        cout << "Cantidad invalida. Capturando 10 paquetes por defecto." << endl;
        cantidad_paquetes = 10;
    }

    cout << "\nIniciando captura de " << cantidad_paquetes << " paquetes...\n" << endl;

    // 5. Iniciar captura con límite definido.
    // Al pasar 'cantidad_paquetes' en lugar de -1, la función retornará sola
    // cuando alcance ese número de paquetes procesados.
    pcap_loop(manejador_captura, cantidad_paquetes, manejador_paquetes, nullptr);

    cout << "\nCaptura finalizada exitosamente." << endl;

    // 6. Cerrar el manejador al terminar.
    pcap_close(manejador_captura);

    cout << "\nPresiona Enter para salir...";
    cin.ignore(10000, '\n'); // Limpia el buffer de entrada del 'cin' anterior
    cin.get();               // Espera a que el usuario presione Enter

    return 0;
}