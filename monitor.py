from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime
from colorama import Fore, Style, init
from collections import defaultdict

init(autoreset=True)

# Mapeo de protocolos
PROTO_MAP = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
}

# Diccionario para contar el número de conexiones por IP origen
connection_count = defaultdict(int)
ALERT_THRESHOLD = 20

# Lista de puertos a vigilar (posibles accesos maliciosos)
SUSPICIOS_PORTS = {22, 23, 3389, 5900, 8080}

"""Esta función se llama cada vez que se detecta un paquete"""
def packet_callback(packet):
    time = datetime.now().strftime("%H:%M:%S")
    
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto_num = packet[IP].proto
        proto_name = PROTO_MAP.get(proto_num, str(proto_num))
        
        sport = dport = "-"
        if TCP in packet:
            sport = packet[TCP].sport
            dport = packet[TCP].dport
        elif UDP in packet:
            sport = packet[UDP].sport
            dport = packet[UDP].dport
        
        # ---Mostrar el trafico ---
        print(
            f"{Fore.CYAN}[{time}] {Fore.GREEN}{ip_src} : {sport} "
            f"{Fore.WHITE}-> {Fore.YELLOW}{ip_dst} : {dport} "
            f"{Fore.MAGENTA}[{proto_name}]"
        )
        
        # --- Detección: multiples conexiones ---
        connection_count[ip_src] += 1
        if connection_count[ip_src] > ALERT_THRESHOLD:
            print(
                f"{Fore.RED}[ALERTA] Posible escaneo de puertos desde {ip_src}"
                f"({connection_count[ip_src]} conexiones)."
            )
            
        # --- Detección: escaneo de puertos delicados ---
        if dport != "-" and int(dport) in SUSPICIOS_PORTS:
            print(
                f"{Fore.YELLOW}[ADVERTENCIA] Conexión hacia puerto sensible {dport}."
                f"desde {ip_src}"
            )
            
        # --- Detección trafico ICMP ---
        if ICMP in packet:
            print(
                f"{Fore.BLUE}[INFO] Trafico ICMP detectado entre {ip_src} y {ip_dst}"
            )
        
def main():
    print(Fore.BLUE + Style.BRIGHT + "\n=== Network Traffic Monitor ===\n")
    print(Fore.WHITE + " Capturando trafico de red ... (Ctrl + C para detener)\n")
        
    try:
        sniff(prn=packet_callback, store=False)
    except KeyboardInterrupt:
        print(Fore.RED + "\n\nFinalizando monitoreo...")
        print(Fore.GREEN + f"Total de IPs analizadas: {len(connection_count)}")
            
if __name__ == "__main__":
    main()