from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime
from colorama import Fore, Style, init
from collections import defaultdict
import csv, os

init(autoreset=True)

# Mapeo de protocolos
PROTO_MAP = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
    47: "GRE",
    50: "ESP",
    51: "AH",
    89: "OSPF",
}

# Diccionario para contar el número de conexiones por IP origen
connection_count = defaultdict(int)
ALERT_THRESHOLD = 20

# Lista de puertos a vigilar (posibles accesos maliciosos)
SUSPICIOS_PORTS = {22, 23, 3389, 5900, 8080}

OUTPUT_FILE =  "captures/networl_events.csv" # Carpeta de salida
os.mkdir("captures", exist_ok=True) # Crear la carpeta si no existe

# Crear el archivo CSV si no existe
if not os.path.exists(OUTPUT_FILE):
    with open(OUTPUT_FILE, mode="w", newline="") as file:
        writer =  csv.writer(file)
        writer.writerow(["timestamp", "IP_Origen", "IP_Destino", "Protocolo","Puerto_Origen", "Puerto_Destino", "Evento"])
        
"""Guardar eventos en el archivo SCV"""
def log_event(timestamp, src, dst, proto, sport, dport, event):
    with open(OUTPUT_FILE, mode="a", newline="") as file:
        writer = csv.writer(file)
        writer.writerow([timestamp, src, dst, proto, sport, dport, event])
        

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
        
        event_desc = "Trafico normal"
        
        # --- Detección: multiples conexiones ---
        connection_count[ip_src] += 1
        if connection_count[ip_src] > ALERT_THRESHOLD:
            event_desc = f"Posible escaneo de puertos ({connection_count[ip_src]} conexiones)"
            print(f"{Fore.RED}[ALERTA]{event_desc} desde {ip_src}")
            
            
        # --- Detección: escaneo de puertos delicados ---
        if dport != "-" and int(dport) in SUSPICIOS_PORTS:
            event_desc = f"Conexión hacia puerto sensible {dport}"
            print(f"{Fore.YELLOW}[ADVERTENCIA] {event_desc} desde {ip_src}")
            
        # --- Detección trafico ICMP ---
        if ICMP in packet:
            event_desc = "Tráfico ICMP detectado"
            print(f"{Fore.BLUE}[INFO] {event_desc} entre {ip_src} y {ip_dst}")
            
        # Guardar evento
        log_event(time, ip_src, ip_dst, proto_name, sport, dport, event_desc)
        
        
def main():
    print(Fore.BLUE + Style.BRIGHT + "\n=== Network Traffic Monitor ===\n")
    print(Fore.WHITE + " Capturando trafico de red ... (Ctrl + C para detener)\n")
        
    try:
        sniff(prn=packet_callback, store=False)
    except KeyboardInterrupt:
        print(Fore.RED + "\n\nFinalizando monitoreo...")
        print(Fore.GREEN + f"Total de IPs analizadas: {len(connection_count)}")
        print(Fore.WHITE + f"Resultados guardados en : {OUTPUT_FILE}")
        
            
if __name__ == "__main__":
    main()