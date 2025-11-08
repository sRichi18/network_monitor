from scapy.all import sniff, IP, TCP, UDP
from datetime import datetime
from colorama import Fore, Style, init

init(autoreset=True)

"""Esta función se llama cada vez que se detecta un paquete"""
def packet_callback(packet):
    time = datetime.now().strftime("%H:%M:%S")
    
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = packet[IP].proto
        
        #Verificación del tipo de paquete (TCP/UDP)
        if TCP in packet:
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            proto_name = "TCP"
        if UDP in packet:
            sport = packet[UDP].sport
            dport = packet[UDP].dport
            proto_name = "UDP"
        else:
            sport = dport = "-"
            proto_name = str(proto)
            
        print(
            f"{Fore.CYAN}[{time}] {Fore.GREEN}{ip_src} : {sport} "
            f"{Fore.WHITE}-> {Fore.YELLOW}{ip_dst} : {dport} "
            f"{Fore.MAGENTA}[{proto_name}]"
        )

        
def main():
    print(Fore.BLUE + Style.BRIGHT + "\n=== Network Traffic Monitor ===\n")
    print(Fore.WHITE + " Capturando trafico de red ... (Ctrl + C para detener)\n")
        
    try:
        sniff(prn=packet_callback, store=False)
    except:
        print(Fore.RED + "\n\nFinalizando monitoreo...")
            
if __name__ == "__main__":
    main()