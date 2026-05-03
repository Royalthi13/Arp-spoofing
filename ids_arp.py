import scapy.all as scapy
from rich.console import Console
from rich.panel import Panel

console = Console()

known_devices = {}

def process_sniffed_packet(packet):
    if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op == 2:
        ip_src = packet[scapy.ARP].psrc
        mac_src = packet[scapy.ARP].hwsrc

        
        if ip_src not in known_devices:
            known_devices[ip_src] = mac_src
            console.print(f"[bold blue][*][/bold blue] Dispositivo registrado: {ip_src} -> {mac_src}")
        
        
        elif known_devices[ip_src] != mac_src:
            console.print("-" * 50)
            console.print(f"[bold red][!] ALERTA: ATAQUE ARP DETECTADO EN {ip_src}[/bold red]")
            console.print(f"[yellow]MAC Legítima: {known_devices[ip_src]}[/yellow]")
            console.print(f"[bold white]MAC Atacante: {mac_src}[/bold white]")

def start_ids():
    console.clear()
    console.print(Panel("[bold cyan]IDS - MONITOR DE INTEGRIDAD ARP[/bold cyan]", expand=False))
    console.print("[italic]Escuchando tráfico en enp0s3...[/italic]\n")
    
    scapy.sniff(iface="enp0s3", store=False, prn=process_sniffed_packet, filter="arp")

if __name__ == "__main__":
    start_ids()










