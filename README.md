# Laboratorio de ARP Spoofing y Detección IDS
**Adrián Muñoz Saiz — 2º DAM**

Simulación completa de un ataque Man-in-the-Middle mediante ARP Spoofing sobre una red virtualizada, incluyendo un IDS por anomalías para su detección y una demo final de robo de credenciales HTTP en texto plano.

---

## Arquitectura del Laboratorio

Tres máquinas virtuales en VirtualBox bajo red interna `arp-lab`, emulando un segmento LAN conmutado:

| Máquina | Rol | IP |
|---|---|---|
| Ubuntu Server | Router / Servidor web vulnerable | 192.168.1.1 |
| Kali Linux | Atacante | 192.168.1.110 |
| Windows 7 | Víctima | 192.168.1.120 |

> **¿Por qué Red Interna?** En una red conmutada (switch), el tráfico es unicast directo entre nodos. Un sniffer pasivo no capturaría el tráfico ajeno — el ataque MitM es estrictamente necesario para interceptarlo.

El Ubuntu Server actúa como gateway con IP forwarding habilitado (`net.ipv4.ip_forward=1` en `/etc/sysctl.conf`), lo que le permite enrutar paquetes entre los nodos en lugar de descartarlos.

---

## Requisitos

- Python 3.x
- Scapy
- Rich

```bash
pip install -r requirements.txt
```

---

## Ejecución

Todo el proyecto se controla desde un único punto de entrada:

```bash
sudo python3 main.py
```

`main.py` unifica los tres módulos en una interfaz de terminal interactiva con menú. Al arrancar, verifica que se ejecuta con privilegios root (necesarios para acceder a los sockets de red crudos); si no es así, aborta con un mensaje de error antes de hacer nada. Una vez dentro, presenta tres opciones:

| Opción | Módulo |
|---|---|
| `[1]` Lanzar Ataque | Modo simulación ARP Spoofing |
| `[2]` Activar Escudos | Modo IDS monitor |
| `[3]` Salir | Sale con confirmación |

Cada módulo se ejecuta y, al terminar (Ctrl+C), vuelve al menú principal sin necesidad de relanzar el script. Los eventos del IDS quedan registrados automáticamente en `alertas.log` con timestamp y formato forense.

---

## Scripts

### `arp_tool.py` — El Atacante

Envenena las tablas ARP de la víctima y del router de forma continua para mantener la posición MitM.

**Cómo funciona:**

1. **`get_mac(ip)`** — Envía un ARP Request broadcast (`ff:ff:ff:ff:ff:ff`) para resolver la MAC física de una IP. Usa `srp()` con `timeout=2` para no quedarse bloqueado si el equipo no responde.

2. **`spoof(target_ip, spoof_ip, target_mac)`** — Envía una ARP Reply (`op=2`) no solicitada suplantando la IP del router. Usa `sendp()` (capa 2) porque el paquete ya lleva cabecera Ethernet; usar `send()` añadiría una cabecera extra y lo rompería.

3. **Bucle infinito con pausa de 2 segundos** — Las cachés ARP se actualizan periódicamente; sin persistencia, el envenenamiento se revierte en segundos. La pausa evita saturar el switch virtual y mantiene un perfil bajo que no interrumpe el tráfico legítimo.

**Ejecución:**
```bash
sudo python3 arp_tool.py
```
Pide las IPs de víctima y router, y muestra una tabla en tiempo real con los paquetes inyectados.

---

### `ids_arp.py` — El Defensor (IDS por Anomalías)

Monitoriza el tráfico ARP de la red y detecta cambios en las asociaciones IP↔MAC.

**Cómo funciona:**

1. **Fase de aprendizaje** — La primera vez que ve una IP, registra su MAC como línea base legítima.

2. **Fase de detección** — Si llega una ARP Reply (`op=2`) con una MAC distinta para una IP ya conocida, levanta una alerta mostrando la MAC legítima y la MAC del atacante.

3. **Optimizaciones de rendimiento:**
   - `store=False` — Descarta los paquetes tras evaluarlos; sin esto, la RAM se llenaría en ataques prolongados.
   - `filter="arp"` — Filtro BPF a nivel de kernel que ignora todo el tráfico TCP/UDP, delegando el filtrado al hardware.

**Ejecución:**
```bash
sudo python3 ids_arp.py
```

> ⚠️ **Orden importante:** el IDS debe arrancar *antes* que el atacante para aprender la línea base legítima. Si el ataque ya está activo al iniciar el IDS, aprenderá las MACs envenenadas como válidas y no detectará nada.

---

### `server.py` — Servidor Web Vulnerable (Fase 3)

Servidor HTTP básico que sirve un formulario de login falso (Panel de Control de Red) y registra las credenciales enviadas en texto plano.

- Responde `200 OK` con el formulario en GET.
- En POST, extrae y muestra el payload (`user=X&pass=Y`) en la consola del servidor.
- Devuelve un **Error 500** ficticio para confundir a la víctima y ocultar la exfiltración.

---

## Flujo completo del ataque (Fase 3)

```
Víctima (W7) ──ARP envenenado──▶ Kali (MitM) ──IP Forward──▶ Ubuntu (servidor)
                                      │
                                      └──▶ tcpdump captura las credenciales
```

1. Kali envenena las tablas ARP de W7 y del router con `arp_tool.py`.
2. W7 accede al servidor web y envía sus credenciales.
3. El tráfico pasa por Kali; con IP forwarding activo en Kali, se reenvía al destino real (sin esto sería un DoS, no un MitM).
4. `tcpdump` en Kali captura el paquete HTTP en claro:

```bash
sudo tcpdump -i eth0 -vv -A host 192.168.1.120 and port 80
```

Resultado visible en la captura: `user=adrian&pass=123456781`

La víctima solo ve el Error 500 y no sospecha nada.

---

## Conclusión

El laboratorio demuestra de forma práctica por qué el tráfico HTTP sin cifrado es inseguro en una red local, y cómo un IDS por anomalías puede detectar el ataque que lo hace posible. La contramedida más efectiva a nivel de aplicación es usar HTTPS, que cifra el payload y hace ilegible la captura de tcpdump aunque el MitM siga activo.
