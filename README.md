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
[PEGA AQUÍ EL SCRIPT COMPLETO]

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
