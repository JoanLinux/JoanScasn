import socket
import ssl
from scapy.all import IP, TCP, sr1
from datetime import datetime
from ipaddress import ip_network

def check_certificate(ip, port):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((ip, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=ip) as ssock:
                cert = ssock.getpeercert()
                issuer = dict(x[0] for x in cert.get("issuer", ()))
                subject = dict(x[0] for x in cert.get("subject", ()))
                not_after = cert.get("notAfter")
                expiration_date = datetime.strptime(not_after, "%b %d %H:%M:%S %Y GMT")
                is_expired = expiration_date < datetime.utcnow()
                is_self_signed = issuer == subject

                return {
                    "ip": ip,
                    "port": port,
                    "is_expired": is_expired,
                    "is_self_signed": is_self_signed,
                    "expiration_date": not_after,
                    "issuer": issuer,
                }
    except ssl.SSLError as e:
        return {"ip": ip, "port": port, "error": f"SSL Error: {e}"}
    except Exception as e:
        return {"ip": ip, "port": port, "error": str(e)}

def scan_network(cidr, ports):
    results = []
    for ip in ip_network(cidr):
        for port in ports:
            response = sr1(IP(dst=str(ip))/TCP(dport=port, flags="S"), timeout=1, verbose=0)
            if response and response.haslayer(TCP) and response[TCP].flags == 0x12:  # SYN-ACK received
                cert_result = check_certificate(str(ip), port)
                results.append(cert_result)
    return results

def main():
    cidr = input("Ingrese la red a escanear (formato CIDR, ej. 192.168.1.0/24): ")
    ports = [8080, 443, 444]
    print(f"Escaneando la red {cidr} en los puertos {ports}...")

    results = scan_network(cidr, ports)
    print("\nResultados del escaneo:")
    for result in results:
        if "error" in result:
            print(f"{result['ip']}:{result['port']} - Error: {result['error']}")
        else:
            status = "Caducado" if result["is_expired"] else "Válido"
            signature = "Autofirmado" if result["is_self_signed"] else "Certificado válido"
            print(f"{result['ip']}:{result['port']} - Estado: {status}, {signature}, Vence: {result.get('expiration_date', 'N/A')}")

if __name__ == "__main__":
    main()