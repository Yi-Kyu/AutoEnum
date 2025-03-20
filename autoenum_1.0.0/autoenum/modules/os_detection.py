#!/usr/bin/env python3
"""
Módulo de detección de sistema operativo para AutoEnum
"""

import socket
import struct
import logging
import subprocess
import platform
import re
import random

logger = logging.getLogger("AutoEnum.OSDetection")

# Información del módulo
MODULE_INFO = {
    "name": "os_detection",
    "description": "Detector de sistema operativo",
    "author": "AutoEnum Team",
    "version": "1.0.0",
    "category": "reconnaissance"
}

def detect_os_by_ttl(target, timeout=5):
    """Detecta el sistema operativo basado en el valor TTL"""
    try:
        # Determinar comando ping según plataforma
        if platform.system().lower() == "windows":
            ping_cmd = ["ping", "-n", "1", "-w", str(timeout * 1000), target]
        else:
            ping_cmd = ["ping", "-c", "1", "-W", str(timeout), target]
        
        # Ejecutar ping
        result = subprocess.run(ping_cmd, capture_output=True, text=True)
        
        # Buscar valor TTL
        ttl_match = re.search(r"TTL=(\d+)", result.stdout, re.IGNORECASE)
        
        if ttl_match:
            ttl = int(ttl_match.group(1))
            
            # Determinar OS basado en TTL
            if ttl <= 64:
                return {
                    "name": "Linux/Unix",
                    "confidence": "70%",
                    "method": "TTL"
                }
            elif ttl <= 128:
                return {
                    "name": "Windows",
                    "confidence": "70%",
                    "method": "TTL"
                }
            elif ttl <= 255:
                return {
                    "name": "Cisco/Network Device",
                    "confidence": "60%",
                    "method": "TTL"
                }
            else:
                return {
                    "name": "Unknown",
                    "confidence": "0%",
                    "method": "TTL"
                }
        else:
            logger.warning(f"No se pudo determinar TTL para {target}")
            return None
    
    except Exception as e:
        logger.error(f"Error al detectar OS por TTL: {e}")
        return None

def detect_os_by_tcp_window(target, port=80, timeout=5):
    """Detecta el sistema operativo basado en el tamaño de ventana TCP"""
    try:
        # Crear socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        
        # Conectar al objetivo
        s.connect((target, port))
        
        # Obtener información del socket
        sock_info = s.getsockopt(socket.SOL_TCP, socket.TCP_INFO, 92)
        
        # Cerrar socket
        s.close()
        
        # Extraer tamaño de ventana
        # Nota: Esto puede variar según la plataforma
        if len(sock_info) >= 16:
            window_size = struct.unpack("I", sock_info[12:16])[0]
            
            # Determinar OS basado en tamaño de ventana
            if window_size == 5840:
                return {
                    "name": "Linux",
                    "confidence": "60%",
                    "method": "TCP Window"
                }
            elif window_size == 16384:
                return {
                    "name": "Windows",
                    "confidence": "60%",
                    "method": "TCP Window"
                }
            elif window_size == 65535:
                return {
                    "name": "FreeBSD/OpenBSD",
                    "confidence": "60%",
                    "method": "TCP Window"
                }
            else:
                return {
                    "name": "Unknown",
                    "confidence": "0%",
                    "method": "TCP Window"
                }
        else:
            logger.warning(f"No se pudo determinar tamaño de ventana TCP para {target}")
            return None
    
    except Exception as e:
        logger.error(f"Error al detectar OS por TCP Window: {e}")
        return None

def detect_os_by_open_ports(ports):
    """Detecta el sistema operativo basado en puertos abiertos"""
    if not ports:
        return None
    
    # Puertos comunes por sistema operativo
    windows_ports = [135, 139, 445, 3389]
    linux_ports = [22, 111, 2049]
    network_device_ports = [23, 161, 162, 8291, 8728, 8729]
    
    # Contar coincidencias
    windows_count = sum(1 for p in ports if p in windows_ports)
    linux_count = sum(1 for p in ports if p in linux_ports)
    network_count = sum(1 for p in ports if p in network_device_ports)
    
    # Determinar OS basado en coincidencias
    if windows_count > linux_count and windows_count > network_count:
        confidence = min(windows_count * 20, 80)
        return {
            "name": "Windows",
            "confidence": f"{confidence}%",
            "method": "Open Ports"
        }
    elif linux_count > windows_count and linux_count > network_count:
        confidence = min(linux_count * 20, 80)
        return {
            "name": "Linux/Unix",
            "confidence": f"{confidence}%",
            "method": "Open Ports"
        }
    elif network_count > windows_count and network_count > linux_count:
        confidence = min(network_count * 20, 80)
        return {
            "name": "Network Device",
            "confidence": f"{confidence}%",
            "method": "Open Ports"
        }
    else:
        return {
            "name": "Unknown",
            "confidence": "0%",
            "method": "Open Ports"
        }

def scan(target, options=None):
    """Función principal de detección de sistema operativo"""
    if options is None:
        options = {}
    
    logger.info(f"Iniciando detección de sistema operativo en {target}")
    
    # Opciones
    timeout = options.get("timeout", 5)
    
    # Resultados
    results = {
        "target": target,
        "os": []
    }
    
    # Detectar por TTL
    ttl_result = detect_os_by_ttl(target, timeout)
    if ttl_result:
        results["os"].append(ttl_result)
    
    # Detectar por TCP Window (solo si hay puertos abiertos)
    if "ports" in options and options["ports"]:
        # Seleccionar un puerto abierto aleatorio
        open_ports = [p.get("port") for p in options["ports"] if p.get("state") == "open"]
        
        if open_ports:
            port = random.choice(open_ports)
            
            tcp_result = detect_os_by_tcp_window(target, port, timeout)
            if tcp_result:
                results["os"].append(tcp_result)
        
        # Detectar por puertos abiertos
        ports_result = detect_os_by_open_ports(open_ports)
        if ports_result:
            results["os"].append(ports_result)
    
    # Determinar el OS más probable
    if results["os"]:
        # Ordenar por confianza (de mayor a menor)
        results["os"].sort(key=lambda x: int(x.get("confidence", "0%").rstrip("%")), reverse=True)
        
        # El OS más probable es el primero
        results["most_likely_os"] = results["os"][0]["name"]
    else:
        results["most_likely_os"] = "Unknown"
    
    logger.info(f"Detección de sistema operativo completada. Resultado: {results['most_likely_os']}")
    
    return results

if __name__ == "__main__":
    # Configuración para pruebas
    logging.basicConfig(level=logging.INFO)
    
    import sys
    if len(sys.argv) > 1:
        target = sys.argv[1]
        
        results = scan(target)
        
        print(f"Resultados para {target}:")
        print(f"Sistema Operativo más probable: {results['most_likely_os']}")
        
        print("\nDetecciones:")
        for os_info in results["os"]:
            print(f"- {os_info['name']} ({os_info['confidence']} confianza, método: {os_info['method']})")
    else:
        print("Uso: python os_detection.py <target>")