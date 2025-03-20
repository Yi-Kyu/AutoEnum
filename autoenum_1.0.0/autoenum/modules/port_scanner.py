#!/usr/bin/env python3
"""
Módulo de escaneo de puertos para AutoEnum
"""

import socket
import logging
import time
import random
from concurrent.futures import ThreadPoolExecutor

logger = logging.getLogger("AutoEnum.PortScanner")

# Información del módulo
MODULE_INFO = {
    "name": "port_scanner",
    "description": "Escáner de puertos TCP",
    "author": "AutoEnum Team",
    "version": "1.0.0",
    "category": "reconnaissance"
}

def scan_port(target, port, timeout=5):
    """Escanea un puerto específico"""
    try:
        # Crear socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        
        # Intentar conectar
        result = s.connect_ex((target, port))
        
        # Cerrar socket
        s.close()
        
        if result == 0:
            # Puerto abierto
            return {
                "port": port,
                "state": "open",
                "service": get_service_name(port)
            }
        else:
            # Puerto cerrado o filtrado
            return {
                "port": port,
                "state": "closed",
                "service": ""
            }
    
    except socket.gaierror:
        logger.error(f"Error de resolución de nombre: {target}")
        return {
            "port": port,
            "state": "error",
            "service": ""
        }
    
    except socket.error:
        return {
            "port": port,
            "state": "filtered",
            "service": ""
        }
    
    except Exception as e:
        logger.error(f"Error al escanear puerto {port}: {e}")
        return {
            "port": port,
            "state": "error",
            "service": ""
        }

def get_service_name(port):
    """Obtiene el nombre del servicio para un puerto"""
    try:
        return socket.getservbyport(port)
    except:
        # Servicios comunes no registrados
        common_services = {
            8080: "http-alt",
            8443: "https-alt",
            3306: "mysql",
            5432: "postgresql",
            27017: "mongodb",
            6379: "redis",
            9200: "elasticsearch",
            9300: "elasticsearch-cluster"
        }
        
        return common_services.get(port, "")

def parse_ports(ports_str):
    """Parsea una cadena de puertos (ej: 80,443,22 o 1-1000)"""
    ports = []
    
    if not ports_str:
        # Puertos comunes por defecto
        return [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]
    
    parts = ports_str.split(",")
    
    for part in parts:
        if "-" in part:
            # Rango de puertos
            start, end = part.split("-")
            ports.extend(range(int(start), int(end) + 1))
        else:
            # Puerto individual
            ports.append(int(part))
    
    return ports

def scan(target, options=None):
    """Función principal de escaneo de puertos"""
    if options is None:
        options = {}
    
    logger.info(f"Iniciando escaneo de puertos en {target}")
    
    # Opciones
    ports_str = options.get("ports", "")
    threads = options.get("threads", 10)
    timeout = options.get("timeout", 5)
    evasion = options.get("evasion", {})
    
    # Parsear puertos
    ports = parse_ports(ports_str)
    
    # Aplicar técnicas de evasión
    if evasion.get("enabled", False):
        # Aleatorizar orden de puertos
        random.shuffle(ports)
        
        # Aplicar retraso
        delay = evasion.get("delay", 0.0)
        if delay > 0:
            logger.info(f"Aplicando retraso de {delay} segundos entre escaneos")
    
    # Resultados
    results = {
        "target": target,
        "ports": []
    }
    
    # Resolver IP
    try:
        ip = socket.gethostbyname(target)
        results["ip"] = ip
    except socket.gaierror:
        logger.error(f"No se pudo resolver el nombre: {target}")
        return results
    
    # Escanear puertos
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = []
        
        for port in ports:
            # Aplicar retraso si está habilitado
            if evasion.get("enabled", False) and evasion.get("delay", 0.0) > 0:
                time.sleep(evasion.get("delay", 0.0))
            
            futures.append(executor.submit(scan_port, target, port, timeout))
        
        for future in futures:
            try:
                result = future.result()
                
                # Solo añadir puertos abiertos o filtrados
                if result["state"] in ["open", "filtered"]:
                    results["ports"].append(result)
            except Exception as e:
                logger.error(f"Error en escaneo de puertos: {e}")
    
    # Ordenar puertos
    results["ports"].sort(key=lambda x: x["port"])
    
    logger.info(f"Escaneo de puertos completado. Encontrados {len(results['ports'])} puertos abiertos/filtrados.")
    
    return results

if __name__ == "__main__":
    # Configuración para pruebas
    logging.basicConfig(level=logging.INFO)
    
    import sys
    if len(sys.argv) > 1:
        target = sys.argv[1]
        ports = sys.argv[2] if len(sys.argv) > 2 else "1-1000"
        
        results = scan(target, {"ports": ports})
        
        print(f"Resultados para {target} ({results.get('ip', 'desconocido')}):")
        
        for port_info in results["ports"]:
            port = port_info["port"]
            state = port_info["state"]
            service = port_info["service"]
            
            if service:
                print(f"Puerto {port} ({service}): {state}")
            else:
                print(f"Puerto {port}: {state}")
    else:
        print("Uso: python port_scanner.py <target> [ports]")