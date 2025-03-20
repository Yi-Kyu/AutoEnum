#!/usr/bin/env python3
"""
AutoEnum - Framework de Escaneo y Enumeración
"""

import os
import sys
import argparse
import logging
import json
import time
from datetime import datetime
from autoenum.framework.core import AutoEnumFramework

# Configurar logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("AutoEnum")

def parse_arguments():
    """Parsea los argumentos de línea de comandos"""
    parser = argparse.ArgumentParser(description="AutoEnum - Framework de Escaneo y Enumeración")
    
    # Argumentos básicos
    parser.add_argument("-t", "--target", help="Objetivo a escanear (IP o dominio)")
    parser.add_argument("-p", "--ports", help="Puertos a escanear (ej: 80,443,22 o 1-1000)")
    parser.add_argument("-s", "--service-detection", action="store_true", help="Activar detección de servicios")
    parser.add_argument("-o", "--os-detection", action="store_true", help="Activar detección de sistema operativo")
    parser.add_argument("-w", "--web-scan", action="store_true", help="Activar escaneo web")
    
    # Argumentos avanzados
    parser.add_argument("--threads", type=int, default=10, help="Número de hilos (default: 10)")
    parser.add_argument("--timeout", type=int, default=5, help="Timeout en segundos (default: 5)")
    parser.add_argument("--wordlist", help="Ruta a wordlist para fuerza bruta")
    parser.add_argument("--output", help="Archivo de salida para resultados")
    parser.add_argument("--format", choices=["json", "txt", "html", "md"], default="json", help="Formato de salida")
    
    # Argumentos de evasión
    parser.add_argument("--evasion", action="store_true", help="Activar técnicas de evasión")
    parser.add_argument("--delay", type=float, default=0.0, help="Retraso entre peticiones (segundos)")
    parser.add_argument("--random-agent", action="store_true", help="Usar User-Agent aleatorio")
    
    # Argumentos de informe
    parser.add_argument("--report", action="store_true", help="Generar informe detallado")
    parser.add_argument("--report-from", help="Generar informe a partir de archivo de resultados")
    
    # Argumentos de visualización
    parser.add_argument("--web-interface", action="store_true", help="Iniciar interfaz web")
    parser.add_argument("--web-port", type=int, default=5000, help="Puerto para interfaz web")
    
    # Argumentos de depuración
    parser.add_argument("--debug", action="store_true", help="Activar modo debug")
    parser.add_argument("--version", action="store_true", help="Mostrar versión")
    
    return parser.parse_args()

def main():
    """Función principal"""
    args = parse_arguments()
    
    # Configurar nivel de logging
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Mostrar versión
    if args.version:
        print("AutoEnum v1.0.0")
        return
    
    # Iniciar interfaz web
    if args.web_interface:
        try:
            from autoenum.framework.web_interface import WebInterface
            
            interface = WebInterface(port=args.web_port, debug=args.debug)
            interface.start()
            return
        except ImportError:
            logger.error("No se pudo importar el módulo de interfaz web")
            return
    
    # Generar informe a partir de archivo
    if args.report_from:
        if not os.path.exists(args.report_from):
            logger.error(f"Archivo no encontrado: {args.report_from}")
            return
        
        try:
            with open(args.report_from, "r") as f:
                results = json.load(f)
            
            framework = AutoEnumFramework()
            report = framework.generate_report(results)
            
            report_file = args.output or f"report_{int(time.time())}.{args.format}"
            
            with open(report_file, "w") as f:
                f.write(report)
            
            logger.info(f"Informe generado: {report_file}")
            return
        except Exception as e:
            logger.error(f"Error al generar informe: {e}")
            return
    
    # Verificar argumentos requeridos
    if not args.target:
        logger.error("Se requiere un objetivo (-t/--target)")
        return
    
    # Inicializar framework
    framework = AutoEnumFramework()
    
    # Preparar opciones
    options = {
        "ports": args.ports,
        "service_detection": args.service_detection,
        "os_detection": args.os_detection,
        "web_scan": args.web_scan,
        "threads": args.threads,
        "timeout": args.timeout,
        "wordlist": args.wordlist,
        "evasion": {
            "enabled": args.evasion,
            "delay": args.delay,
            "random_agent": args.random_agent
        }
    }
    
    # Ejecutar escaneo
    logger.info(f"Iniciando escaneo en {args.target}")
    start_time = time.time()
    
    results = framework.scan(args.target, options)
    
    elapsed_time = time.time() - start_time
    logger.info(f"Escaneo completado en {elapsed_time:.2f} segundos")
    
    # Guardar resultados
    if args.output:
        output_file = args.output
    else:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = f"results/{args.target}_{timestamp}.{args.format}"
    
    # Crear directorio si no existe
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    
    with open(output_file, "w") as f:
        if args.format == "json":
            json.dump(results, f, indent=2)
        else:
            # Para otros formatos, convertir a texto simple por ahora
            f.write(str(results))
    
    logger.info(f"Resultados guardados en {output_file}")
    
    # Generar informe
    if args.report:
        report = framework.generate_report(results)
        
        report_file = f"{os.path.splitext(output_file)[0]}_report.md"
        
        with open(report_file, "w") as f:
            f.write(report)
        
        logger.info(f"Informe generado: {report_file}")

if __name__ == "__main__":
    main()