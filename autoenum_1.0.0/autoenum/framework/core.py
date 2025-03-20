#!/usr/bin/env python3
"""
Módulo core para AutoEnum
"""

import os
import sys
import logging
import importlib
import json
from datetime import datetime

logger = logging.getLogger("AutoEnum.Core")

class AutoEnumFramework:
    """Framework principal de AutoEnum"""
    
    def __init__(self, config=None):
        """Inicializa el framework"""
        self.config = config or {}
        self.modules = {}
        
        # Cargar módulos
        self._load_modules()
    
    def _load_modules(self):
        """Carga los módulos disponibles"""
        logger.debug("Cargando módulos...")
        
        # Directorio de módulos
        modules_dir = os.path.join(os.path.dirname(__file__), "..", "modules")
        
        # Verificar si el directorio existe
        if not os.path.exists(modules_dir):
            logger.warning(f"Directorio de módulos no encontrado: {modules_dir}")
            return
        
        # Buscar módulos
        for item in os.listdir(modules_dir):
            if item.startswith("__"):
                continue
            
            module_path = os.path.join(modules_dir, item)
            
            # Verificar si es un archivo Python
            if os.path.isfile(module_path) and item.endswith(".py"):
                module_name = item[:-3]  # Eliminar .py
                
                try:
                    # Importar módulo
                    spec = importlib.util.spec_from_file_location(
                        f"autoenum.modules.{module_name}", 
                        module_path
                    )
                    module = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(module)
                    
                    # Verificar si el módulo tiene la función scan
                    if hasattr(module, "scan"):
                        # Obtener información del módulo
                        module_info = getattr(module, "MODULE_INFO", {
                            "name": module_name,
                            "description": "No description",
                            "author": "Unknown",
                            "version": "1.0.0"
                        })
                        
                        # Registrar módulo
                        self.modules[module_name] = {
                            "module": module,
                            "info": module_info
                        }
                        
                        logger.debug(f"Módulo cargado: {module_name} v{module_info.get('version', '1.0.0')}")
                
                except Exception as e:
                    logger.error(f"Error al cargar módulo {module_name}: {e}")
        
        logger.info(f"Se cargaron {len(self.modules)} módulos")
    
    def scan(self, target, options=None):
        """Ejecuta un escaneo completo"""
        if options is None:
            options = {}
        
        logger.info(f"Iniciando escaneo en {target}")
        
        # Resultados
        results = {
            "target": target,
            "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "modules": {},
            "duration": 0
        }
        
        # Tiempo de inicio
        start_time = datetime.now()
        
        # Ejecutar módulos según opciones
        if options.get("ports") is not None:
            results["modules"]["port_scanner"] = self._run_module("port_scanner", target, {
                "ports": options.get("ports"),
                "threads": options.get("threads", 10),
                "timeout": options.get("timeout", 5),
                "evasion": options.get("evasion", {})
            })
        
        if options.get("service_detection", False):
            # Usar resultados del escaneo de puertos
            ports = []
            if "port_scanner" in results["modules"]:
                ports = results["modules"]["port_scanner"].get("ports", [])
            
            results["modules"]["service_detection"] = self._run_module("service_detection", target, {
                "ports": ports,
                "threads": options.get("threads", 10),
                "timeout": options.get("timeout", 5)
            })
        
        if options.get("os_detection", False):
            results["modules"]["os_detection"] = self._run_module("os_detection", target, {
                "timeout": options.get("timeout", 5)
            })
        
        if options.get("web_scan", False):
            # Verificar si hay puertos web (80, 443, etc.)
            web_ports = []
            if "port_scanner" in results["modules"]:
                for port_info in results["modules"]["port_scanner"].get("ports", []):
                    port = port_info.get("port", 0)
                    if port in [80, 443, 8080, 8443]:
                        web_ports.append(port)
            
            results["modules"]["web_scanner"] = self._run_module("web_scanner", target, {
                "ports": web_ports,
                "threads": options.get("threads", 10),
                "timeout": options.get("timeout", 5),
                "wordlist": options.get("wordlist"),
                "user_agent": options.get("evasion", {}).get("random_agent", False)
            })
        
        # Calcular duración
        duration = (datetime.now() - start_time).total_seconds()
        results["duration"] = duration
        
        logger.info(f"Escaneo completado en {duration:.2f} segundos")
        
        return results
    
    def _run_module(self, module_name, target, options=None):
        """Ejecuta un módulo específico"""
        if options is None:
            options = {}
        
        if module_name not in self.modules:
            logger.warning(f"Módulo no encontrado: {module_name}")
            return {"error": "Módulo no encontrado"}
        
        try:
            logger.info(f"Ejecutando módulo: {module_name}")
            
            # Obtener módulo
            module = self.modules[module_name]["module"]
            
            # Ejecutar función scan
            result = module.scan(target, options)
            
            logger.info(f"Módulo {module_name} completado")
            
            return result
        
        except Exception as e:
            logger.error(f"Error al ejecutar módulo {module_name}: {e}")
            return {"error": str(e)}
    
    def generate_report(self, results):
        """Genera un informe de los resultados"""
        report = []
        
        # Encabezado
        report.append("# Informe de Escaneo y Enumeración")
        report.append(f"**Target:** {results.get('target', 'No especificado')}")
        report.append(f"**Fecha:** {results.get('scan_time', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))}")
        report.append(f"**Duración:** {results.get('duration', 0):.2f} segundos")
        
        # Resumen
        report.append("\n## Resumen")
        
        # Puertos y servicios
        if "modules" in results and "port_scanner" in results["modules"]:
            port_module = results["modules"]["port_scanner"]
            
            if "ports" in port_module:
                open_ports = [p for p in port_module["ports"] if p.get("state") == "open"]
                report.append(f"\nSe encontraron {len(open_ports)} puertos abiertos.")
        
        # Sistema operativo
        if "modules" in results and "os_detection" in results["modules"]:
            os_module = results["modules"]["os_detection"]
            
            if "most_likely_os" in os_module:
                report.append(f"\nSistema Operativo detectado: {os_module['most_likely_os']}")
        
        # Servicios web
        if "modules" in results and "web_scanner" in results["modules"]:
            web_module = results["modules"]["web_scanner"]
            
            if "directories" in web_module:
                report.append(f"\nSe encontraron {len(web_module['directories'])} directorios/archivos web.")
        
        # Detalles
        report.append("\n## Detalles")
        
        # Puertos y servicios
        if "modules" in results and "port_scanner" in results["modules"]:
            port_module = results["modules"]["port_scanner"]
            
            report.append("\n### Puertos y Servicios")
            
            if "ports" in port_module:
                report.append("\n| Puerto | Estado | Servicio |")
                report.append("| ------ | ------ | -------- |")
                
                for port_info in port_module["ports"]:
                    port = port_info.get("port", "")
                    state = port_info.get("state", "")
                    service = port_info.get("service", "")
                    
                    report.append(f"| {port} | {state} | {service} |")
        
        # Sistema operativo
        if "modules" in results and "os_detection" in results["modules"]:
            os_module = results["modules"]["os_detection"]
            
            report.append("\n### Sistema Operativo")
            
            if "os" in os_module and os_module["os"]:
                report.append("\n| Sistema Operativo | Confianza | Método |")
                report.append("| ---------------- | --------- | ------ |")
                
                for os_info in os_module["os"]:
                    name = os_info.get("name", "")
                    confidence = os_info.get("confidence", "")
                    method = os_info.get("method", "")
                    
                    report.append(f"| {name} | {confidence} | {method} |")
        
        # Servicios web
        if "modules" in results and "web_scanner" in results["modules"]:
            web_module = results["modules"]["web_scanner"]
            
            report.append("\n### Servicios Web")
            
            if "web_server" in web_module:
                report.append(f"\n**Servidor Web:** {web_module['web_server']}")
            
            if "technologies" in web_module and web_module["technologies"]:
                report.append(f"\n**Tecnologías detectadas:**")
                for tech in web_module["technologies"]:
                    report.append(f"- {tech}")
            
            if "directories" in web_module:
                report.append("\n**Directorios y archivos encontrados:**")
                report.append("\n| URL | Estado | Tamaño |")
                report.append("| --- | ------ | ------ |")
                
                for directory in web_module["directories"]:
                    url = directory.get("url", "")
                    status = directory.get("status", "")
                    size = directory.get("size", "")
                    
                    report.append(f"| {url} | {status} | {size} |")
        
        # Recomendaciones
        report.append("\n## Recomendaciones")
        
        # Puertos abiertos
        if "modules" in results and "port_scanner" in results["modules"]:
            port_module = results["modules"]["port_scanner"]
            
            if "ports" in port_module:
                open_ports = [p for p in port_module["ports"] if p.get("state") == "open"]
                
                if open_ports:
                    report.append("\n### Puertos Abiertos")
                    report.append("\nSe recomienda revisar la necesidad de mantener abiertos los siguientes puertos:")
                    
                    for port_info in open_ports:
                        port = port_info.get("port", "")
                        service = port_info.get("service", "")
                        
                        if service:
                            report.append(f"- Puerto {port} ({service})")
                        else:
                            report.append(f"- Puerto {port}")
        
        # Conclusión
        report.append("\n## Conclusión")
        report.append("\nEste informe fue generado automáticamente por AutoEnum Framework.")
        
        return "\n".join(report)