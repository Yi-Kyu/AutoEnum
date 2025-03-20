"""
Módulos de escaneo para AutoEnum
"""

import os
import importlib
import logging

logger = logging.getLogger("AutoEnum.Modules")

# Lista de módulos disponibles
available_modules = []

# Cargar módulos automáticamente
def _load_available_modules():
    """Carga la lista de módulos disponibles"""
    global available_modules
    
    # Directorio actual
    current_dir = os.path.dirname(__file__)
    
    # Buscar archivos Python en el directorio
    for item in os.listdir(current_dir):
        if item.startswith("__"):
            continue
            
        if item.endswith(".py"):
            module_name = item[:-3]  # Eliminar .py
            available_modules.append(module_name)
            
    logger.debug(f"Módulos disponibles: {', '.join(available_modules)}")

# Cargar módulos al importar el paquete
_load_available_modules()

# Función para obtener un módulo por nombre
def get_module(module_name):
    """Obtiene un módulo por su nombre"""
    if module_name not in available_modules:
        return None
        
    try:
        return importlib.import_module(f"autoenum.modules.{module_name}")
    except ImportError as e:
        logger.error(f"Error al importar módulo {module_name}: {e}")
        return None
