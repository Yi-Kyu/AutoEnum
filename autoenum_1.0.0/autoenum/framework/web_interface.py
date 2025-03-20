#!/usr/bin/env python3
"""
Módulo de escaneo web para AutoEnum
"""

import requests
import logging
import time
import random
import re
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor
from bs4 import BeautifulSoup

logger = logging.getLogger("AutoEnum.WebScanner")

# Información del módulo
MODULE_INFO = {
    "name": "web_scanner",
    "description": "Escáner web básico",
    "author": "AutoEnum Team",
    "version": "1.0.0",
    "category": "reconnaissance"
}

# Lista de User-Agents
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/91.0.864.59 Safari/537.36"
]

def get_random_user_agent():
    """Obtiene un User-Agent aleatorio"""
    return random.choice(USER_AGENTS)

def check_url(url, timeout=5, user_agent=None):
    """Verifica una URL"""
    try:
        headers = {}
        
        if user_agent:
            if user_agent == "random":
                headers["User-Agent"] = get_random_user_agent()
            else:
                headers["User-Agent"] = user_agent
        
        response = requests.get(url, timeout=timeout, headers=headers, allow_redirects=True, verify=False)
        
        return {
            "url": url,
            "status": response.status_code,
            "size": len(response.content),
            "title": get_page_title(response.text) if response.status_code == 200 else "",
            "server": response.headers.get("Server", ""),
            "content_type": response.headers.get("Content-Type", "")
        }
    
    except requests.exceptions.RequestException as e:
        logger.debug(f"Error al verificar URL {url}: {e}")
        return {
            "url": url,
            "status": 0,
            "size": 0,
            "title": "",
            "server": "",
            "content_type": ""
        }

def get_page_title(html):
    """Extrae el título de una página HTML"""
    try:
        soup = BeautifulSoup(html, "html.parser")
        title = soup.title.string if soup.title else ""
        return title.strip()
    except:
        return ""

def detect_technologies(response):
    """Detecta tecnologías web basadas en cabeceras y contenido"""
    technologies = []
    
    # Verificar cabeceras
    headers = response.headers
    
    if "X-Powered-By" in headers:
        value = headers["X-Powered-By"]
        technologies.append(value)
    
    if "Server" in headers:
        value = headers["Server"]
        technologies.append(value)
    
    # Verificar cookies
    cookies = response.cookies
    
    if "PHPSESSID" in cookies:
        technologies.append("PHP")
    
    if "JSESSIONID" in cookies:
        technologies.append("Java")
    
    if "ASP.NET_SessionId" in cookies:
        technologies.append("ASP.NET")
    
    # Verificar contenido
    content = response.text.lower()
    
    patterns = {
        "WordPress": [r"wp-content", r"wp-includes"],
        "Joomla": [r"joomla", r"com_content"],
        "Drupal": [r"drupal", r"sites/all"],
        "jQuery": [r"jquery"],
        "Bootstrap": [r"bootstrap"],
        "React": [r"react", r"reactjs"],
        "Angular": [r"angular", r"ng-"],
        "Vue.js": [r"vue", r"vuejs"]
    }
    
    for tech, patterns_list in patterns.items():
        for pattern in patterns_list:
            if re.search(pattern, content):
                technologies.append(tech)
                break
    
    return list(set(technologies))

def directory_bruteforce(base_url, wordlist, threads=10, timeout=5, user_agent=None):
    """Realiza fuerza bruta de directorios"""
    results = []
    
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = []
        
        for word in wordlist:
            word = word.strip()
            
            if not word or word.startswith("#"):
                continue
            
            url = urljoin(base_url, word)
            futures.append(executor.submit(check_url, url, timeout, user_agent))
        
        for future in futures:
            try:
                result = future.result()
                
                # Solo añadir resultados con respuesta
                if result["status"] != 0:
                    results.append(result)
            except Exception as e:
                logger.error(f"Error en fuerza bruta de directorios: {e}")
    
    return results

def load_wordlist(wordlist_path):
    """Carga una wordlist desde un archivo"""
    try:
        with open(wordlist_path, "r") as f:
            return f.readlines()
    except Exception as e:
        logger.error(f"Error al cargar wordlist {wordlist_path}: {e}")
        
        # Wordlist mínima por defecto
        return [
            "admin", "login", "wp-admin", "administrator", "phpmyadmin",
            "dashboard", "wp-login.php", "admin.php", "index.php",
            "images", "img", "css", "js", "static", "assets",
            "api", "v1", "v2", "docs", "documentation",
            "backup", "bak", "old", "new", "test", "dev",
            "robots.txt", "sitemap.xml", ".git", ".env"
        ]

def scan(target, options=None):
    """Función principal de escaneo web"""
    if options is None:
        options = {}
    
    logger.info(f"Iniciando escaneo web en {target}")
    
    # Opciones
    ports = options.get("ports", [80, 443])
    threads = options.get("threads", 10)
    timeout = options.get("timeout", 5)
    wordlist_path = options.get("wordlist")
    user_agent = options.get("user_agent", False)
    
    # Configurar User-Agent
    if user_agent:
        user_agent = "random"
    else:
        user_agent = None
    
    # Resultados
    results = {
        "target": target,
        "web_server": "",
        "technologies": [],
        "directories": []
    }
    
    # Verificar si el objetivo ya incluye protocolo
    if target.startswith(("http://", "https://")):
        urls = [target]
    else:
        # Crear URLs para cada puerto
        urls = []
        
        for port in ports:
            if port == 80:
                urls.append(f"http://{target}")
            elif port == 443:
                urls.append(f"https://{target}")
            else:
                urls.append(f"http://{target}:{port}")
    
    # Verificar URLs base
    for url in urls:
        logger.info(f"Verificando URL base: {url}")
        
        result = check_url(url, timeout, user_agent)
        
        if result["status"] != 0:
            # URL accesible
            results["directories"].append(result)
            
            # Guardar información del servidor web
            if result["server"]:
                results["web_server"] = result["server"]
            
            # Detectar tecnologías
            try:
                response = requests.get(url, timeout=timeout, headers={"User-Agent": get_random_user_agent() if user_agent else "AutoEnum Scanner"}, verify=False)
                
                if response.status_code == 200:
                    technologies = detect_technologies(response)
                    results["technologies"].extend(technologies)
            except:
                pass
            
            # Realizar fuerza bruta de directorios
            if wordlist_path:
                wordlist = load_wordlist(wordlist_path)
            else:
                # Usar wordlist mínima por defecto
                wordlist = load_wordlist("")
            
            logger.info(f"Iniciando fuerza bruta de directorios en {url} con {len(wordlist)} palabras")
            
            bruteforce_results = directory_bruteforce(url, wordlist, threads, timeout, user_agent)
            results["directories"].extend(bruteforce_results)
    
    # Eliminar duplicados y ordenar directorios
    unique_dirs = {}
    for dir_info in results["directories"]:
        unique_dirs[dir_info["url"]] = dir_info
    
    results["directories"] = list(unique_dirs.values())
    results["directories"].sort(key=lambda x: x["url"])
    
    # Eliminar duplicados en tecnologías
    results["technologies"] = list(set(results["technologies"]))
    
    logger.info(f"Escaneo web completado. Encontrados {len(results['directories'])} directorios/archivos.")
    
    return results

if __name__ == "__main__":
    # Configuración para pruebas
    logging.basicConfig(level=logging.INFO)
    requests.packages.urllib3.disable_warnings()
    
    import sys
    if len(sys.argv) > 1:
        target = sys.argv[1]
        
        results = scan(target)
        
        print(f"Resultados para {target}:")
        print(f"Servidor Web: {results['web_server']}")
        
        if results["technologies"]:
            print(f"Tecnologías detectadas: {', '.join(results['technologies'])}")
        
        print("\nDirectorios/archivos encontrados:")
        for dir_info in results["directories"]:
            url = dir_info["url"]
            status = dir_info["status"]
            size = dir_info["size"]
            
            print(f"- {url} (Status: {status}, Size: {size})")
    else:
        print("Uso: python web_scanner.py <target>")
