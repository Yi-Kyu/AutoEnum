#!/usr/bin/env python3
"""
Módulo de interfaz web para AutoEnum
"""

import time
import sys
import os
import json
import logging
import threading
import webbrowser
from autoenum.framework.core import AutoEnumFramework
from datetime import datetime
from flask import Flask, render_template, request, jsonify, send_from_directory, redirect, url_for
from werkzeug.utils import secure_filename

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

logger = logging.getLogger("AutoEnum.WebInterface")

class WebInterface:
    """Interfaz web para AutoEnum Framework"""
    
    def __init__(self, port=5000, debug=False, framework=None):
        """Inicializa la interfaz web"""
        self.port = port
        self.debug = debug
        self.framework = framework
        self.app = Flask(__name__, 
                         template_folder=self._get_template_path(),
                         static_folder=self._get_static_path())
        self.server_thread = None
        self.configure_routes()
        
        logger.info(f"Interfaz web inicializada en puerto {port}")
    
    def _get_template_path(self):
        """Obtiene la ruta a los templates"""
        # Buscar en diferentes ubicaciones posibles
        possible_paths = [
            os.path.join(os.path.dirname(__file__), "templates"),
            os.path.join(os.path.dirname(__file__), "..", "templates"),
            os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates"),
            os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "templates")
        ]
        
        for path in possible_paths:
            if os.path.exists(path):
                return path
        
        # Si no se encuentra, crear directorio de templates
        default_path = os.path.join(os.path.dirname(__file__), "templates")
        os.makedirs(default_path, exist_ok=True)
        
        # Crear template básico si no existe
        index_template = os.path.join(default_path, "index.html")
        if not os.path.exists(index_template):
            with open(index_template, "w") as f:
                f.write(self._get_default_template())
        
        return default_path
    
    def _get_static_path(self):
        """Obtiene la ruta a los archivos estáticos"""
        # Buscar en diferentes ubicaciones posibles
        possible_paths = [
            os.path.join(os.path.dirname(__file__), "static"),
            os.path.join(os.path.dirname(__file__), "..", "static"),
            os.path.join(os.path.dirname(os.path.abspath(__file__)), "static"),
            os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "static")
        ]
        
        for path in possible_paths:
            if os.path.exists(path):
                return path
        
        # Si no se encuentra, crear directorio de estáticos
        default_path = os.path.join(os.path.dirname(__file__), "static")
        os.makedirs(default_path, exist_ok=True)
        
        # Crear CSS básico si no existe
        css_path = os.path.join(default_path, "css")
        os.makedirs(css_path, exist_ok=True)
        
        style_css = os.path.join(css_path, "style.css")
        if not os.path.exists(style_css):
            with open(style_css, "w") as f:
                f.write(self._get_default_css())
        
        # Crear JS básico si no existe
        js_path = os.path.join(default_path, "js")
        os.makedirs(js_path, exist_ok=True)
        
        main_js = os.path.join(js_path, "main.js")
        if not os.path.exists(main_js):
            with open(main_js, "w") as f:
                f.write(self._get_default_js())
        
        return default_path
    
    def _get_default_template(self):
        """Obtiene una plantilla HTML por defecto"""
        return """<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AutoEnum - Framework de Escaneo y Enumeración</title>
    <link rel="stylesheet" href="{{ url_for('static', filename='css/style.css') }}">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css">
</head>
<body>
    <div class="container">
        <header>
            <h1><i class="fas fa-search"></i> AutoEnum</h1>
            <p>Framework modular de escaneo y enumeración para pruebas de penetración</p>
        </header>
        
        <main>
            <section class="scan-form">
                <h2>Nuevo Escaneo</h2>
                <form id="scan-form" action="/scan" method="post">
                    <div class="form-group">
                        <label for="target">Objetivo:</label>
                        <input type="text" id="target" name="target" placeholder="ejemplo.com o 192.168.1.1" required>
                    </div>
                    
                    <div class="form-group">
                        <label for="ports">Puertos:</label>
                        <input type="text" id="ports" name="ports" placeholder="80,443,22 o 1-1000">
                    </div>
                    
                    <div class="options-group">
                        <div class="option">
                            <input type="checkbox" id="service-detection" name="service_detection">
                            <label for="service-detection">Detección de servicios</label>
                        </div>
                        
                        <div class="option">
                            <input type="checkbox" id="os-detection" name="os_detection">
                            <label for="os-detection">Detección de SO</label>
                        </div>
                        
                        <div class="option">
                            <input type="checkbox" id="web-scan" name="web_scan">
                            <label for="web-scan">Escaneo web</label>
                        </div>
                    </div>
                    
                    <div class="advanced-options">
                        <h3>Opciones avanzadas</h3>
                        
                        <div class="form-group">
                            <label for="threads">Hilos:</label>
                            <input type="number" id="threads" name="threads" min="1" max="50" value="10">
                        </div>
                        
                        <div class="form-group">
                            <label for="timeout">Timeout (segundos):</label>
                            <input type="number" id="timeout" name="timeout" min="1" max="60" value="5">
                        </div>
                        
                        <div class="option">
                            <input type="checkbox" id="evasion" name="evasion">
                            <label for="evasion">Técnicas de evasión</label>
                        </div>
                        
                        <div class="form-group">
                            <label for="delay">Retraso entre peticiones (segundos):</label>
                            <input type="number" id="delay" name="delay" min="0" max="10" step="0.1" value="0">
                        </div>
                        
                        <div class="option">
                            <input type="checkbox" id="random-agent" name="random_agent">
                            <label for="random-agent">User-Agent aleatorio</label>
                        </div>
                    </div>
                    
                    <div class="form-actions">
                        <button type="submit" class="btn primary">Iniciar Escaneo</button>
                        <button type="reset" class="btn secondary">Limpiar</button>
                    </div>
                </form>
            </section>
            
            <section class="results-section">
                <h2>Resultados Recientes</h2>
                <div id="results-list">
                    {% if scans %}
                        {% for scan in scans %}
                            <div class="result-item">
                                <div class="result-header">
                                    <h3>{{ scan.target }}</h3>
                                    <span class="timestamp">{{ scan.timestamp }}</span>
                                </div>
                                <div class="result-summary">
                                    <p>Puertos abiertos: {{ scan.open_ports }}</p>
                                    <p>Sistema Operativo: {{ scan.os }}</p>
                                </div>
                                <div class="result-actions">
                                    <a href="/results/{{ scan.id }}" class="btn small">Ver detalles</a>
                                    <a href="/results/{{ scan.id }}/download" class="btn small secondary">Descargar</a>
                                </div>
                            </div>
                        {% endfor %}
                    {% else %}
                        <p class="no-results">No hay resultados disponibles</p>
                    {% endif %}
                </div>
            </section>
        </main>
        
        <footer>
            <p>&copy; AutoEnum Framework</p>
        </footer>
    </div>
    
    <script src="{{ url_for('static', filename='js/main.js') }}"></script>
</body>
</html>
"""
    
    def _get_default_css(self):
        """Obtiene un CSS por defecto"""
        return """/* Variables */
:root {
    --primary-color: #e74c3c;
    --secondary-color: #3498db;
    --dark-color: #2c3e50;
    --light-color: #ecf0f1;
    --success-color: #2ecc71;
    --warning-color: #f39c12;
    --danger-color: #c0392b;
    --text-color: #333;
    --border-radius: 4px;
    --box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
}

/* Reset y estilos base */
* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}

body {
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    line-height: 1.6;
    color: var(--text-color);
    background-color: #f5f5f5;
}

.container {
    max-width: 1200px;
    margin: 0 auto;
    padding: 20px;
}

/* Encabezado */
header {
    background-color: var(--dark-color);
    color: white;
    padding: 20px;
    border-radius: var(--border-radius);
    margin-bottom: 20px;
    text-align: center;
}

header h1 {
    margin-bottom: 10px;
}

header p {
    opacity: 0.8;
}

/* Formulario de escaneo */
.scan-form {
    background-color: white;
    padding: 20px;
    border-radius: var(--border-radius);
    box-shadow: var(--box-shadow);
    margin-bottom: 20px;
}

.scan-form h2 {
    margin-bottom: 20px;
    color: var(--dark-color);
    border-bottom: 1px solid #eee;
    padding-bottom: 10px;
}

.form-group {
    margin-bottom: 15px;
}

.form-group label {
    display: block;
    margin-bottom: 5px;
    font-weight: bold;
}

.form-group input {
    width: 100%;
    padding: 10px;
    border: 1px solid #ddd;
    border-radius: var(--border-radius);
    font-size: 16px;
}

.options-group {
    display: flex;
    flex-wrap: wrap;
    gap: 20px;
    margin-bottom: 20px;
}

.option {
    display: flex;
    align-items: center;
    margin-bottom: 10px;
}

.option input[type="checkbox"] {
    margin-right: 10px;
}

.advanced-options {
    background-color: #f9f9f9;
    padding: 15px;
    border-radius: var(--border-radius);
    margin-bottom: 20px;
}

.advanced-options h3 {
    margin-bottom: 15px;
    font-size: 18px;
    color: var(--dark-color);
}

.form-actions {
    display: flex;
    gap: 10px;
}

/* Botones */
.btn {
    display: inline-block;
    padding: 10px 20px;
    background-color: var(--primary-color);
    color: white;
    border: none;
    border-radius: var(--border-radius);
    cursor: pointer;
    font-size: 16px;
    text-decoration: none;
    transition: background-color 0.3s;
}

.btn:hover {
    background-color: var(--danger-color);
}

.btn.secondary {
    background-color: #95a5a6;
}

.btn.secondary:hover {
    background-color: #7f8c8d;
}

.btn.small {
    padding: 5px 10px;
    font-size: 14px;
}

/* Resultados */
.results-section {
    background-color: white;
    padding: 20px;
    border-radius: var(--border-radius);
    box-shadow: var(--box-shadow);
}

.results-section h2 {
    margin-bottom: 20px;
    color: var(--dark-color);
    border-bottom: 1px solid #eee;
    padding-bottom: 10px;
}

.result-item {
    border: 1px solid #eee;
    border-radius: var(--border-radius);
    padding: 15px;
    margin-bottom: 15px;
}

.result-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 10px;
}

.result-header h3 {
    color: var(--primary-color);
}

.timestamp {
    color: #777;
    font-size: 14px;
}

.result-summary {
    margin-bottom: 15px;
}

.result-actions {
    display: flex;
    gap: 10px;
}

.no-results {
    color: #777;
    font-style: italic;
    text-align: center;
    padding: 20px;
}

/* Pie de página */
footer {
    text-align: center;
    margin-top: 30px;
    padding: 20px;
    color: #777;
    border-top: 1px solid #eee;
}

/* Responsive */
@media (max-width: 768px) {
    .options-group {
        flex-direction: column;
        gap: 5px;
    }
    
    .form-actions {
        flex-direction: column;
    }
    
    .btn {
        width: 100%;
        margin-bottom: 10px;
    }
}
"""
    
    def _get_default_js(self):
        """Obtiene un JavaScript por defecto"""
        return """document.addEventListener('DOMContentLoaded', function() {
    // Toggle para opciones avanzadas
    const advancedOptions = document.querySelector('.advanced-options');
    const advancedToggle = document.createElement('button');
    advancedToggle.type = 'button';
    advancedToggle.className = 'btn secondary';
    advancedToggle.textContent = 'Mostrar opciones avanzadas';
    advancedToggle.style.marginBottom = '20px';
    
    // Insertar el botón antes de las opciones avanzadas
    advancedOptions.parentNode.insertBefore(advancedToggle, advancedOptions);
    
    // Ocultar opciones avanzadas inicialmente
    advancedOptions.style.display = 'none';
    
    // Manejar clic en el botón
    advancedToggle.addEventListener('click', function() {
        if (advancedOptions.style.display === 'none') {
            advancedOptions.style.display = 'block';
            advancedToggle.textContent = 'Ocultar opciones avanzadas';
        } else {
            advancedOptions.style.display = 'none';
            advancedToggle.textContent = 'Mostrar opciones avanzadas';
        }
    });
    
    // Validación del formulario
    const scanForm = document.getElementById('scan-form');
    if (scanForm) {
        scanForm.addEventListener('submit', function(e) {
            const targetInput = document.getElementById('target');
            if (!targetInput.value.trim()) {
                e.preventDefault();
                alert('Por favor, ingresa un objetivo válido');
                targetInput.focus();
                return false;
            }
            
            // Mostrar indicador de carga
            const submitBtn = scanForm.querySelector('button[type="submit"]');
            submitBtn.disabled = true;
            submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Procesando...';
            
            // Continuar con el envío
            return true;
        });
    }
    
    // Actualización en tiempo real (si hay resultados en curso)
    function checkScanStatus() {
        const resultsList = document.getElementById('results-list');
        if (resultsList) {
            fetch('/api/scan-status')
                .then(response => response.json())
                .then(data => {
                    if (data.active_scans && data.active_scans.length > 0) {
                        // Actualizar la interfaz con los escaneos activos
                        updateActiveScansList(data.active_scans);
                        
                        // Programar la próxima actualización
                        setTimeout(checkScanStatus, 5000);
                    }
                })
                .catch(error => console.error('Error al verificar estado de escaneos:', error));
        }
    }
    
    function updateActiveScansList(activeScans) {
        const activeScansContainer = document.getElementById('active-scans');
        if (!activeScansContainer) {
            // Crear contenedor si no existe
            const resultsSection = document.querySelector('.results-section');
            const newContainer = document.createElement('div');
            newContainer.id = 'active-scans';
            newContainer.className = 'active-scans';
            newContainer.innerHTML = '<h3>Escaneos en Progreso</h3><div class="active-scans-list"></div>';
            resultsSection.insertBefore(newContainer, resultsSection.firstChild);
        }
        
        const activeScansListContainer = document.querySelector('.active-scans-list');
        activeScansListContainer.innerHTML = '';
        
        activeScans.forEach(scan => {
            const scanItem = document.createElement('div');
            scanItem.className = 'active-scan-item';
            scanItem.innerHTML = `
                <div class="scan-target">${scan.target}</div>
                <div class="scan-progress">
                    <div class="progress-bar" style="width: ${scan.progress}%"></div>
                </div>
                <div class="scan-status">${scan.status}</div>
            `;
            activeScansListContainer.appendChild(scanItem);
        });
    }
    
    // Iniciar verificación de estado
    checkScanStatus();
});
"""
    
    def configure_routes(self):
        """Configura las rutas de la aplicación Flask"""
        app = self.app
        
        @app.route('/')
        def index():
            """Página principal"""
            # Obtener escaneos recientes
            scans = self.get_recent_scans()
            return render_template('index.html', scans=scans)
        
        @app.route('/scan', methods=['POST'])
        def start_scan():
            """Inicia un nuevo escaneo"""
            if not self.framework:
                return jsonify({"error": "Framework no inicializado"}), 500
            
            # Obtener datos del formulario
            target = request.form.get('target')
            ports = request.form.get('ports')
            service_detection = 'service_detection' in request.form
            os_detection = 'os_detection' in request.form
            web_scan = 'web_scan' in request.form
            
            # Opciones avanzadas
            threads = int(request.form.get('threads', 10))
            timeout = int(request.form.get('timeout', 5))
            evasion_enabled = 'evasion' in request.form
            delay = float(request.form.get('delay', 0.0))
            random_agent = 'random_agent' in request.form
            
            # Validar datos
            if not target:
                return jsonify({"error": "Se requiere un objetivo"}), 400
            
            # Preparar opciones
            options = {
                "ports": ports,
                "service_detection": service_detection,
                "os_detection": os_detection,
                "web_scan": web_scan,
                "threads": threads,
                "timeout": timeout,
                "evasion": {
                    "enabled": evasion_enabled,
                    "delay": delay,
                    "random_agent": random_agent
                }
            }
            
            # Iniciar escaneo en un hilo separado
            scan_thread = threading.Thread(
                target=self._run_scan,
                args=(target, options)
            )
            scan_thread.daemon = True
            scan_thread.start()
            
            # Redirigir a la página de estado
            return redirect(url_for('scan_status', target=target))
        
        @app.route('/scan-status/<target>')
        def scan_status(target):
            """Muestra el estado de un escaneo"""
            # Aquí se mostraría una página con actualización en tiempo real
            return render_template('scan_status.html', target=target)
        
        @app.route('/results/<scan_id>')
        def view_results(scan_id):
            """Muestra los resultados de un escaneo"""
            # Obtener resultados del escaneo
            results = self.get_scan_results(scan_id)
            if not results:
                return jsonify({"error": "Resultados no encontrados"}), 404
            
            return render_template('results.html', results=results)
        
        @app.route('/results/<scan_id>/download')
        def download_results(scan_id):
            """Descarga los resultados de un escaneo"""
            # Obtener formato solicitado
            format_type = request.args.get('format', 'json')
            
            # Obtener resultados
            results_file = self.get_results_file(scan_id, format_type)
            if not results_file:
                return jsonify({"error": "Archivo no encontrado"}), 404
            
            # Enviar archivo
            return send_from_directory(
                os.path.dirname(results_file),
                os.path.basename(results_file),
                as_attachment=True
            )
        
        @app.route('/api/scan-status')
        def api_scan_status():
            """API para obtener el estado de los escaneos activos"""
            # Obtener escaneos activos
            active_scans = self.get_active_scans()
            return jsonify({"active_scans": active_scans})
    
    def _run_scan(self, target, options):
        """Ejecuta un escaneo en segundo plano"""
        try:
            # Registrar inicio de escaneo
            scan_id = self._generate_scan_id(target)
            self._register_active_scan(scan_id, target)
            
            # Ejecutar escaneo
            results = self.framework.scan(target, options)
            
            # Guardar resultados
            self._save_scan_results(scan_id, results)
            
            # Actualizar estado
            self._update_scan_status(scan_id, "completed")
            
            logger.info(f"Escaneo completado para {target}")
        
        except Exception as e:
            logger.error(f"Error en escaneo de {target}: {e}")
            self._update_scan_status(scan_id, f"error: {str(e)}")
    
    def _generate_scan_id(self, target):
        """Genera un ID único para un escaneo"""
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        return f"{target.replace('.', '_')}_{timestamp}"
    
    def _register_active_scan(self, scan_id, target):
        """Registra un escaneo activo"""
        # Aquí se implementaría el registro de escaneos activos
        # Por ejemplo, en una base de datos o archivo
        active_scans_file = os.path.join(self._get_results_dir(), "active_scans.json")
        
        active_scans = []
        if os.path.exists(active_scans_file):
            try:
                with open(active_scans_file, "r") as f:
                    active_scans = json.load(f)
            except:
                active_scans = []
        
        active_scans.append({
            "id": scan_id,
            "target": target,
            "start_time": datetime.now().isoformat(),
            "status": "running",
            "progress": 0
        })
        
        with open(active_scans_file, "w") as f:
            json.dump(active_scans, f, indent=2)
    
    def _update_scan_status(self, scan_id, status, progress=100):
        """Actualiza el estado de un escaneo"""
        active_scans_file = os.path.join(self._get_results_dir(), "active_scans.json")
        
        if not os.path.exists(active_scans_file):
            return
        
        try:
            with open(active_scans_file, "r") as f:
                active_scans = json.load(f)
            
            # Actualizar estado
            for scan in active_scans:
                if scan["id"] == scan_id:
                    scan["status"] = status
                    scan["progress"] = progress
                    if status == "completed" or status.startswith("error"):
                        scan["end_time"] = datetime.now().isoformat()
            
            # Filtrar escaneos completados o con error hace más de 1 hora
            current_time = datetime.now()
            active_scans = [
                scan for scan in active_scans
                if scan["status"] == "running" or
                ("end_time" in scan and 
                 (current_time - datetime.fromisoformat(scan["end_time"])).total_seconds() < 3600)
            ]
            
            with open(active_scans_file, "w") as f:
                json.dump(active_scans, f, indent=2)
        
        except Exception as e:
            logger.error(f"Error al actualizar estado de escaneo: {e}")
    
    def _save_scan_results(self, scan_id, results):
        """Guarda los resultados de un escaneo"""
        results_dir = self._get_results_dir()
        os.makedirs(results_dir, exist_ok=True)
        
        # Guardar en formato JSON
        json_file = os.path.join(results_dir, f"{scan_id}.json")
        with open(json_file, "w") as f:
            json.dump(results, f, indent=2)
        
        # Guardar en formato Markdown si hay método de generación de informes
        if self.framework and hasattr(self.framework, "generate_report"):
            report = self.framework.generate_report(results)
            md_file = os.path.join(results_dir, f"{scan_id}.md")
            with open(md_file, "w") as f:
                f.write(report)
    
    def _get_results_dir(self):
        """Obtiene el directorio de resultados"""
        # Buscar en diferentes ubicaciones posibles
        possible_paths = [
            os.path.join(os.path.dirname(__file__), "..", "..", "results"),
            os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "results"),
            os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "results")
        ]
        
        for path in possible_paths:
            if os.path.exists(path):
                return path
        
        # Si no se encuentra, crear directorio
        default_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "results")
        os.makedirs(default_path, exist_ok=True)
        return default_path
    
    def get_recent_scans(self, limit=10):
        """Obtiene los escaneos recientes"""
        results_dir = self._get_results_dir()
        scans = []
        
        if not os.path.exists(results_dir):
            return scans
        
        # Buscar archivos JSON de resultados
        json_files = [f for f in os.listdir(results_dir) if f.endswith(".json") and f != "active_scans.json"]
        
        # Ordenar por fecha de modificación (más recientes primero)
        json_files.sort(key=lambda x: os.path.getmtime(os.path.join(results_dir, x)), reverse=True)
        
        # Limitar cantidad
        json_files = json_files[:limit]
        
        # Cargar información básica
        for json_file in json_files:
            try:
                with open(os.path.join(results_dir, json_file), "r") as f:
                    data = json.load(f)
                
                # Extraer información básica
                scan_id = json_file.replace(".json", "")
                target = data.get("target", "Desconocido")
                timestamp = datetime.fromtimestamp(os.path.getmtime(os.path.join(results_dir, json_file))).strftime("%Y-%m-%d %H:%M:%S")
                
                # Contar puertos abiertos
                open_ports = 0
                if "modules" in data and "port_scanner" in data["modules"]:
                    port_data = data["modules"]["port_scanner"]
                    if "ports" in port_data:
                        open_ports = len([p for p in port_data["ports"] if p.get("state") == "open"])
                
                # Obtener sistema operativo detectado
                os_detected = "Desconocido"
                if "modules" in data and "os_detection" in data["modules"]:
                    os_data = data["modules"]["os_detection"]
                    if "most_likely_os" in os_data:
                        os_detected = os_data["most_likely_os"]
                
                scans.append({
                    "id": scan_id,
                    "target": target,
                    "timestamp": timestamp,
                    "open_ports": open_ports,
                    "os": os_detected
                })
            
            except Exception as e:
                logger.error(f"Error al cargar resultados de {json_file}: {e}")
        
        return scans
    
    def get_scan_results(self, scan_id):
        """Obtiene los resultados de un escaneo específico"""
        results_dir = self._get_results_dir()
        json_file = os.path.join(results_dir, f"{scan_id}.json")
        
        if not os.path.exists(json_file):
            return None
        
        try:
            with open(json_file, "r") as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Error al cargar resultados de {scan_id}: {e}")
            return None
    
    def get_results_file(self, scan_id, format_type="json"):
        """Obtiene el archivo de resultados en el formato especificado"""
        results_dir = self._get_results_dir()
        
        if format_type == "json":
            file_path = os.path.join(results_dir, f"{scan_id}.json")
        elif format_type == "md":
            file_path = os.path.join(results_dir, f"{scan_id}.md")
        else:
            return None
        
        if os.path.exists(file_path):
            return file_path
        
        return None
    
    def get_active_scans(self):
        """Obtiene los escaneos activos"""
        active_scans_file = os.path.join(self._get_results_dir(), "active_scans.json")
        
        if not os.path.exists(active_scans_file):
            return []
        
        try:
            with open(active_scans_file, "r") as f:
                active_scans = json.load(f)
            
            # Filtrar solo los escaneos en ejecución
            return [scan for scan in active_scans if scan["status"] == "running"]
        
        except Exception as e:
            logger.error(f"Error al cargar escaneos activos: {e}")
            return []
    
    def start(self):
        """Inicia el servidor web"""
        if self.server_thread and self.server_thread.is_alive():
            logger.warning("El servidor web ya está en ejecución")
            return
        
        def run_server():
            self.app.run(host="0.0.0.0", port=self.port, debug=self.debug, use_reloader=False)
        
        self.server_thread = threading.Thread(target=run_server)
        self.server_thread.daemon = True
        self.server_thread.start()
        
        logger.info(f"Servidor web iniciado en http://localhost:{self.port}")
        
        # Abrir navegador automáticamente
        webbrowser.open(f"http://localhost:{self.port}")
    
    def stop(self):
        """Detiene el servidor web"""
        if self.server_thread and self.server_thread.is_alive():
            # No hay una forma limpia de detener un servidor Flask en un hilo
            # Esta es una solución temporal
            logger.info("Deteniendo servidor web...")
            self.server_thread = None
        else:
            logger.warning("El servidor web no está en ejecución")

if __name__ == "__main__":
    # Configuración para pruebas
    logging.basicConfig(level=logging.INFO)
    
    # Crear interfaz web
    interface = WebInterface(port=5000, debug=True)
    
    # Iniciar servidor
    interface.start()
    
    # Mantener el script en ejecución
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Deteniendo servidor...")
