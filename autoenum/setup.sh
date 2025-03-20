cat > setup.sh << 'EOF'
#!/bin/bash

# Colores para mejor visualización
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}╔════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║                                                        ║${NC}"
echo -e "${BLUE}║  ${GREEN}AutoEnum - Configuración Automática de Dependencias${BLUE}  ║${NC}"
echo -e "${BLUE}║                                                        ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════╝${NC}"
echo ""

# Verificar Python 3.6+
echo -e "${BLUE}[*] Verificando versión de Python...${NC}"
if command -v python3 &>/dev/null; then
    python_version=$(python3 --version 2>&1 | awk '{print $2}')
    python_major=$(echo $python_version | cut -d. -f1)
    python_minor=$(echo $python_version | cut -d. -f2)

    if [[ $python_major -ge 3 && $python_minor -ge 6 ]]; then
        echo -e "${GREEN}[✓] Python $python_version encontrado (cumple el requisito de 3.6+)${NC}"
        PYTHON_CMD="python3"
    else
        echo -e "${RED}[✗] Python $python_version encontrado, pero se requiere 3.6+${NC}"
        exit 1
    fi
else
    echo -e "${RED}[✗] Python 3 no encontrado${NC}"
    echo -e "${YELLOW}[!] Por favor, instala Python 3.6 o superior${NC}"
    exit 1
fi

# Verificar pip
echo -e "\n${BLUE}[*] Verificando pip...${NC}"
if command -v pip3 &>/dev/null; then
    echo -e "${GREEN}[✓] pip3 encontrado${NC}"
    PIP_CMD="pip3"
else
    echo -e "${YELLOW}[!] pip3 no encontrado, intentando instalar...${NC}"
    
    if command -v apt-get &>/dev/null; then
        sudo apt-get update
        sudo apt-get install -y python3-pip
        
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}[✓] pip3 instalado correctamente${NC}"
            PIP_CMD="pip3"
        else
            echo -e "${RED}[✗] Error al instalar pip3${NC}"
            exit 1
        fi
    else
        echo -e "${RED}[✗] No se pudo instalar pip3 automáticamente. Por favor, instálalo manualmente.${NC}"
        exit 1
    fi
fi

# Crear entorno virtual (opcional)
echo -e "\n${BLUE}[*] Configurando entorno virtual (opcional)...${NC}"
if command -v virtualenv &>/dev/null; then
    echo -e "${GREEN}[✓] virtualenv encontrado${NC}"

    read -p "¿Deseas usar un entorno virtual para AutoEnum? (recomendado) [S/n]: " use_venv
    use_venv=${use_venv:-S}

    if [[ $use_venv =~ ^[Ss]$ ]]; then
        echo -e "${BLUE}[*] Creando entorno virtual...${NC}"
        
        if [ -d "venv" ]; then
            echo -e "${YELLOW}[!] El directorio 'venv' ya existe. ¿Deseas eliminarlo y crear uno nuevo? [s/N]: ${NC}"
            read recreate_venv
            recreate_venv=${recreate_venv:-N}
            
            if [[ $recreate_venv =~ ^[Ss]$ ]]; then
                rm -rf venv
                virtualenv -p python3 venv
            fi
        else
            virtualenv -p python3 venv
        fi
        
        echo -e "${BLUE}[*] Activando entorno virtual...${NC}"
        source venv/bin/activate
        PIP_CMD="pip"
        echo -e "${GREEN}[✓] Entorno virtual activado${NC}"
    else
        echo -e "${YELLOW}[!] No se usará entorno virtual${NC}"
    fi
else
    echo -e "${YELLOW}[!] virtualenv no encontrado. Instalando...${NC}"
    $PIP_CMD install virtualenv
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}[✓] virtualenv instalado correctamente${NC}"
        echo -e "${YELLOW}[!] Por favor, ejecuta este script nuevamente para crear el entorno virtual${NC}"
        exit 0
    else
        echo -e "${YELLOW}[!] No se pudo instalar virtualenv. Continuando sin entorno virtual...${NC}"
    fi
fi

# Instalar dependencias
echo -e "\n${BLUE}[*] Instalando dependencias...${NC}"
$PIP_CMD install -r requirements.txt

if [ $? -eq 0 ]; then
    echo -e "${GREEN}[✓] Dependencias instaladas correctamente${NC}"
else
    echo -e "${RED}[✗] Error al instalar dependencias${NC}"
    exit 1
fi

# Verificar permisos de ejecución
echo -e "\n${BLUE}[*] Configurando permisos de ejecución...${NC}"
chmod +x autoenum.py
echo -e "${GREEN}[✓] Permisos de ejecución configurados para autoenum.py${NC}"

# Crear enlace simbólico (opcional)
echo -e "\n${BLUE}[*] ¿Deseas crear un enlace simbólico en /usr/local/bin? (requiere sudo) [s/N]: ${NC}"
read create_symlink
create_symlink=${create_symlink:-N}

if [[ $create_symlink =~ ^[Ss]$ ]]; then
    echo -e "${BLUE}[*] Creando enlace simbólico...${NC}"
    
    # Obtener ruta absoluta
    SCRIPT_PATH=$(realpath autoenum.py)
    
    sudo ln -sf $SCRIPT_PATH /usr/local/bin/autoenum
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}[✓] Enlace simbólico creado en /usr/local/bin/autoenum${NC}"
        echo -e "${GREEN}[✓] Ahora puedes ejecutar la herramienta desde cualquier ubicación con el comando 'autoenum'${NC}"
    else
        echo -e "${RED}[✗] Error al crear el enlace simbólico${NC}"
    fi
else
    echo -e "${YELLOW}[!] No se creará el enlace simbólico${NC}"
fi

echo -e "\n${GREEN}[✓] Configuración completada exitosamente!${NC}"
echo -e "${GREEN}[✓] AutoEnum está listo para usar${NC}"

echo -e "\n${BLUE}╔════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║                                                        ║${NC}"
echo -e "${BLUE}║  ${GREEN}Uso básico:${BLUE}                                       ║${NC}"
echo -e "${BLUE}║  ${YELLOW}./autoenum.py -t ejemplo.com -p 80,443,22 -s -w${BLUE}      ║${NC}"
echo -e "${BLUE}║                                                        ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════╝${NC}"
EOF

# Hacer ejecutable
chmod +x setup.sh