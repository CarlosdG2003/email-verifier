#!/usr/bin/env python3
"""
Script para ejecutar la API de Email Verifier
Ejecutar desde la raíz del proyecto: python run_api.py
"""

import os
import sys
import uvicorn
from pathlib import Path

# Añadir el directorio raíz al path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

if __name__ == "__main__":
    print("Iniciando Email Verifier API...")
    print("Documentación: http://localhost:8000/docs")
    print("Presiona Ctrl+C para detener")
    
    # Ejecutar directamente con uvicorn
    uvicorn.run(
        "api.main:app",  # Importar la app directamente
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )