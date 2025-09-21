"""
Configuración para la API de Email Verifier
"""

from pydantic_settings import BaseSettings
from typing import List

class Settings(BaseSettings):
    # Información de la aplicación
    app_name: str = "Email Verifier API"
    version: str = "1.0.0"
    description: str = "API profesional para validación de emails con múltiples niveles de verificación"
    debug: bool = True
    
    # Configuración del servidor
    host: str = "0.0.0.0"
    port: int = 8000
    reload: bool = True
    
    # Configuración CORS
    allowed_origins: List[str] = ["*"]  # En producción, especificar dominios
    allowed_methods: List[str] = ["*"]
    allowed_headers: List[str] = ["*"]
    
    # Configuración de validación
    dns_timeout: int = 5
    smtp_timeout: int = 10
    max_retries: int = 2
    
    # Configuración de rate limiting
    rate_limit_per_minute: int = 60
    rate_limit_per_hour: int = 1000
    max_bulk_emails: int = 100
    bulk_timeout_seconds: int = 300
    
    # Configuración de logging
    log_level: str = "INFO"
    log_format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    
    # Configuración de archivos
    data_dir: str = "data"
    logs_dir: str = "logs"
    
    # Configuración de cache (futuro)
    cache_ttl_seconds: int = 3600
    
    # Configuración de seguridad (futuro)
    api_key_header: str = "X-API-Key"
    require_api_key: bool = False
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"

# Instancia global
settings = Settings()