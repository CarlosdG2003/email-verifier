"""
Modelos Pydantic para la API de Email Verifier
"""

from pydantic import BaseModel, EmailStr, validator, Field
from typing import List, Optional, Dict, Any
from datetime import datetime

# Modelos para requests
class EmailValidationRequest(BaseModel):
    """Request para validación individual"""
    email: EmailStr = Field(..., description="Email a validar")
    level: str = Field(default="basic", description="Nivel de validación")
    
    @validator('level')
    def validate_level(cls, v):
        valid_levels = ['basic', 'standard', 'professional']
        if v not in valid_levels:
            raise ValueError(f'Level debe ser uno de: {", ".join(valid_levels)}')
        return v

class BulkEmailValidationRequest(BaseModel):
    """Request para validación masiva"""
    emails: List[EmailStr] = Field(..., description="Lista de emails a validar")
    level: str = Field(default="basic", description="Nivel de validación")
    
    @validator('emails')
    def validate_emails_count(cls, v):
        if len(v) == 0:
            raise ValueError('Debe proporcionar al menos un email')
        if len(v) > 100:  # Limitar requests masivos
            raise ValueError('Máximo 100 emails por request')
        return v
    
    @validator('level')
    def validate_level(cls, v):
        valid_levels = ['basic', 'standard', 'professional']
        if v not in valid_levels:
            raise ValueError(f'Level debe ser uno de: {", ".join(valid_levels)}')
        return v

# Modelos para responses
class ValidationCheckResponse(BaseModel):
    """Respuesta de una validación individual"""
    is_valid: bool
    score: int
    details: Dict[str, Any]
    processing_time_ms: float
    error_message: Optional[str] = None

class EmailValidationResponse(BaseModel):
    """Respuesta completa de validación de email"""
    email: str
    level: str
    overall_status: str
    confidence: float
    risk_score: float
    fraud_indicators: List[str]
    basic_checks: Dict[str, ValidationCheckResponse]
    standard_checks: Optional[Dict[str, ValidationCheckResponse]] = None
    professional_checks: Optional[Dict[str, ValidationCheckResponse]] = None
    recommendations: List[str]
    processing_time_ms: float
    timestamp: str

class TaskStatus(BaseModel):
    """Estado de una tarea de validación masiva"""
    task_id: str
    status: str = Field(..., description="pending, processing, completed, failed")
    progress: int = Field(default=0, description="Progreso de 0 a 100")
    total_emails: int
    processed_emails: int = 0
    created_at: str
    completed_at: Optional[str] = None
    estimated_completion: Optional[str] = None

class BulkValidationSummary(BaseModel):
    """Resumen de validación masiva"""
    total_emails: int
    valid_emails: int
    invalid_emails: int
    risky_emails: int
    error_emails: int
    average_confidence: float
    average_risk_score: float
    average_processing_time_ms: float

class BulkValidationResponse(BaseModel):
    """Respuesta de validación masiva completa"""
    task_id: str
    total_emails: int
    processed_emails: int
    results: List[EmailValidationResponse]
    summary: BulkValidationSummary
    processing_time_ms: float
    timestamp: str

class APIStatsResponse(BaseModel):
    """Estadísticas de la API"""
    total_validations: int
    validations_today: int
    success_rate: float
    average_response_time_ms: float
    active_bulk_tasks: int
    uptime_seconds: float

class HealthCheckResponse(BaseModel):
    """Health check response"""
    status: str
    service: str
    version: str
    timestamp: str
    debug: bool
    components: Dict[str, str] = Field(default_factory=dict)

class ErrorResponse(BaseModel):
    """Respuesta de error estándar"""
    error: str
    message: str
    timestamp: str
    request_id: Optional[str] = None

# Modelos para configuración
class DomainListResponse(BaseModel):
    """Lista de dominios para configuración"""
    disposable_domains: int
    free_domains: int
    blacklist_domains: int
    last_updated: str

class ValidatorStatsResponse(BaseModel):
    """Estadísticas de los validadores"""
    disposable_domains: int
    free_domains: int
    blacklist_domains: int
    suspicious_patterns: int
    dkim_selectors: int
    dns_timeout: int
    smtp_timeout: int