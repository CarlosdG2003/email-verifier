"""
Modelos de datos para el Email Verifier
Autor: Tu nombre
Fecha: 2025

Este archivo contiene las clases de datos utilizadas en todo el sistema.
"""

from dataclasses import dataclass
from typing import Dict, List, Any, Optional
from datetime import datetime

@dataclass
class ValidationResult:
    """
    Resultado de una validación individual
    
    Attributes:
        is_valid: Si la validación pasó o no
        score: Puntuación de 0-100 (100 = mejor)
        details: Información detallada de la validación
        processing_time_ms: Tiempo de procesamiento en milisegundos
        error_message: Mensaje de error si hubo algún problema
    """
    is_valid: bool
    score: int  # 0-100
    details: Dict[str, Any]
    processing_time_ms: float
    error_message: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convierte el resultado a diccionario"""
        return {
            "is_valid": self.is_valid,
            "score": self.score,
            "details": self.details,
            "processing_time_ms": self.processing_time_ms,
            "error_message": self.error_message
        }

@dataclass 
class EmailReport:
    """
    Reporte completo de verificación de email
    
    Estructura que coincide con el JSON que pidió tu tutor
    """
    email: str
    level: str
    overall_status: str  # valid|invalid|risky
    confidence: float    # 0-100
    risk_score: float    # 0-10
    fraud_indicators: List[str]
    basic_checks: Dict[str, Any]
    standard_checks: Dict[str, Any]
    professional_checks: Dict[str, Any]
    recommendations: List[str]
    processing_time_ms: float
    timestamp: str
    
    def to_dict(self) -> Dict[str, Any]:
        """Convierte el reporte a diccionario (JSON)"""
        return {
            "email": self.email,
            "level": self.level,
            "overall_status": self.overall_status,
            "confidence": self.confidence,
            "risk_score": self.risk_score,
            "fraud_indicators": self.fraud_indicators,
            "basic_checks": self.basic_checks,
            "standard_checks": self.standard_checks,
            "professional_checks": self.professional_checks,
            "recommendations": self.recommendations,
            "processing_time_ms": self.processing_time_ms,
            "timestamp": self.timestamp
        }

@dataclass
class DomainInfo:
    """Información sobre un dominio"""
    domain: str
    exists: bool
    has_mx: bool
    has_spf: bool
    has_dkim: bool
    has_dmarc: bool
    is_disposable: bool
    is_free: bool
    is_blacklisted: bool
    creation_date: Optional[datetime] = None
    registrar: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convierte la información del dominio a diccionario"""
        return {
            "domain": self.domain,
            "exists": self.exists,
            "has_mx": self.has_mx,
            "has_spf": self.has_spf,
            "has_dkim": self.has_dkim,
            "has_dmarc": self.has_dmarc,
            "is_disposable": self.is_disposable,
            "is_free": self.is_free,
            "is_blacklisted": self.is_blacklisted,
            "creation_date": self.creation_date.isoformat() if self.creation_date else None,
            "registrar": self.registrar
        }

# Constantes para niveles de validación
class ValidationLevels:
    """Niveles de validación disponibles"""
    BASIC = "basic"
    STANDARD = "standard" 
    PROFESSIONAL = "professional"
    
    @classmethod
    def all_levels(cls) -> List[str]:
        """Retorna todos los niveles disponibles"""
        return [cls.BASIC, cls.STANDARD, cls.PROFESSIONAL]
    
    @classmethod
    def is_valid_level(cls, level: str) -> bool:
        """Verifica si un nivel es válido"""
        return level in cls.all_levels()

# Constantes para estados de verificación
class VerificationStatus:
    """Estados posibles de verificación"""
    VALID = "valid"
    INVALID = "invalid"
    RISKY = "risky"
    ERROR = "error"
    
    @classmethod
    def all_statuses(cls) -> List[str]:
        """Retorna todos los estados disponibles"""
        return [cls.VALID, cls.INVALID, cls.RISKY, cls.ERROR]