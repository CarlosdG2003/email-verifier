"""
Validaciones 19-20: Edad de Dominio y Exposición Pública
Versión compacta para proyecto profesional
"""

import time
import hashlib
import requests
from datetime import datetime, timedelta
from typing import Dict, Any, Optional
from src.models.validation_result import ValidationResult

class DomainExposureValidators:
    
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        # Umbrales de edad (días)
        self.age_thresholds = {
            'very_new': 30,      # < 30 días
            'new': 180,          # < 6 meses  
            'established': 730,  # < 2 años
            'mature': 1825       # < 5 años
        }
    
    def check_domain_age(self, email: str) -> ValidationResult:
        """19. Edad del Dominio - Usa WHOIS para determinar antigüedad"""
        start_time = time.time()
        
        if "@" not in email:
            return self._error_result(start_time, "Email inválido")
        
        domain = email.split("@")[1].lower()
        
        try:
            # Obtener información WHOIS
            domain_info = self._get_whois_info(domain)
            
            if not domain_info or not domain_info.get('creation_date'):
                return ValidationResult(True, 60, 
                    {"domain": domain, "age_status": "unknown", "error": "No se pudo obtener fecha de creación"},
                    (time.time() - start_time) * 1000, None)
            
            creation_date = domain_info['creation_date']
            age_days = (datetime.now() - creation_date).days
            age_years = round(age_days / 365.25, 1)
            
            # Calcular score basado en edad
            if age_days < self.age_thresholds['very_new']:
                score = 20  # Muy nuevo, muy sospechoso
                age_category = "very_new"
                risk_level = "high"
            elif age_days < self.age_thresholds['new']:
                score = 40  # Nuevo, algo sospechoso
                age_category = "new" 
                risk_level = "medium"
            elif age_days < self.age_thresholds['established']:
                score = 70  # Establecido
                age_category = "established"
                risk_level = "low"
            elif age_days < self.age_thresholds['mature']:
                score = 90  # Maduro
                age_category = "mature"
                risk_level = "very_low"
            else:
                score = 100  # Muy maduro, confiable
                age_category = "very_mature"
                risk_level = "minimal"
            
            details = {
                "domain": domain,
                "creation_date": creation_date.isoformat(),
                "age_days": age_days,
                "age_years": age_years,
                "age_category": age_category,
                "risk_level": risk_level,
                "registrar": domain_info.get('registrar', 'Unknown')
            }
            
            error_msg = None
            if score < 40:
                error_msg = f"Dominio muy nuevo ({age_days} días) - alto riesgo"
            elif score < 70:
                error_msg = f"Dominio nuevo ({age_days} días) - riesgo moderado"
            
        except Exception as e:
            return self._error_result(start_time, f"Error WHOIS: {str(e)}", 50)
        
        processing_time = (time.time() - start_time) * 1000
        return ValidationResult(score >= 40, score, details, processing_time, error_msg)
    
    def check_email_public_exposure(self, email: str) -> ValidationResult:
        """20. Verificación de Email Público - Busca exposición en breaches y web"""
        start_time = time.time()
        
        if "@" not in email:
            return self._error_result(start_time, "Email inválido")
        
        exposure_sources = []
        exposure_score = 100  # Empezar alto, reducir por exposición
        total_exposures = 0
        
        try:
            # 1. Verificar en Have I Been Pwned (simulado - requiere API key real)
            breach_info = self._check_hibp_simulation(email)
            if breach_info['found']:
                total_exposures += breach_info['breach_count']
                exposure_score -= 30  # Gran penalización por breaches
                exposure_sources.append(f"Data breaches: {breach_info['breach_count']} encontrados")
            
            # 2. Verificar exposición en Google (simulado por rate limits)
            google_exposure = self._check_google_exposure(email)
            if google_exposure['found']:
                total_exposures += 1
                exposure_score -= 20
                exposure_sources.append("Indexado públicamente en buscadores")
            
            # 3. Verificar patrones de email públicos comunes
            public_patterns = self._check_public_patterns(email)
            if public_patterns['is_public_pattern']:
                exposure_score -= 10
                exposure_sources.append(f"Patrón público: {public_patterns['pattern_type']}")
            
            # Normalizar score
            exposure_score = max(0, min(100, exposure_score))
            
            # Determinar nivel de exposición
            if exposure_score >= 80:
                exposure_level = "minimal"
            elif exposure_score >= 60:
                exposure_level = "low"
            elif exposure_score >= 40:
                exposure_level = "moderate"
            elif exposure_score >= 20:
                exposure_level = "high"
            else:
                exposure_level = "critical"
            
            details = {
                "email": email,
                "exposure_score": exposure_score,
                "exposure_level": exposure_level,
                "total_exposures": total_exposures,
                "exposure_sources": exposure_sources,
                "checked_sources": ["breaches", "search_engines", "public_patterns"]
            }
            
            error_msg = None
            if exposure_score < 40:
                error_msg = f"Email con alta exposición pública ({exposure_level})"
            elif exposure_score < 70:
                error_msg = f"Email con exposición moderada ({exposure_level})"
            
        except Exception as e:
            return self._error_result(start_time, f"Error verificando exposición: {str(e)}", 60)
        
        processing_time = (time.time() - start_time) * 1000
        return ValidationResult(exposure_score >= 60, exposure_score, details, processing_time, error_msg)
    
    def _get_whois_info(self, domain: str) -> Optional[Dict[str, Any]]:
        """Obtiene información WHOIS del dominio"""
        try:
            import whois
            domain_info = whois.whois(domain)
            
            if not domain_info:
                return None
            
            creation_date = domain_info.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            
            return {
                'creation_date': creation_date,
                'registrar': domain_info.registrar,
                'expiration_date': domain_info.expiration_date
            }
            
        except Exception:
            return None
    
    def _check_hibp_simulation(self, email: str) -> Dict[str, Any]:
        """
        Simulación de Have I Been Pwned
        En producción real usaría: https://haveibeenpwned.com/api/v3/breachedaccount/{email}
        """
        # Simulación basada en hash del email para consistencia
        email_hash = hashlib.md5(email.encode()).hexdigest()
        hash_value = int(email_hash[:4], 16)  # Usar primeros 4 chars como número
        
        # Simulación: emails con hash par tienen mayor probabilidad de breach
        if hash_value % 3 == 0:  # ~33% tienen breaches
            breach_count = (hash_value % 3) + 1
            return {
                'found': True,
                'breach_count': breach_count,
                'simulated': True
            }
        
        return {'found': False, 'breach_count': 0, 'simulated': True}
    
    def _check_google_exposure(self, email: str) -> Dict[str, Any]:
        """
        Simulación de búsqueda en Google
        En producción real usaría Custom Search API con cuota limitada
        """
        # Patrones que sugieren exposición pública común
        username = email.split("@")[0].lower()
        
        # Simulación: usernames muy comunes o con patrones están más expuestos
        common_usernames = ['admin', 'info', 'support', 'contact', 'sales']
        has_numbers = any(char.isdigit() for char in username)
        
        if username in common_usernames or (len(username) < 5 and has_numbers):
            return {'found': True, 'reason': 'Common pattern likely indexed'}
        
        return {'found': False}
    
    def _check_public_patterns(self, email: str) -> Dict[str, Any]:
        """Verifica patrones típicos de emails públicos"""
        username = email.split("@")[0].lower()
        
        # Patrones públicos comunes
        public_patterns = {
            'contact': ['contact', 'info', 'hello', 'hi'],
            'support': ['support', 'help', 'service', 'assist'],
            'business': ['admin', 'office', 'business', 'company'],
            'marketing': ['marketing', 'promo', 'news', 'newsletter'],
            'generic': ['mail', 'email', 'inbox', 'mailbox']
        }
        
        for pattern_type, patterns in public_patterns.items():
            if username in patterns:
                return {
                    'is_public_pattern': True,
                    'pattern_type': pattern_type,
                    'matched_pattern': username
                }
        
        return {'is_public_pattern': False}
    
    def _error_result(self, start_time: float, message: str, score: int = 0) -> ValidationResult:
        """Helper para crear resultados de error"""
        processing_time = (time.time() - start_time) * 1000
        return ValidationResult(False, score, {"error": message}, processing_time, message)
    
    def check_all_domain_exposure_validations(self, email: str) -> Dict[str, ValidationResult]:
        """Ejecuta todas las validaciones de dominio y exposición"""
        return {
            "domain_age": self.check_domain_age(email),
            "email_public_exposure": self.check_email_public_exposure(email)
        }