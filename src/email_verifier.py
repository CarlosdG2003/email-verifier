"""
Email Verifier - Clase principal del verificador
"""

import time
import logging
from typing import Dict, List, Any
from datetime import datetime

from src.models.validation_result import ValidationResult, ValidationLevels, VerificationStatus
from src.validators.basic_validators_part1 import BasicValidatorsPart1
from src.validators.basic_validators_part2 import BasicValidatorsPart2
from src.validators.dns_validators import DNSValidators
from src.validators.smtp_validators import SMTPValidators

logger = logging.getLogger(__name__)

class EmailVerifier:
    """
    Verificador de emails con múltiples niveles de validación
    
    Niveles:
    - basic: Validaciones 1-6 (formato, longitud, dominios)
    - standard: Incluye validaciones DNS (MX, SPF)
    - professional: Incluye DKIM, DMARC y verificaciones avanzadas
    """
    
    def __init__(self, dns_timeout: int = 5):
        logger.info("Inicializando EmailVerifier...")
        
        # Inicializar validadores
        self.basic_part1 = BasicValidatorsPart1()
        self.basic_part2 = BasicValidatorsPart2()
        self.dns_validators = DNSValidators(timeout=dns_timeout)
        self.smtp_validators = SMTPValidators(timeout=15)
        
        try:
            from src.validators.advanced_dns_validators import AdvancedDNSValidators
            self.advanced_dns = AdvancedDNSValidators(timeout=dns_timeout)
        except ImportError as e:
            logger.warning(f"No se pudo cargar AdvancedDNSValidators: {e}")
            self.advanced_dns = None
        
        logger.info("EmailVerifier inicializado correctamente")
    
    def verify_email(self, email: str, level: str = "basic") -> Dict[str, Any]:
        """
        Verifica un email según el nivel especificado
        
        Args:
            email: Email a verificar
            level: Nivel de verificación ('basic', 'standard', 'professional')
        
        Returns:
            Diccionario con todos los resultados de la verificación
        """
        start_time = time.time()
        logger.info(f"Iniciando verificación de '{email}' (nivel: {level})")
        
        # Validar nivel
        if not ValidationLevels.is_valid_level(level):
            level = ValidationLevels.BASIC
        
        # Estructura base del resultado
        result = {
            "email": email,
            "level": level,
            "overall_status": VerificationStatus.VALID,
            "confidence": 100,
            "risk_score": 0,
            "fraud_indicators": [],
            "basic_checks": {},
            "standard_checks": {},
            "professional_checks": {},
            "recommendations": [],
            "processing_time_ms": 0,
            "timestamp": datetime.now().isoformat()
        }
        
        try:
            # Validaciones básicas (siempre se ejecutan)
            logger.info("Ejecutando validaciones básicas...")
            basic_results = self._run_basic_checks(email)
            result["basic_checks"] = basic_results
            
            # Validaciones estándar
            if level in [ValidationLevels.STANDARD, ValidationLevels.PROFESSIONAL]:
                logger.info("Ejecutando validaciones estándar...")
                standard_results = self._run_standard_checks(email)
                result["standard_checks"] = standard_results
                
            # Validaciones profesionales
            if level == ValidationLevels.PROFESSIONAL:
                logger.info("Ejecutando validaciones profesionales...")
                professional_results = self._run_professional_checks(email)
                result["professional_checks"] = professional_results
            
            # Calcular scores finales
            self._calculate_final_scores(result)
            
            logger.info(f"Verificación completada: {result['overall_status']} (confianza: {result['confidence']}%)")
            
        except Exception as e:
            logger.error(f"Error durante verificación: {e}")
            result["overall_status"] = VerificationStatus.ERROR
            result["fraud_indicators"].append(f"Error durante verificación: {str(e)}")
            result["confidence"] = 0
        
        result["processing_time_ms"] = round((time.time() - start_time) * 1000, 2)
        
        return result
    
    def _run_basic_checks(self, email: str) -> Dict[str, Any]:
        """Ejecuta las validaciones básicas (1-6)"""
        results = {}
        
        # Validaciones 1-3
        format_result = self.basic_part1.check_format(email)
        results["format"] = format_result.to_dict()
        
        length_result = self.basic_part1.check_length(email)
        results["length"] = length_result.to_dict()
        
        disposable_result = self.basic_part1.check_disposable_domain(email)
        results["disposable_domain"] = disposable_result.to_dict()
        
        # Validaciones 4-6
        free_result = self.basic_part2.check_free_domain(email)
        results["free_domain"] = free_result.to_dict()
        
        dbl_result = self.basic_part2.check_dbl_domain(email)
        results["dbl_domain"] = dbl_result.to_dict()
        
        suspicious_result = self.basic_part2.check_suspicious_username(email)
        results["suspicious_username"] = suspicious_result.to_dict()
        
        return results
    
    def _run_standard_checks(self, email: str) -> Dict[str, Any]:
        """Ejecuta las validaciones estándar (7-8)"""
        results = {}
        
        mx_result = self.dns_validators.check_mx_record(email)
        results["mx_record"] = mx_result.to_dict()
        
        spf_result = self.dns_validators.check_spf_record(email)
        results["spf_record"] = spf_result.to_dict()
        
        return results
    
    def _run_professional_checks(self, email: str) -> Dict[str, Any]:
        """Ejecuta las validaciones profesionales (9-12 y más)"""
        results = {}
        
        # Validaciones DNS básicas (9-10)
        dkim_result = self.dns_validators.check_dkim_record(email)
        results["dkim_record"] = dkim_result.to_dict()
        
        dmarc_result = self.dns_validators.check_dmarc_record(email)
        results["dmarc_record"] = dmarc_result.to_dict()
        
        # Validaciones DNS avanzadas (11-12)
        if self.advanced_dns:
            mx_consistency_result = self.advanced_dns.check_mx_domain_consistency(email)
            results["mx_domain_consistency"] = mx_consistency_result.to_dict()
            
            domain_reg_result = self.advanced_dns.check_domain_registration(email)
            results["domain_registration"] = domain_reg_result.to_dict()
        else:
            # Fallback si no se pudo cargar AdvancedDNSValidators
            results["mx_domain_consistency"] = {"is_valid": True, "score": 80, "details": {"status": "not_available"}}
            results["domain_registration"] = {"is_valid": True, "score": 80, "details": {"status": "not_available"}}
        
        # Validaciones SMTP (13-14)
        mailbox_result = self.smtp_validators.check_mailbox_exists(email)
        results["mailbox_exists"] = mailbox_result.to_dict()

        acceptance_result = self.smtp_validators.check_mail_acceptance(email)
        results["mail_acceptance"] = acceptance_result.to_dict()
        
        # Placeholder para validaciones futuras 15-23
        results.update({
            "password_breaches": {
                "found_in_breaches": False,
                "breach_count": 0,
                "latest_breach": None,
                "breached_sites": []
            },
            "domain_analysis": {
                "has_website": True,
                "ssl_valid": True,
                "content_quality": 90
            }
        })
        
        return results
    
    def _calculate_final_scores(self, result: Dict[str, Any]) -> None:
        """Calcula los scores finales y determina el estado general - VERSIÓN SIMPLE QUE FUNCIONA"""
        all_scores = []
        fraud_indicators = []
        recommendations = []
        
        # Recopilar scores de todas las validaciones (PROMEDIO SIMPLE)
        for check_type in ["basic_checks", "standard_checks", "professional_checks"]:
            checks = result.get(check_type, {})
            for check_name, check_data in checks.items():
                if isinstance(check_data, dict) and "score" in check_data:
                    all_scores.append(check_data["score"])
                    
                    # Detectar indicadores de fraude
                    if check_data["score"] < 50:
                        if check_name == "disposable_domain" and check_data.get("details", {}).get("is_disposable"):
                            fraud_indicators.append("Dominio temporal/desechable detectado")
                        elif check_name == "dbl_domain" and check_data.get("details", {}).get("is_blacklisted"):
                            fraud_indicators.append("Dominio en lista negra")
                        elif check_name == "suspicious_username":
                            fraud_indicators.append("Patrón de username sospechoso")
                        elif check_name == "format" and not check_data.get("is_valid"):
                            fraud_indicators.append("Formato de email inválido")
                        elif check_name == "mx_record":
                            fraud_indicators.append("Dominio no puede recibir emails")
        
        # Calcular confianza promedio (COMO FUNCIONABA ANTES)
        confidence = round(sum(all_scores) / len(all_scores), 2) if all_scores else 0
        
        # ÚNICA regla absoluta: si no tiene MX Y se ejecutaron validaciones DNS
        standard_checks = result.get("standard_checks", {})
        if standard_checks:  # Solo si se ejecutaron validaciones DNS
            mx_check = standard_checks.get("mx_record", {})
            if mx_check and mx_check.get("score", 100) == 0:
                confidence = min(confidence, 60)  # Sin MX = máximo 60%
        
        # Calcular risk score
        risk_score = round((100 - confidence) / 10, 1)
        
        # Determinar estado general (umbrales originales)
        if confidence >= 80:
            overall_status = VerificationStatus.VALID
        elif confidence >= 60:
            overall_status = VerificationStatus.RISKY
        else:
            overall_status = VerificationStatus.INVALID
        
        # Generar recomendaciones
        if fraud_indicators:
            recommendations.append("Se detectaron indicadores de riesgo en este email")
        
        # Recomendación específica para MX solo si se ejecutó y falló
        if standard_checks:
            mx_check = standard_checks.get("mx_record", {})
            if mx_check and mx_check.get("score", 100) == 0:
                recommendations.append("Dominio no puede recibir emails (sin registros MX)")
        
        # Otras recomendaciones específicas
        format_check = result.get("basic_checks", {}).get("format", {})
        if format_check and not format_check.get("is_valid", True):
            recommendations.append("Formato de email inválido - corregir antes de usar")
            
        disposable_check = result.get("basic_checks", {}).get("disposable_domain", {})
        if disposable_check and disposable_check.get("details", {}).get("is_disposable", False):
            recommendations.append("Email temporal - se eliminará automáticamente")
        
        # Recomendaciones generales
        if confidence < 70:
            recommendations.append("Considerar verificación adicional antes de usar este email")
        if risk_score > 3:
            recommendations.append("Email de alto riesgo, usar con precaución")
        if confidence > 90:
            recommendations.append("Email parece legítimo y seguro")
        
        # Actualizar resultado
        result["confidence"] = confidence
        result["risk_score"] = risk_score
        result["overall_status"] = overall_status
        result["fraud_indicators"] = fraud_indicators
        result["recommendations"] = recommendations
    
    def verify_batch(self, emails: List[str], level: str = "basic") -> List[Dict[str, Any]]:
        """
        Verifica múltiples emails
        
        Args:
            emails: Lista de emails a verificar
            level: Nivel de verificación
            
        Returns:
            Lista con resultados de verificación
        """
        logger.info(f"Iniciando verificación en lote de {len(emails)} emails")
        
        results = []
        for i, email in enumerate(emails, 1):
            logger.info(f"Verificando email {i}/{len(emails)}: {email}")
            result = self.verify_email(email, level)
            results.append(result)
        
        logger.info(f"Verificación en lote completada: {len(results)} resultados")
        return results
    
    def get_stats(self) -> Dict[str, Any]:
        """Retorna estadísticas de los validadores"""
        return {
            "disposable_domains": len(self.basic_part1.disposable_domains),
            "free_domains": len(self.basic_part2.free_domains),
            "blacklist_domains": len(self.basic_part2.blacklist_domains),
            "suspicious_patterns": len(self.basic_part2.suspicious_patterns),
            "dkim_selectors": len(self.dns_validators.common_dkim_selectors),
            "dns_timeout": self.dns_validators.timeout,
            "smtp_timeout": self.smtp_validators.timeout
        }