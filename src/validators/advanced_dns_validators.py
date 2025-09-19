"""
Validaciones DNS avanzadas 11-12: Consistencia MX y Registro de Dominio
"""

import dns.resolver
import time
import logging
import whois
from typing import Dict, Any, List
from src.models.validation_result import ValidationResult

logger = logging.getLogger(__name__)

class AdvancedDNSValidators:
    
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout + 2
        self.resolver.nameservers = ['8.8.8.8', '1.1.1.1']
        
        logger.info(f"AdvancedDNSValidators inicializado con timeout: {timeout}s")
    
    def check_mx_domain_consistency(self, email: str) -> ValidationResult:
        """
        11. Consistencia MX - Verifica si el MX corresponde al dominio
        
        Analiza si los registros MX apuntan a servidores relacionados con el dominio
        o si usan servicios externos (Google Workspace, Microsoft 365, etc.)
        """
        start_time = time.time()
        
        domain = email.split("@")[-1].lower() if "@" in email else ""
        if not domain:
            return ValidationResult(
                False, 0, {"error": "No se pudo extraer dominio"},
                (time.time() - start_time) * 1000, "Email sin dominio válido"
            )
        
        mx_records = []
        mx_hosts = []
        consistency_score = 100
        analysis = {}
        error_msg = None
        
        try:
            # Obtener registros MX
            mx_results = self.resolver.resolve(domain, 'MX')
            mx_records = [str(record) for record in mx_results]
            
            # Extraer hostnames de MX
            for record in mx_records:
                parts = record.split(' ', 1)
                if len(parts) == 2:
                    mx_host = parts[1].rstrip('.')
                    mx_hosts.append(mx_host)
            
            if not mx_hosts:
                return ValidationResult(False, 0, {"error": "Sin registros MX válidos"}, 
                                      (time.time() - start_time) * 1000, "Sin MX records")
            
            # Analizar consistencia
            analysis = self._analyze_mx_consistency(domain, mx_hosts)
            consistency_score = analysis["consistency_score"]
            
        except dns.resolver.NXDOMAIN:
            error_msg = "Dominio inexistente"
            consistency_score = 0
        except dns.resolver.NoAnswer:
            error_msg = "Sin registros MX"
            consistency_score = 0
        except Exception as e:
            error_msg = f"Error MX consistency: {str(e)}"
            consistency_score = 0
        
        details = {
            "domain": domain,
            "mx_records": mx_records,
            "mx_hosts": mx_hosts,
            "consistency_analysis": analysis,
            "uses_external_mx": analysis.get("uses_external_service", False),
            "external_service": analysis.get("external_service", None)
        }
        
        is_valid = consistency_score > 0
        processing_time = (time.time() - start_time) * 1000
        
        return ValidationResult(is_valid, consistency_score, details, processing_time, error_msg)
    
    def _analyze_mx_consistency(self, domain: str, mx_hosts: List[str]) -> Dict[str, Any]:
        """Analiza la consistencia entre dominio y sus MX records"""
        
        analysis = {
            "consistency_score": 100,
            "uses_external_service": False,
            "external_service": None,
            "consistency_issues": []
        }
        
        # Servicios MX conocidos
        external_services = {
            'google': ['gmail.com', 'google.com'],
            'microsoft': ['outlook.com', 'protection.outlook.com'],
            'zoho': ['zoho.com'],
            'amazon': ['amazonses.com']
        }
        
        domain_root = '.'.join(domain.split('.')[-2:]) if '.' in domain else domain
        
        for mx_host in mx_hosts:
            mx_host_lower = mx_host.lower()
            
            # Verificar si MX contiene el dominio original
            if domain in mx_host_lower or domain_root in mx_host_lower:
                continue
            
            # Verificar servicios externos conocidos
            external_detected = False
            for service, patterns in external_services.items():
                if any(pattern in mx_host_lower for pattern in patterns):
                    analysis["uses_external_service"] = True
                    analysis["external_service"] = service
                    external_detected = True
                    break
            
            if not external_detected:
                analysis["consistency_issues"].append(f"MX desconocido: {mx_host}")
        
        # Calcular score
        if analysis["uses_external_service"]:
            analysis["consistency_score"] = 85
        elif analysis["consistency_issues"]:
            issue_penalty = min(50, len(analysis["consistency_issues"]) * 20)
            analysis["consistency_score"] = max(30, 100 - issue_penalty)
        
        return analysis
    
    def check_domain_registration(self, email: str) -> ValidationResult:
        """
        12. Dominio Registrado - Verifica si es dominio válido y registrado
        
        Usa WHOIS para verificar que el dominio esté correctamente registrado
        """
        start_time = time.time()
        
        domain = email.split("@")[-1].lower() if "@" in email else ""
        if not domain:
            return ValidationResult(
                False, 0, {"error": "No se pudo extraer dominio"},
                (time.time() - start_time) * 1000, "Email sin dominio válido"
            )
        
        is_registered = False
        registration_info = {}
        score = 0
        error_msg = None
        
        try:
            # Realizar consulta WHOIS
            whois_result = whois.whois(domain)
            
            if whois_result:
                is_registered = True
                
                # Extraer información relevante
                registration_info = {
                    "domain_name": getattr(whois_result, 'domain_name', None),
                    "creation_date": str(getattr(whois_result, 'creation_date', 'Unknown')),
                    "expiration_date": str(getattr(whois_result, 'expiration_date', 'Unknown')),
                    "registrar": getattr(whois_result, 'registrar', 'Unknown'),
                    "name_servers": getattr(whois_result, 'name_servers', []),
                    "status": getattr(whois_result, 'status', [])
                }
                
                # Calcular score basado en la información disponible
                score = self._calculate_registration_score(whois_result, domain)
            else:
                error_msg = "Sin información WHOIS disponible"
                score = 20  # Penalización menor por falta de info WHOIS
                
        except Exception as e:
            error_msg = f"Error WHOIS: {str(e)}"
            
            # Intentar verificación DNS básica como fallback
            try:
                # Si al menos responde a consulta DNS básica
                self.resolver.resolve(domain, 'A')
                is_registered = True
                score = 60  # Score menor por no tener WHOIS pero tener DNS
                registration_info = {"fallback": "Verificado via DNS"}
            except:
                is_registered = False
                score = 0
                error_msg = "Dominio no registrado o inaccesible"
        
        details = {
            "domain": domain,
            "is_registered": is_registered,
            "registration_info": registration_info,
            "whois_available": bool(registration_info and not registration_info.get("fallback"))
        }
        
        processing_time = (time.time() - start_time) * 1000
        
        return ValidationResult(is_registered, score, details, processing_time, error_msg)
    
    def _calculate_registration_score(self, whois_result, domain: str) -> int:
        """Calcula score basado en información WHOIS"""
        score = 100
        
        try:
            # Verificar fechas de registro
            creation_date = getattr(whois_result, 'creation_date', None)
            if creation_date:
                if not isinstance(creation_date, list):
                    creation_date = [creation_date]
                
                first_date = creation_date[0]
                if hasattr(first_date, 'year'):
                    import datetime
                    days_registered = (datetime.datetime.now() - first_date).days
                    
                    if days_registered < 30:
                        score -= 30  # Dominio muy nuevo
                    elif days_registered < 90:
                        score -= 15  # Dominio nuevo
            
            # Verificar status sospechoso
            status = getattr(whois_result, 'status', [])
            if isinstance(status, list) and status:
                suspicious_statuses = ['HOLD', 'LOCK', 'SUSPEND']
                if any(sus_status.upper() in str(status).upper() for sus_status in suspicious_statuses):
                    score -= 40
                    
        except Exception as e:
            logger.warning(f"Error calculando registration score: {e}")
            score = 70
        
        return max(0, min(100, score))
    
    def check_all_advanced_dns(self, email: str) -> Dict[str, ValidationResult]:
        """Ejecuta todas las validaciones DNS avanzadas"""
        return {
            "mx_domain_consistency": self.check_mx_domain_consistency(email),
            "domain_registration": self.check_domain_registration(email)
        }