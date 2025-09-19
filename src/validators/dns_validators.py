"""
Validaciones DNS 7-10: MX, SPF, DKIM, DMARC
"""

import dns.resolver
import time
import logging
from typing import Dict
from src.models.validation_result import ValidationResult

logger = logging.getLogger(__name__)

class DNSValidators:
    
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout + 2
        self.resolver.nameservers = ['8.8.8.8', '1.1.1.1']
        
        self.common_dkim_selectors = [
            'default', 'google', 'k1', 'dkim', 'mail', 'selector1', 'selector2'
        ]
        
        logger.info(f"DNSValidators inicializado con timeout: {timeout}s")
    
    def check_mx_record(self, email: str) -> ValidationResult:
        """7. Verificación de registros MX"""
        start_time = time.time()
        
        domain = email.split("@")[-1] if "@" in email else ""
        if not domain:
            return ValidationResult(
                False, 0, {"error": "No se pudo extraer dominio"},
                (time.time() - start_time) * 1000, "Email sin dominio válido"
            )
        
        mx_records = []
        has_mx = False
        error_msg = None
        
        try:
            mx_results = self.resolver.resolve(domain, 'MX')
            mx_records = [str(record) for record in mx_results]
            has_mx = len(mx_records) > 0
        except dns.resolver.NXDOMAIN:
            error_msg = "Dominio inexistente"
        except dns.resolver.NoAnswer:
            error_msg = "Sin registros MX"
        except dns.resolver.Timeout:
            error_msg = f"Timeout DNS tras {self.timeout}s"
        except Exception as e:
            error_msg = f"Error DNS: {str(e)}"
        
        is_valid = has_mx
        score = 100 if has_mx else 0
        
        details = {
            "domain": domain,
            "has_mx_records": has_mx,
            "mx_records": mx_records,
            "mx_count": len(mx_records)
        }
        
        processing_time = (time.time() - start_time) * 1000
        return ValidationResult(is_valid, score, details, processing_time, error_msg)
    
    def check_spf_record(self, email: str) -> ValidationResult:
        """8. Verificación de registros SPF"""
        start_time = time.time()
        
        domain = email.split("@")[-1] if "@" in email else ""
        if not domain:
            return ValidationResult(
                True, 60, {"error": "No se pudo extraer dominio"},
                (time.time() - start_time) * 1000
            )
        
        has_spf = False
        spf_record = ""
        error_msg = None
        
        try:
            txt_results = self.resolver.resolve(domain, 'TXT')
            for record in txt_results:
                txt_string = str(record).strip('"')
                if txt_string.startswith('v=spf1'):
                    has_spf = True
                    spf_record = txt_string
                    break
        except dns.resolver.NXDOMAIN:
            error_msg = "Dominio inexistente"
        except dns.resolver.NoAnswer:
            pass  # Normal no tener TXT records
        except dns.resolver.Timeout:
            error_msg = f"Timeout DNS tras {self.timeout}s"
        except Exception as e:
            error_msg = f"Error SPF: {str(e)}"
        
        is_valid = True  # SPF no invalida el email
        
        # Scoring corregido
        if has_spf:
            score = 100
        elif error_msg and "Dominio inexistente" in error_msg:
            score = 0  # Dominio inexistente = 0
        else:
            score = 60  # Sin SPF pero dominio existe
        
        details = {
            "domain": domain,
            "has_spf_record": has_spf,
            "spf_record": spf_record
        }
        
        processing_time = (time.time() - start_time) * 1000
        return ValidationResult(is_valid, score, details, processing_time, error_msg)
    
    def check_dkim_record(self, email: str) -> ValidationResult:
        """9. Verificación de registros DKIM"""
        start_time = time.time()
        
        domain = email.split("@")[-1] if "@" in email else ""
        if not domain:
            return ValidationResult(
                True, 70, {"error": "No se pudo extraer dominio"},
                (time.time() - start_time) * 1000
            )
        
        has_dkim = False
        dkim_records = []
        found_selectors = []
        
        for selector in self.common_dkim_selectors:
            try:
                dkim_domain = f"{selector}._domainkey.{domain}"
                txt_results = self.resolver.resolve(dkim_domain, 'TXT')
                
                for record in txt_results:
                    txt_string = str(record).strip('"')
                    if 'v=DKIM1' in txt_string:
                        has_dkim = True
                        found_selectors.append(selector)
                        dkim_records.append({
                            "selector": selector,
                            "record": txt_string
                        })
                        break
            except:
                continue
        
        is_valid = True  # DKIM no invalida el email
        score = 100 if has_dkim else 70
        
        details = {
            "domain": domain,
            "has_dkim_records": has_dkim,
            "dkim_records": dkim_records,
            "found_selectors": found_selectors
        }
        
        processing_time = (time.time() - start_time) * 1000
        return ValidationResult(is_valid, score, details, processing_time)
    
    def check_dmarc_record(self, email: str) -> ValidationResult:
        """10. Verificación de registros DMARC"""
        start_time = time.time()
        
        domain = email.split("@")[-1] if "@" in email else ""
        if not domain:
            return ValidationResult(
                True, 70, {"error": "No se pudo extraer dominio"},
                (time.time() - start_time) * 1000
            )
        
        has_dmarc = False
        dmarc_record = ""
        dmarc_policy = ""
        error_msg = None
        
        try:
            dmarc_domain = f"_dmarc.{domain}"
            txt_results = self.resolver.resolve(dmarc_domain, 'TXT')
            
            for record in txt_results:
                txt_string = str(record).strip('"')
                if txt_string.startswith('v=DMARC1'):
                    has_dmarc = True
                    dmarc_record = txt_string
                    for part in txt_string.split(';'):
                        if part.strip().startswith('p='):
                            dmarc_policy = part.strip().split('=')[1]
                    break
        except dns.resolver.NXDOMAIN:
            error_msg = "Dominio inexistente"
        except dns.resolver.NoAnswer:
            pass  # Normal no tener DMARC
        except dns.resolver.Timeout:
            error_msg = f"Timeout DNS tras {self.timeout}s"
        except Exception as e:
            error_msg = f"Error DMARC: {str(e)}"
        
        is_valid = True  # DMARC no invalida el email
        
        # Scoring corregido
        if has_dmarc:
            score = 100
        elif error_msg and "Dominio inexistente" in error_msg:
            score = 0  # Dominio inexistente = 0
        else:
            score = 70  # Sin DMARC pero dominio existe
        
        details = {
            "domain": domain,
            "has_dmarc_record": has_dmarc,
            "dmarc_record": dmarc_record,
            "dmarc_policy": dmarc_policy
        }
        
        processing_time = (time.time() - start_time) * 1000
        return ValidationResult(is_valid, score, details, processing_time, error_msg)
    
    def check_all_dns_records(self, email: str) -> Dict[str, ValidationResult]:
        """Ejecuta todas las validaciones DNS"""
        return {
            "mx_record": self.check_mx_record(email),
            "spf_record": self.check_spf_record(email),
            "dkim_record": self.check_dkim_record(email),
            "dmarc_record": self.check_dmarc_record(email)
        }
    
    def set_timeout(self, timeout: int) -> None:
        """Actualiza el timeout DNS"""
        self.timeout = timeout
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout + 2