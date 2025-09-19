"""
Validaciones básicas 1-3: Formato, Longitud, Dominios Desechables
"""

import re
import time
import logging
from typing import Set
from src.models.validation_result import ValidationResult

logger = logging.getLogger(__name__)

class BasicValidatorsPart1:
    
    def __init__(self):
        self.disposable_domains = {
            '10minutemail.com', 'tempmail.org', 'guerrillamail.com',
            'mailinator.com', 'temp-mail.org', 'throwaway.email',
            'getnada.com', 'maildrop.cc', '33mail.com', 'dispostable.com',
            'sharklasers.com', 'yopmail.com', 'mohmal.com', 'tmpmail.org'
        }
        
        logger.info(f"BasicValidatorsPart1 inicializado con {len(self.disposable_domains)} dominios desechables")
    
    def check_format(self, email: str) -> ValidationResult:
        """1. Validación de formato RFC5322 simplificado"""
        start_time = time.time()
        
        rfc5322_pattern = r'^[a-zA-Z0-9!#$%&\'*+/=?^_`{|}~-]+(?:\.[a-zA-Z0-9!#$%&\'*+/=?^_`{|}~-]+)*@(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?$'
        
        is_valid = bool(re.match(rfc5322_pattern, email))
        score = 100 if is_valid else 0
        
        email_parts = email.split("@") if "@" in email else [email]
        has_at = "@" in email
        has_domain = False
        
        if has_at and len(email_parts) == 2:
            domain = email_parts[1]
            has_domain = len(domain) > 0 and "." in domain
        
        details = {
            "regex_pattern": "RFC5322_simplified",
            "contains_at": has_at,
            "has_domain": has_domain,
            "email_parts": email_parts
        }
        
        processing_time = (time.time() - start_time) * 1000
        
        error_msg = None
        if not is_valid:
            if not has_at:
                error_msg = "Email debe contener @"
            elif not has_domain:
                error_msg = "Formato de email no válido"
        
        return ValidationResult(is_valid, score, details, processing_time, error_msg)
    
    def check_length(self, email: str) -> ValidationResult:
        """2. Validación de longitud según RFC"""
        start_time = time.time()
        
        total_length = len(email)
        username_length = len(email.split("@")[0]) if "@" in email else len(email)
        
        total_valid = total_length <= 254
        username_valid = username_length <= 64
        
        is_valid = total_valid and username_valid
        score = 100
        
        if not total_valid:
            score -= 50
        if not username_valid:
            score -= 50
        
        details = {
            "total_length": total_length,
            "username_length": username_length,
            "max_total": 254,
            "max_username": 64,
            "total_valid": total_valid,
            "username_valid": username_valid
        }
        
        processing_time = (time.time() - start_time) * 1000
        
        error_msg = None
        if not is_valid:
            if not total_valid:
                error_msg = f"Email demasiado largo ({total_length}/254 caracteres)"
            if not username_valid:
                error_msg = f"Username demasiado largo ({username_length}/64 caracteres)"
        
        return ValidationResult(is_valid, max(0, score), details, processing_time, error_msg)
    
    def check_disposable_domain(self, email: str) -> ValidationResult:
        """3. Verificación de dominios desechables/temporales"""
        start_time = time.time()
        
        domain = email.split("@")[-1].lower() if "@" in email else ""
        is_disposable = domain in self.disposable_domains
        
        is_valid = not is_disposable
        score = 0 if is_disposable else 100
        
        details = {
            "domain": domain,
            "is_disposable": is_disposable,
            "disposable_domains_checked": len(self.disposable_domains)
        }
        
        processing_time = (time.time() - start_time) * 1000
        
        error_msg = None
        if is_disposable:
            error_msg = f"Dominio {domain} es temporal/desechable"
        
        return ValidationResult(is_valid, score, details, processing_time, error_msg)
    
    def add_disposable_domains(self, domains: Set[str]) -> None:
        """Añade dominios desechables personalizados"""
        self.disposable_domains.update(domains)
        logger.info(f"Añadidos {len(domains)} dominios desechables")