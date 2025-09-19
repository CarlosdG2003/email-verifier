"""
Validaciones básicas 4-6: Dominios Gratuitos, Blacklist, Username Sospechoso
"""

import re
import time
import logging
from typing import Set, List
from src.models.validation_result import ValidationResult

logger = logging.getLogger(__name__)

class BasicValidatorsPart2:
    
    def __init__(self):
        self.free_domains = {
            'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com',
            'aol.com', 'icloud.com', 'protonmail.com', 'yandex.com',
            'live.com', 'msn.com', 'zoho.com', 'mail.com',
            'inbox.com', 'gmx.com', 'fastmail.com'
        }
        
        self.blacklist_domains = {
            'spam.com', 'fakeemail.net', 'scam.org', 'example.com',
            'test.com', 'invalid.com', 'mailsac.com'
        }
        
        self.suspicious_patterns = [
            r'^[a-z]+\d{3,}$',                      # user123456
            r'^(test|admin|root|noreply).*',        # usuarios técnicos
            r'.*(\d)\1{2,}.*',                      # números repetidos
            r'^[a-z]{1,3}\d{6,}$',                  # a123456
            r'^(info|contact|support|sales).*',     # emails genéricos
            r'.*sospechoso.*',                      # palabra "sospechoso"
            r'.*fake.*|.*spam.*|.*bot.*',           # palabras spam
            r'^[a-z]+_[a-z]+\d{4,}$',              # user_word1234
            r'^[a-z]{1,2}\d{8,}$'                   # ab12345678
        ]
        
        logger.info(f"BasicValidatorsPart2 inicializado")
        logger.info(f"  - {len(self.free_domains)} dominios gratuitos")
        logger.info(f"  - {len(self.blacklist_domains)} dominios blacklist")
        logger.info(f"  - {len(self.suspicious_patterns)} patrones sospechosos")
    
    def check_free_domain(self, email: str) -> ValidationResult:
        """4. Verificación de dominios gratuitos"""
        start_time = time.time()
        
        domain = email.split("@")[-1].lower() if "@" in email else ""
        is_free = domain in self.free_domains
        
        # Los dominios gratuitos no invalidan el email
        is_valid = True
        score = 70 if is_free else 100
        
        details = {
            "domain": domain,
            "is_free": is_free,
            "provider_type": "free" if is_free else "corporate"
        }
        
        processing_time = (time.time() - start_time) * 1000
        
        return ValidationResult(is_valid, score, details, processing_time)
    
    def check_dbl_domain(self, email: str) -> ValidationResult:
        """5. Verificación de dominios en blacklist"""
        start_time = time.time()
        
        domain = email.split("@")[-1].lower() if "@" in email else ""
        is_blacklisted = domain in self.blacklist_domains
        
        is_valid = not is_blacklisted
        score = 0 if is_blacklisted else 100
        
        details = {
            "domain": domain,
            "is_blacklisted": is_blacklisted,
            "blacklist_size": len(self.blacklist_domains)
        }
        
        processing_time = (time.time() - start_time) * 1000
        
        error_msg = None
        if is_blacklisted:
            error_msg = f"Dominio {domain} está en lista negra"
        
        return ValidationResult(is_valid, score, details, processing_time, error_msg)
    
    def check_suspicious_username(self, email: str) -> ValidationResult:
        """6. Verificación de username sospechoso"""
        start_time = time.time()
        
        username = email.split("@")[0] if "@" in email else email
        suspicious_matches = []
        
        for pattern in self.suspicious_patterns:
            if re.match(pattern, username.lower()):
                suspicious_matches.append(pattern)
        
        is_suspicious = len(suspicious_matches) > 0
        is_valid = not is_suspicious
        
        penalty = len(suspicious_matches) * 25
        score = max(0, 100 - penalty)
        
        details = {
            "username": username,
            "is_suspicious": is_suspicious,
            "matched_patterns": suspicious_matches,
            "patterns_checked": len(self.suspicious_patterns),
            "suspicion_level": len(suspicious_matches)
        }
        
        processing_time = (time.time() - start_time) * 1000
        
        error_msg = None
        if is_suspicious:
            error_msg = f"Username '{username}' coincide con {len(suspicious_matches)} patrones sospechosos"
        
        return ValidationResult(is_valid, score, details, processing_time, error_msg)
    
    def add_free_domains(self, domains: Set[str]) -> None:
        """Añade dominios gratuitos personalizados"""
        self.free_domains.update(domains)
        logger.info(f"Añadidos {len(domains)} dominios gratuitos")
    
    def add_blacklist_domains(self, domains: Set[str]) -> None:
        """Añade dominios a la blacklist"""
        self.blacklist_domains.update(domains)
        logger.info(f"Añadidos {len(domains)} dominios a blacklist")
    
    def add_suspicious_patterns(self, patterns: List[str]) -> None:
        """Añade patrones sospechosos personalizados"""
        self.suspicious_patterns.extend(patterns)
        logger.info(f"Añadidos {len(patterns)} patrones sospechosos")