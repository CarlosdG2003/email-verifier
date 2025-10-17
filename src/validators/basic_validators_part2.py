"""Validaciones básicas 4-6: dominios gratuitos, blacklist y usernames sospechosos."""

import re
import time
import logging
from typing import Set, List
from src.models.validation_result import ValidationResult

logger = logging.getLogger(__name__)


class BasicValidatorsPart2:
    """Valida dominios gratuitos, blacklist y usernames sospechosos."""

    def __init__(self) -> None:
        self.free_domains: Set[str] = {
            'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com', 'icloud.com',
            'protonmail.com', 'yandex.com', 'live.com', 'msn.com', 'zoho.com', 'mail.com',
            'inbox.com', 'gmx.com', 'fastmail.com'
        }

        self.blacklist_domains: Set[str] = {
            'spam.com', 'fakeemail.net', 'scam.org', 'example.com', 'test.com',
            'invalid.com', 'mailsac.com'
        }

        self.suspicious_patterns: List[str] = [
            r'^[a-z]+\d{3,}$', r'^(test|admin|root|noreply).*', r'.*(\d)\1{2,}.*',
            r'^[a-z]{1,3}\d{6,}$', r'^(info|contact|support|sales).*', r'.*sospechoso.*',
            r'.*(fake|spam|bot|automated).*', r'^[a-z]+_[a-z]+\d{4,}$', r'^[a-z]{1,2}\d{8,}$',
            r'.*micr[o0]s[o0]ft.*', r'.*g[o0]{2}[gl]le.*', r'.*amaz[o0]n.*'
        ]

        logger.info(
            "BasicValidatorsPart2 inicializado con %d dominios gratuitos, %d blacklist y %d patrones",
            len(self.free_domains), len(self.blacklist_domains), len(self.suspicious_patterns)
        )

    def check_free_domain(self, email: str) -> ValidationResult:
        """Verifica si el dominio pertenece a un proveedor gratuito."""
        start = time.time()
        domain = email.split("@")[-1].lower() if "@" in email else ""
        is_free = domain in self.free_domains

        details = {
            "domain": domain,
            "is_free": is_free,
            "provider_type": "free" if is_free else "corporate"
        }
        score = 70 if is_free else 100
        elapsed = (time.time() - start) * 1000
        return ValidationResult(True, score, details, elapsed)

    def check_dbl_domain(self, email: str) -> ValidationResult:
        """Verifica si el dominio está en la blacklist."""
        start = time.time()
        domain = email.split("@")[-1].lower() if "@" in email else ""
        example_domains = {"example.com", "sample.org", "test.com", "demo.net"}

        is_blacklisted = domain in self.blacklist_domains and domain not in example_domains
        error = f"Dominio {domain} está en lista negra" if is_blacklisted else None
        score = 0 if is_blacklisted else 100

        details = {
            "domain": domain,
            "is_blacklisted": is_blacklisted,
            "blacklist_size": len(self.blacklist_domains)
        }

        elapsed = (time.time() - start) * 1000
        return ValidationResult(not is_blacklisted, score, details, elapsed, error)

    def check_suspicious_username(self, email: str) -> ValidationResult:
        """Detecta patrones sospechosos en el nombre de usuario."""
        start = time.time()
        username = email.split("@")[0] if "@" in email else email
        matches = [p for p in self.suspicious_patterns if re.match(p, username.lower())]
        is_suspicious = len(matches) > 0
        score = max(0, 100 - len(matches) * 25)
        error = f"Username '{username}' coincide con {len(matches)} patrones sospechosos" if is_suspicious else None

        details = {
            "username": username,
            "is_suspicious": is_suspicious,
            "matched_patterns": matches,
            "patterns_checked": len(self.suspicious_patterns),
            "suspicion_level": len(matches)
        }

        elapsed = (time.time() - start) * 1000
        return ValidationResult(not is_suspicious, score, details, elapsed, error)

    def add_free_domains(self, domains: Set[str]) -> None:
        """Añade dominios gratuitos personalizados."""
        self.free_domains.update(domains)
        logger.info("Añadidos %d dominios gratuitos", len(domains))

    def add_blacklist_domains(self, domains: Set[str]) -> None:
        """Añade dominios a la blacklist."""
        self.blacklist_domains.update(domains)
        logger.info("Añadidos %d dominios a blacklist", len(domains))

    def add_suspicious_patterns(self, patterns: List[str]) -> None:
        """Añade patrones sospechosos personalizados."""
        self.suspicious_patterns.extend(patterns)
        logger.info("Añadidos %d patrones sospechosos", len(patterns))
