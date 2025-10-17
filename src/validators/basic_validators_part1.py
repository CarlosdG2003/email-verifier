"""Validaciones básicas 1-3: formato, longitud y dominios desechables."""

import re
import time
import logging
from typing import Set
from src.models.validation_result import ValidationResult

logger = logging.getLogger(__name__)


class BasicValidatorsPart1:
    """Valida formato, longitud y dominios desechables de correos electrónicos."""

    def __init__(self) -> None:
        self.disposable_domains: Set[str] = {
            '10minutemail.com', 'tempmail.org', 'guerrillamail.com', 'mailinator.com', 'temp-mail.org',
            'throwaway.email', 'getnada.com', 'maildrop.cc', '33mail.com', 'dispostable.com',
            'sharklasers.com', 'yopmail.com', 'mohmal.com', 'tmpmail.org'
        }
        logger.info("BasicValidatorsPart1 inicializado con %d dominios desechables", len(self.disposable_domains))

    def check_format(self, email: str) -> ValidationResult:
        """Valida el formato RFC5322 simplificado."""
        start = time.time()
        pattern = (
            r'^[\w!#$%&\'*+/=?^_`{|}~-]+'
            r'(?:\.[\w!#$%&\'*+/=?^_`{|}~-]+)*@'
            r'(?:[\w](?:[\w-]*[\w])?\.)+[\w](?:[\w-]*[\w])?$'
        )

        is_valid = bool(re.match(pattern, email))
        score = 100 if is_valid else 0
        parts = email.split("@")
        has_at = "@" in email
        has_domain = len(parts) == 2 and "." in parts[-1]

        if not is_valid:
            if not has_at:
                error = "Email debe contener '@'"
            elif not has_domain:
                error = "Formato de email no válido (falta dominio)"
            else:
                error = "Formato de email no válido"
        else:
            error = None

        details = {
            "regex_pattern": "RFC5322_simplified",
            "contains_at": has_at,
            "has_domain": has_domain,
            "email_parts": parts
        }
        elapsed = (time.time() - start) * 1000
        return ValidationResult(is_valid, score, details, elapsed, error)

    def check_length(self, email: str) -> ValidationResult:
        """Valida la longitud total y del usuario."""
        start = time.time()
        username = email.split("@")[0] if "@" in email else email
        total, user_len = len(email), len(username)

        total_ok = total <= 254
        user_ok = user_len <= 64
        score = 100 - (0 if total_ok else 50) - (0 if user_ok else 50)

        if not total_ok:
            error = f"Email demasiado largo ({total}/254)"
        elif not user_ok:
            error = f"Username demasiado largo ({user_len}/64)"
        else:
            error = None

        details = {
            "total_length": total,
            "username_length": user_len,
            "max_total": 254,
            "max_username": 64,
            "total_valid": total_ok,
            "username_valid": user_ok,
        }
        elapsed = (time.time() - start) * 1000
        return ValidationResult(total_ok and user_ok, max(0, score), details, elapsed, error)

    def check_disposable_domain(self, email: str) -> ValidationResult:
        """Comprueba si el dominio pertenece a una lista de dominios desechables."""
        start = time.time()
        domain = email.split("@")[-1].lower() if "@" in email else ""
        is_temp = domain in self.disposable_domains
        error = f"Dominio {domain} es temporal/desechable" if is_temp else None

        details = {
            "domain": domain,
            "is_disposable": is_temp,
            "disposable_domains_checked": len(self.disposable_domains)
        }
        elapsed = (time.time() - start) * 1000
        return ValidationResult(not is_temp, 0 if is_temp else 100, details, elapsed, error)

    def add_disposable_domains(self, domains: Set[str]) -> None:
        """Añade dominios desechables personalizados."""
        self.disposable_domains.update(domains)
        logger.info("Añadidos %d dominios desechables", len(domains))
