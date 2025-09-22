"""Validaciones básicas 1-3: Formato, Longitud, Dominios Desechables"""
import re, time, logging
from typing import Set
from src.models.validation_result import ValidationResult

logger = logging.getLogger(__name__)

class BasicValidatorsPart1:
    # Inicializa dominios desechables por defecto
    def __init__(self):
        self.disposable_domains = {
            '10minutemail.com','tempmail.org','guerrillamail.com','mailinator.com','temp-mail.org',
            'throwaway.email','getnada.com','maildrop.cc','33mail.com','dispostable.com',
            'sharklasers.com','yopmail.com','mohmal.com','tmpmail.org'
        }
        logger.info(f"BasicValidatorsPart1 inicializado con {len(self.disposable_domains)} dominios desechables")

    # 1. Valida formato RFC5322 simplificado
    def check_format(self, email: str) -> ValidationResult:
        start = time.time()
        pattern = r'^[\w!#$%&\'*+/=?^_`{|}~-]+(?:\.[\w!#$%&\'*+/=?^_`{|}~-]+)*@(?:[\w](?:[\w-]*[\w])?\.)+[\w](?:[\w-]*[\w])?$'
        is_valid = bool(re.match(pattern, email)); score = 100 if is_valid else 0
        parts = email.split("@"); has_at = "@" in email; has_domain = len(parts)==2 and "." in parts[-1]
        details = {"regex_pattern":"RFC5322_simplified","contains_at":has_at,"has_domain":has_domain,"email_parts":parts}
        err = None if is_valid else "Email debe contener @" if not has_at else "Formato de email no válido" if not has_domain else None
        return ValidationResult(is_valid, score, details, (time.time()-start)*1000, err)

    # 2. Valida longitud total y del usuario
    def check_length(self, email: str) -> ValidationResult:
        start = time.time()
        total, username = len(email), len(email.split("@")[0] if "@" in email else email)
        total_valid, user_valid = total<=254, username<=64
        score = 100 - (0 if total_valid else 50) - (0 if user_valid else 50)
        err = None
        if not total_valid: err = f"Email demasiado largo ({total}/254 caracteres)"
        if not user_valid: err = f"Username demasiado largo ({username}/64 caracteres)"
        details = {"total_length":total,"username_length":username,"max_total":254,"max_username":64,
                   "total_valid":total_valid,"username_valid":user_valid}
        return ValidationResult(total_valid and user_valid, max(0,score), details, (time.time()-start)*1000, err)

    # 3. Comprueba si el dominio es temporal/desechable
    def check_disposable_domain(self, email: str) -> ValidationResult:
        start = time.time()
        domain = email.split("@")[-1].lower() if "@" in email else ""
        is_disp = domain in self.disposable_domains
        err = f"Dominio {domain} es temporal/desechable" if is_disp else None
        details = {"domain":domain,"is_disposable":is_disp,"disposable_domains_checked":len(self.disposable_domains)}
        return ValidationResult(not is_disp, 0 if is_disp else 100, details, (time.time()-start)*1000, err)

    # Añade dominios desechables personalizados
    def add_disposable_domains(self, domains: Set[str]) -> None:
        self.disposable_domains.update(domains)
        logger.info(f"Añadidos {len(domains)} dominios desechables")
