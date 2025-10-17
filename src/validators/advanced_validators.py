# Validaciones avanzadas: honeypot y reputación de dominio

import re
import ssl
import time
import socket
import logging
import requests
from datetime import datetime
from typing import Dict
from src.models.validation_result import ValidationResult

logger = logging.getLogger(__name__)

# Dominios de prueba reservados/excluidos
EXCLUDED_DOMAINS = [
    "example.com", "example.net", "example.org",
    "test.com", "test.net", "test.org",
    "demo.com", "demo.net", "demo.org",
    "sample.com", "sample.net", "sample.org"
]


# Clase para validaciones avanzadas de correos
class AdvancedValidators:
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.honeypot_patterns = [
            r'^(admin|administrator|root|test|demo|sample|example|info|contact|support|help|sales|marketing|noreply|no-reply|donotreply|do-not-reply|webmaster|hostmaster|postmaster|abuse|bot|crawler|spider|scraper|harvester|fake|dummy|temp|temporary|invalid|catch|catchall|catch-all|all)$',
            r'^.*(test|temp|fake|dummy|invalid).*$',
            r'^.*\d{4,}.*$', r'^[a-z]{1,2}$', r'^[a-z]{20,}$'
        ]
        self.honeypot_domains = {
            'honeypot.com', 'trap.net', 'bait.org', 'decoy.info', 'spamtrap.com',
            'botcatch.net', 'scrapertrap.org', 'invalid.net', 'fake.com', 'dummy.org',
            'temp.net', 'mailinator.com', 'guerrillamail.com', 'tempmail.org'
        }
        self.trusted_tlds = {
            'high': ['.com', '.org', '.net', '.edu', '.gov', '.mil'],
            'medium': ['.info', '.biz', '.name', '.pro', '.aero', '.coop'],
            'low': ['.tk', '.ml', '.ga', '.cf', '.pw', '.top', '.click', '.download']
        }
        self.trusted_registrars = {
            'godaddy', 'namecheap', 'google', 'amazon', 'microsoft', 'cloudflare',
            'markmonitor', 'network solutions', 'tucows', 'enom', 'name.com', 'hover',
            'gandi', '1&1', 'ovh'
        }
        logger.info("AdvancedValidators inicializado")

    # Detección de honeypots evidentes o artificiales
    def check_honeypot(self, email: str) -> ValidationResult:
        start = time.time()
        if not email or "@" not in email:
            return ValidationResult(False, 0, {"error": "Email inválido"},
                                     (time.time() - start) * 1000, "Email sin formato válido")

        username, domain = email.lower().split("@")
        is_honeypot, suspicion_level, indicators = False, 0, []

        obvious_honeypot_domains = {
            'honeypot.com', 'trap.net', 'bait.org', 'spamtrap.com', 'example.com',
            'test.com', 'demo.net', 'invalid.net', 'fake.com', 'dummy.org', 'mailinator.com'
        }
        if domain in obvious_honeypot_domains:
            is_honeypot, suspicion_level = True, 5
            indicators.append(f"Dominio honeypot obvio: {domain}")

        if domain.endswith(('.test', '.invalid', '.localhost', '.example')):
            is_honeypot, suspicion_level = True, 5
            indicators.append("TLD reservado para pruebas")

        known_companies = {
            'google.com', 'microsoft.com', 'amazon.com', 'apple.com', 'meta.com',
            'reddit.com', 'twitter.com', 'linkedin.com', 'github.com', 'stackoverflow.com',
            'netflix.com', 'spotify.com', 'adobe.com', 'salesforce.com', 'uber.com'
        }

        if domain in known_companies:
            is_honeypot, suspicion_level, indicators = False, 0, []
        elif not any(tld in domain for tld in ['.com', '.org', '.net', '.gov', '.edu']):
            for p in [r'^(test|demo|fake|dummy|invalid|temp)$', r'^.*(test|fake|dummy|invalid).*$',
                      r'^[a-z]{1}$', r'^[0-9]+$']:
                if re.match(p, username):
                    suspicion_level = max(suspicion_level, 3)
                    indicators.append(f"Patrón sospechoso: {p}")
                    break

        score = 0 if is_honeypot else 60 if suspicion_level >= 3 else 80 if suspicion_level >= 2 else 100
        details = {
            "email": email, "username": username, "domain": domain,
            "is_honeypot": is_honeypot, "indicators": indicators,
            "suspicion_level": suspicion_level, "is_known_company": domain in known_companies
        }
        err = f"Honeypot detectado: {', '.join(indicators)}" if is_honeypot else None
        return ValidationResult(not is_honeypot, score, details,
                                (time.time() - start) * 1000, err)

    # Análisis de reputación del dominio
    def check_domain_reputation(self, email: str) -> ValidationResult:
        start = time.time()
        if not email or "@" not in email:
            return ValidationResult(False, 0, {"error": "Email inválido"},
                                     (time.time() - start) * 1000, "Email sin formato válido")

        domain = email.split("@")[1].lower()
        if domain in EXCLUDED_DOMAINS:
            return ValidationResult(True, 100,
                {"domain": domain, "note": "Dominio de prueba reservado"},
                (time.time() - start) * 1000, None)

        score, details = 50, {}
        try:
            tld_score = self._analyze_tld(domain)
            details["tld"] = {"score": tld_score, "category": self._get_tld_category(domain)}
            score += tld_score

            age_score, age_info = self._analyze_domain_age(domain)
            score += age_score; details["age"] = age_info

            ssl_score, ssl_info = self._analyze_ssl_certificate(domain)
            score += ssl_score; details["ssl"] = ssl_info

            reg_score, reg_info = self._analyze_registrar(domain)
            score += reg_score; details["registrar"] = reg_info

            struct_score = self._analyze_domain_structure(domain)
            score += struct_score; details["structure"] = struct_score

            score = max(0, min(100, score))
            level = ("excellent" if score >= 80 else "good" if score >= 60 else
                     "neutral" if score >= 40 else "poor" if score >= 20 else "very_poor")

        except Exception as e:
            logger.error(f"Error reputación {domain}: {e}")
            score, level, details = 40, "unknown", {"error": str(e)}

        err = ("Dominio con reputación muy baja" if score < 20 else
               "Dominio cuestionable" if score < 40 else None)

        return ValidationResult(score >= 40, score, {
            "domain": domain, "reputation_level": level, "details": details
        }, (time.time() - start) * 1000, err)

    # --- Funciones auxiliares ---
    def _analyze_tld(self, d: str) -> int:
        if '.' not in d: return -20
        t = '.' + d.split('.')[-1]
        if t in self.trusted_tlds['high']: return 20
        if t in self.trusted_tlds['medium']: return 5
        if t in self.trusted_tlds['low']: return -15
        return 0

    def _get_tld_category(self, d: str) -> str:
        if '.' not in d: return "invalid"
        t = '.' + d.split('.')[-1]
        for cat, tlds in self.trusted_tlds.items():
            if t in tlds: return cat
        return "unknown"

    def _analyze_domain_age(self, d: str) -> tuple:
        try:
            import whois
            info = whois.whois(d)
            if info and info.creation_date:
                cd = info.creation_date[0] if isinstance(info.creation_date, list) else info.creation_date
                age = (datetime.now() - cd).days / 365.25
                s = 15 if age >= 10 else 10 if age >= 5 else 5 if age >= 2 else 0 if age >= 1 else -10
                return s, {"creation_date": cd.isoformat(), "years": round(age, 1), "score": s}
        except Exception as e:
            logger.warning(f"WHOIS error {d}: {e}")
        return 0, {"error": "Edad desconocida"}

    def _analyze_ssl_certificate(self, d: str) -> tuple:
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((d, 443), timeout=self.timeout) as s:
                with ctx.wrap_socket(s, server_hostname=d) as ss:
                    c = ss.getpeercert()
                    if c:
                        exp = datetime.strptime(c['notAfter'], '%b %d %H:%M:%S %Y %Z')
                        days = (exp - datetime.now()).days
                        sc = 10 if days > 30 else 5 if days > 0 else -10
                        return sc, {"has_ssl": True, "expires": exp.isoformat(), "days_left": days, "score": sc}
        except Exception as e:
            logger.warning(f"SSL error {d}: {e}")
        return -5, {"has_ssl": False, "error": "No SSL o error"}

    def _analyze_registrar(self, d: str) -> tuple:
        try:
            import whois
            info = whois.whois(d)
            if info and info.registrar:
                r = info.registrar.lower()
                if any(t in r for t in self.trusted_registrars):
                    return 10, {"registrar": info.registrar, "trusted": True, "score": 10}
                return 0, {"registrar": info.registrar, "trusted": False, "score": 0}
        except Exception as e:
            logger.warning(f"Registrar error {d}: {e}")
        return 0, {"error": "Registrador desconocido"}

    def _analyze_domain_structure(self, d: str) -> int:
        s = 5 if 5 <= len(d) <= 20 else -5 if len(d) > 30 else 0
        if d.count('-') > 2: s -= 5
        if sum(c.isdigit() for c in d) > len(d) * 0.3: s -= 5
        if d.count('.') > 3: s -= 5
        return s

    # Ejecuta todas las validaciones avanzadas
    def check_all_advanced_validations(self, email: str) -> Dict[str, ValidationResult]:
        return {
            "honeypot": self.check_honeypot(email),
            "domain_reputation": self.check_domain_reputation(email)
        }
