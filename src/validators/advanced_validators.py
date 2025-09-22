"""
Validaciones Avanzadas: Honeypot y Reputación de Dominio
"""

import time
import logging
import requests
import socket
import ssl
import re
from datetime import datetime
from typing import Dict
from src.models.validation_result import ValidationResult

logger = logging.getLogger(__name__)

# Dominios de prueba reservados/excluidos (no se consideran honeypot)
EXCLUDED_DOMAINS = [
    "example.com","example.net","example.org",
    "test.com","test.net","test.org",
    "demo.com","demo.net","demo.org",
    "sample.com","sample.net","sample.org"
]

class AdvancedValidators:
    def __init__(self, timeout:int=10):
        self.timeout = timeout
        self.honeypot_patterns = [
            r'^(admin|administrator|root|test|demo|sample|example|info|contact|support|help|sales|marketing|noreply|no-reply|donotreply|do-not-reply|webmaster|hostmaster|postmaster|abuse|bot|crawler|spider|scraper|harvester|fake|dummy|temp|temporary|invalid|catch|catchall|catch-all|all)$',
            r'^.*(test|temp|fake|dummy|invalid).*$',
            r'^.*\d{4,}.*$', r'^[a-z]{1,2}$', r'^[a-z]{20,}$'
        ]
        self.honeypot_domains = {
            'honeypot.com','trap.net','bait.org','decoy.info','spamtrap.com',
            'botcatch.net','scrapertrap.org','invalid.net','fake.com','dummy.org',
            'temp.net','mailinator.com','guerrillamail.com','tempmail.org'
        }
        self.trusted_tlds = {
            'high':['.com','.org','.net','.edu','.gov','.mil'],
            'medium':['.info','.biz','.name','.pro','.aero','.coop'],
            'low':['.tk','.ml','.ga','.cf','.pw','.top','.click','.download']
        }
        self.trusted_registrars = {
            'godaddy','namecheap','google','amazon','microsoft','cloudflare','markmonitor',
            'network solutions','tucows','enom','name.com','hover','gandi','1&1','ovh'
        }
        logger.info("AdvancedValidators inicializado")

    # Honeypot
    def check_honeypot(self, email: str) -> ValidationResult:
        """
        15. Honeypot Detection - VERSIÓN CORREGIDA
        Solo detecta honeypots obvios, no penaliza emails corporativos legítimos
        """
        start_time = time.time()
        
        if not email or "@" not in email:
            return ValidationResult(
                False, 0, {"error": "Email inválido"},
                (time.time() - start_time) * 1000, "Email sin formato válido"
            )
        
        username, domain = email.split("@")
        username = username.lower()
        domain = domain.lower()
        
        is_honeypot = False
        honeypot_indicators = []
        suspicion_level = 0
        
        # 1. Verificar dominio honeypot conocido (solo dominios obviamente falsos)
        obvious_honeypot_domains = {
            'honeypot.com', 'trap.net', 'bait.org', 'spamtrap.com', 
            'example.com', 'test.com', 'demo.net', 'invalid.net',
            'fake.com', 'dummy.org', 'mailinator.com'
        }
        
        if domain in obvious_honeypot_domains:
            is_honeypot = True
            honeypot_indicators.append(f"Dominio honeypot obvio: {domain}")
            suspicion_level = 5
        
        # 2. Verificar TLDs reservados para pruebas
        if domain.endswith(('.test', '.invalid', '.localhost', '.example')):
            is_honeypot = True
            honeypot_indicators.append(f"TLD reservado para pruebas")
            suspicion_level = 5
        
        # 3. NUEVA LÓGICA: Solo marcar como honeypot si es dominio + username sospechoso
        # NO penalizar emails corporativos de empresas reales
        known_companies = {
            'google.com', 'microsoft.com', 'amazon.com', 'apple.com', 'meta.com',
            'reddit.com', 'twitter.com', 'linkedin.com', 'github.com', 'stackoverflow.com',
            'netflix.com', 'spotify.com', 'adobe.com', 'salesforce.com', 'uber.com'
        }
        
        # Si es empresa conocida, NO es honeypot (incluso con admin/info)
        if domain in known_companies:
            is_honeypot = False
            suspicion_level = 0
            honeypot_indicators = []
        
        # 4. Solo para dominios desconocidos: verificar patrones extremos
        elif not any(tld in domain for tld in ['.com', '.org', '.net', '.gov', '.edu']):
            # Solo patrones muy obvios de honeypot
            extreme_patterns = [
                r'^(test|demo|fake|dummy|invalid|temp)$',
                r'^.*(test|fake|dummy|invalid).*$',
                r'^[a-z]{1}$',  # Solo una letra
                r'^[0-9]+$',    # Solo números
            ]
            
            import re
            for pattern in extreme_patterns:
                if re.match(pattern, username):
                    suspicion_level = max(suspicion_level, 3)
                    honeypot_indicators.append(f"Patrón extremo detectado: {pattern}")
                    break
        
        # 5. Calcular score - MÁS PERMISIVO
        if is_honeypot:
            score = 0  # Solo honeypots obvios
        elif suspicion_level >= 3:
            score = 60  # Reducir penalización
        elif suspicion_level >= 2:
            score = 80  # Más permisivo
        else:
            score = 100  # Default: no es honeypot
        
        # 6. Preparar detalles
        details = {
            "email": email,
            "username": username,
            "domain": domain,
            "is_honeypot": is_honeypot,
            "honeypot_indicators": honeypot_indicators,
            "suspicion_level": suspicion_level,
            "is_known_company": domain in known_companies
        }
        
        error_msg = None
        if is_honeypot:
            error_msg = f"Email honeypot obvio: {', '.join(honeypot_indicators)}"
        
        processing_time = (time.time() - start_time) * 1000
        return ValidationResult(not is_honeypot, score, details, processing_time, error_msg)


    # Reputación de dominio
    def check_domain_reputation(self,email:str)->ValidationResult:
        """
        Analiza reputación del dominio mediante TLD, edad, SSL, registrar y estructura.
        Dominios de prueba reservados se consideran validos automáticamente.
        """
        start = time.time()
        if not email or "@" not in email:
            return ValidationResult(False,0,{"error":"Email inválido"},(time.time()-start)*1000,"Email sin formato válido")

        domain = email.split("@")[1].lower()
        if domain in EXCLUDED_DOMAINS:
            return ValidationResult(
                True,
                100,
                {"domain": domain, "note": "Dominio de prueba reservado, se considera válido"},
                (time.time()-start)*1000,
                None
            )

        score = 50
        details = {}

        try:
            tld_score = self._analyze_tld(domain)
            score += tld_score
            details["tld_analysis"] = {"tld": domain.split('.')[-1], "score": tld_score, "category": self._get_tld_category(domain)}

            age_score, age_info = self._analyze_domain_age(domain)
            score += age_score
            details["domain_age"] = age_info

            ssl_score, ssl_info = self._analyze_ssl_certificate(domain)
            score += ssl_score
            details["ssl_certificate"] = ssl_info

            reg_score, reg_info = self._analyze_registrar(domain)
            score += reg_score
            details["registrar_analysis"] = reg_info

            struct_score = self._analyze_domain_structure(domain)
            score += struct_score
            details["domain_structure"] = {
                "score": struct_score,
                "length": len(domain),
                "subdomains": domain.count('.')-1,
                "has_hyphens": '-' in domain,
                "has_numbers": any(c.isdigit() for c in domain)
            }

            score = max(0, min(100, score))
            level = "excellent" if score>=80 else "good" if score>=60 else "neutral" if score>=40 else "poor" if score>=20 else "very_poor"

        except Exception as e:
            logger.error(f"Error analizando reputación de {domain}: {e}")
            score, level, details = 40, "unknown", {"error": str(e)}

        err = f"Dominio con reputación muy baja: {level}" if score<20 else f"Dominio cuestionable: {level}" if score<40 else None

        return ValidationResult(
            score>=40,
            score,
            {
                "domain": domain,
                "reputation_score": score,
                "reputation_level": level,
                "analysis_details": details,
                "factors_analyzed": ["tld","domain_age","ssl_certificate","registrar","structure"]
            },
            (time.time()-start)*1000,
            err
        )

    # Funciones auxiliares (sin cambios)
    def _analyze_tld(self,d:str)->int:
        if '.' not in d: return -20
        t='.'+d.split('.')[-1]
        return 20 if t in self.trusted_tlds['high'] else 5 if t in self.trusted_tlds['medium'] else -15 if t in self.trusted_tlds['low'] else 0

    def _get_tld_category(self,d:str)->str:
        if '.' not in d: return "invalid"
        t='.'+d.split('.')[-1]
        for cat,tlds in self.trusted_tlds.items():
            if t in tlds: return cat
        return "unknown"

    def _analyze_domain_age(self,d:str)->tuple:
        try:
            import whois
            info = whois.whois(d)
            if info and info.creation_date:
                cd = info.creation_date[0] if isinstance(info.creation_date,list) else info.creation_date
                age = (datetime.now()-cd).days/365.25
                s = 15 if age>=10 else 10 if age>=5 else 5 if age>=2 else 0 if age>=1 else -10
                return s, {"creation_date": cd.isoformat(), "age_years": round(age,1), "score": s}
        except Exception as e: 
            logger.warning(f"WHOIS error {d}: {e}")
        return 0, {"error":"No se pudo obtener edad"}

    def _analyze_ssl_certificate(self,d:str)->tuple:
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((d,443),timeout=self.timeout) as s:
                with ctx.wrap_socket(s,server_hostname=d) as ss:
                    c=ss.getpeercert()
                    if c:
                        exp=datetime.strptime(c['notAfter'],'%b %d %H:%M:%S %Y %Z')
                        days=(exp-datetime.now()).days
                        sc=10 if days>30 else 5 if days>0 else -10
                        return sc, {"has_ssl":True,"expires":exp.isoformat(),"days_until_expiry":days,"score":sc}
        except Exception as e: 
            logger.warning(f"SSL error {d}: {e}")
        return -5, {"has_ssl":False,"error":"No SSL o error"}

    def _analyze_registrar(self,d:str)->tuple:
        try:
            import whois
            info = whois.whois(d)
            if info and info.registrar:
                r = info.registrar.lower()
                if any(t in r for t in self.trusted_registrars):
                    return 10, {"registrar": info.registrar, "is_trusted": True, "score": 10}
                return 0, {"registrar": info.registrar, "is_trusted": False, "score": 0}
        except Exception as e: 
            logger.warning(f"Registrar error {d}: {e}")
        return 0, {"error":"No se pudo obtener registrador"}

    def _analyze_domain_structure(self,d:str)->int:
        s = 5 if 5<=len(d)<=20 else -5 if len(d)>30 else 0
        if d.count('-')>2: s-=5
        if sum(c.isdigit() for c in d)>len(d)*0.3: s-=5
        if d.count('.')>3: s-=5
        return s

    # Ejecuta todas las validaciones avanzadas
    def check_all_advanced_validations(self,email:str)->Dict[str,ValidationResult]:
        return {
            "honeypot": self.check_honeypot(email),
            "domain_reputation": self.check_domain_reputation(email)
        }
