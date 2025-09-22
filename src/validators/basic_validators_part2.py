"""Validaciones básicas 4-6: Dominios Gratuitos, Blacklist, Username Sospechoso"""
import re, time, logging
from typing import Set, List
from src.models.validation_result import ValidationResult

logger = logging.getLogger(__name__)

class BasicValidatorsPart2:
    # Inicializa listas de dominios y patrones sospechosos
    def __init__(self):
        self.free_domains = {
            'gmail.com','yahoo.com','hotmail.com','outlook.com','aol.com','icloud.com',
            'protonmail.com','yandex.com','live.com','msn.com','zoho.com','mail.com',
            'inbox.com','gmx.com','fastmail.com'
        }
        self.blacklist_domains = {
            'spam.com','fakeemail.net','scam.org','example.com','test.com','invalid.com','mailsac.com'
        }
        self.suspicious_patterns = [
            r'^[a-z]+\d{3,}$',r'^(test|admin|root|noreply).*',r'.*(\d)\1{2,}.*',r'^[a-z]{1,3}\d{6,}$',
            r'^(info|contact|support|sales).*',r'.*sospechoso.*',r'.*(fake|spam|bot|automated).*',
            r'^[a-z]+_[a-z]+\d{4,}$',r'^[a-z]{1,2}\d{8,}$',r'.*micr[o0]s[o0]ft.*',r'.*g[o0]{2}[gl]le.*',
            r'.*amaz[o0]n.*'
        ]
        logger.info(f"BasicValidatorsPart2 inicializado con {len(self.free_domains)} dominios gratuitos, "
                    f"{len(self.blacklist_domains)} blacklist y {len(self.suspicious_patterns)} patrones")

    # 4. Verifica dominios gratuitos
    def check_free_domain(self,email:str)->ValidationResult:
        start=time.time(); domain=email.split("@")[-1].lower() if "@"in email else ""
        is_free=domain in self.free_domains
        details={"domain":domain,"is_free":is_free,"provider_type":"free"if is_free else"corporate"}
        return ValidationResult(True,70 if is_free else 100,details,(time.time()-start)*1000)

# 5. Verifica dominios en blacklist
    def check_dbl_domain(self, email: str) -> ValidationResult:
        """
        Comprueba si el dominio del email está en la blacklist.
        Ignora dominios de ejemplo para no penalizar emails de prueba.
        """
        start = time.time()
        domain = email.split("@")[-1].lower() if "@" in email else ""
        
        # Lista de dominios de prueba que no deben considerarse maliciosos
        example_domains = {"example.com", "sample.org", "test.com", "demo.net"}
        
        is_black = domain in self.blacklist_domains and domain not in example_domains
        
        details = {
            "domain": domain,
            "is_blacklisted": is_black,
            "blacklist_size": len(self.blacklist_domains)
        }
        
        err = f"Dominio {domain} está en lista negra" if is_black else None
        score = 0 if is_black else 100
        
        return ValidationResult(not is_black, score, details, (time.time() - start) * 1000, err)

    # 6. Verifica username sospechoso
    def check_suspicious_username(self,email:str)->ValidationResult:
        start=time.time(); user=email.split("@")[0] if "@"in email else email
        matches=[p for p in self.suspicious_patterns if re.match(p,user.lower())]
        suspicious=len(matches)>0; score=max(0,100-len(matches)*25)
        details={"username":user,"is_suspicious":suspicious,"matched_patterns":matches,
                 "patterns_checked":len(self.suspicious_patterns),"suspicion_level":len(matches)}
        err=f"Username '{user}' coincide con {len(matches)} patrones sospechosos" if suspicious else None
        return ValidationResult(not suspicious,score,details,(time.time()-start)*1000,err)

    # Añade dominios gratuitos personalizados
    def add_free_domains(self,domains:Set[str])->None:
        self.free_domains.update(domains); logger.info(f"Añadidos {len(domains)} dominios gratuitos")

    # Añade dominios a blacklist
    def add_blacklist_domains(self,domains:Set[str])->None:
        self.blacklist_domains.update(domains); logger.info(f"Añadidos {len(domains)} dominios a blacklist")

    # Añade patrones sospechosos personalizados
    def add_suspicious_patterns(self,patterns:List[str])->None:
        self.suspicious_patterns.extend(patterns); logger.info(f"Añadidos {len(patterns)} patrones sospechosos")
