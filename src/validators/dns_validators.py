"""Validaciones DNS: MX, SPF, DKIM, DMARC"""

import dns.resolver, time, logging
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
        self.common_dkim_selectors = ['default', 'google', 'k1', 'dkim', 'mail', 'selector1', 'selector2']
        logger.info(f"DNSValidators inicializado con timeout {timeout}s")

    def check_mx_record(self, email: str) -> ValidationResult:
        start = time.time()
        domain = email.split("@")[-1] if "@" in email else ""
        if not domain:
            return ValidationResult(False, 0, {"error": "Dominio no válido"}, (time.time() - start) * 1000)
        mx, has, err = [], False, None
        try:
            mx = [str(r) for r in self.resolver.resolve(domain, 'MX')]
            has = len(mx) > 0
        except dns.resolver.NXDOMAIN:
            err = "Dominio inexistente"
        except dns.resolver.NoAnswer:
            err = "Sin registros MX"
        except dns.resolver.Timeout:
            err = f"Timeout DNS ({self.timeout}s)"
        except Exception as e:
            err = f"Error DNS: {e}"
        return ValidationResult(has, 100 if has else 0,
                                {"domain": domain, "has_mx_records": has, "mx_records": mx, "mx_count": len(mx)},
                                (time.time() - start) * 1000, err)

    def check_spf_record(self, email: str) -> ValidationResult:
        start = time.time()
        domain = email.split("@")[-1] if "@" in email else ""
        if not domain:
            return ValidationResult(True, 60, {"error": "Dominio no válido"}, (time.time() - start) * 1000)
        has_spf, spf, err = False, "", None
        try:
            for r in self.resolver.resolve(domain, 'TXT'):
                t = str(r).strip('"')
                if t.startswith('v=spf1'):
                    has_spf, spf = True, t
                    break
        except dns.resolver.NXDOMAIN:
            err = "Dominio inexistente"
        except dns.resolver.Timeout:
            err = f"Timeout DNS ({self.timeout}s)"
        except dns.resolver.NoAnswer:
            pass
        except Exception as e:
            err = f"Error SPF: {e}"
        score = 100 if has_spf else (0 if err and "Dominio inexistente" in err else 60)
        return ValidationResult(True, score,
                                {"domain": domain, "has_spf_record": has_spf, "spf_record": spf},
                                (time.time() - start) * 1000, err)

    def check_dkim_record(self, email: str) -> ValidationResult:
        start = time.time()
        domain = email.split("@")[-1] if "@" in email else ""
        if not domain:
            return ValidationResult(True, 70, {"error": "Dominio no válido"}, (time.time() - start) * 1000)
        has_dkim, records, found = False, [], []
        for s in self.common_dkim_selectors:
            try:
                for r in self.resolver.resolve(f"{s}._domainkey.{domain}", 'TXT'):
                    t = str(r).strip('"')
                    if 'v=DKIM1' in t:
                        has_dkim = True
                        found.append(s)
                        records.append({"selector": s, "record": t})
                        break
            except:
                continue
        return ValidationResult(True, 100 if has_dkim else 70,
                                {"domain": domain, "has_dkim_records": has_dkim,
                                 "dkim_records": records, "found_selectors": found},
                                (time.time() - start) * 1000)

    def check_dmarc_record(self, email: str) -> ValidationResult:
        start = time.time()
        domain = email.split("@")[-1] if "@" in email else ""
        if not domain:
            return ValidationResult(True, 70, {"error": "Dominio no válido"}, (time.time() - start) * 1000)
        has, dmarc, policy, err = False, "", "", None
        try:
            for r in self.resolver.resolve(f"_dmarc.{domain}", 'TXT'):
                t = str(r).strip('"')
                if t.startswith('v=DMARC1'):
                    has, dmarc = True, t
                for p in t.split(';'):
                    if p.strip().startswith('p='):
                        policy = p.strip().split('=')[1]
                if has:
                    break
        except dns.resolver.NXDOMAIN:
            err = "Dominio inexistente"
        except dns.resolver.Timeout:
            err = f"Timeout DNS ({self.timeout}s)"
        except dns.resolver.NoAnswer:
            pass
        except Exception as e:
            err = f"Error DMARC: {e}"
        score = 100 if has else (0 if err and "Dominio inexistente" in err else 70)
        return ValidationResult(True, score,
                                {"domain": domain, "has_dmarc_record": has,
                                 "dmarc_record": dmarc, "dmarc_policy": policy},
                                (time.time() - start) * 1000, err)

    def check_all_dns_records(self, email: str) -> Dict[str, ValidationResult]:
        return {
            "mx_record": self.check_mx_record(email),
            "spf_record": self.check_spf_record(email),
            "dkim_record": self.check_dkim_record(email),
            "dmarc_record": self.check_dmarc_record(email)
        }

    def set_timeout(self, timeout: int) -> None:
        self.timeout = timeout
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout + 2
