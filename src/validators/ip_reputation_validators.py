# Validaciones IP 17-18: reputación IP y listas RBL
import time, logging, socket, requests
from typing import Dict, Any, List
from src.models.validation_result import ValidationResult

logger = logging.getLogger(__name__)

# Clase para validaciones de reputación IP y verificación en listas negras (RBL)
class IPReputationValidators:
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.rbl_lists = [
            'zen.spamhaus.org',
            'bl.spamcop.net',
            'b.barracudacentral.org',
            'dnsbl.sorbs.net',
            'psbl.surriel.com'
        ]
        self.corporate_ranges = {
            'google': ['8.8.8.0/24', '8.8.4.0/24'],
            'cloudflare': ['1.1.1.0/24', '1.0.0.0/24'],
            'microsoft': ['40.0.0.0/8', '13.0.0.0/8']
        }
        logger.info("IPReputationValidators inicializado")

    # Evalúa reputación IP de los servidores MX del dominio
    def check_ip_reputation(self, email: str) -> ValidationResult:
        start = time.time()
        if not email or "@" not in email:
            return ValidationResult(False, 0, {"error": "Email inválido"},
                                    (time.time() - start) * 1000, "Email sin formato válido")

        domain = email.split("@")[1].lower()
        score, ip_analyses = 50, []
        try:
            mx_ips = self._get_mx_ips(domain)
            if not mx_ips:
                return ValidationResult(False, 30, {"error": "No se pudieron resolver IPs MX"},
                                        (time.time() - start) * 1000, "Error resolviendo MX")

            for ip in mx_ips[:3]:
                a = self._analyze_single_ip(ip)
                ip_analyses.append(a)
                score += a['score_adjustment']

            score = max(0, min(100, score))
            level = ("excellent" if score >= 80 else "good" if score >= 60
                     else "neutral" if score >= 40 else "poor")
            details = {
                "domain": domain,
                "mx_ips_analyzed": len(ip_analyses),
                "reputation_score": score,
                "reputation_level": level,
                "ip_analyses": ip_analyses
            }
        except Exception as e:
            logger.error(f"Error reputación IP {domain}: {e}")
            return ValidationResult(False, 40, {"error": str(e)},
                                    (time.time() - start) * 1000, f"Error: {str(e)}")

        err = f"IPs con reputación muy baja: {level}" if score < 30 else None
        return ValidationResult(score >= 40, score, details, (time.time() - start) * 1000, err)

    # Verifica IPs en listas RBL conocidas
    def check_rbl_lists(self, email: str) -> ValidationResult:
        start = time.time()
        if not email or "@" not in email:
            return ValidationResult(False, 0, {"error": "Email inválido"},
                                    (time.time() - start) * 1000, "Email sin formato válido")

        domain = email.split("@")[1].lower()
        blacklisted_count, total_checks = 0, 0
        rbl_results = []

        try:
            mx_ips = self._get_mx_ips(domain)
            if not mx_ips:
                return ValidationResult(False, 30, {"error": "No se pudieron resolver IPs MX"},
                                        (time.time() - start) * 1000, "Error resolviendo MX")

            for ip in mx_ips[:2]:
                for rbl in self.rbl_lists:
                    total_checks += 1
                    listed = self._check_ip_in_rbl(ip, rbl)
                    if listed:
                        blacklisted_count += 1
                        rbl_results.append(f"{ip} listada en {rbl}")

            blacklist_pct = (blacklisted_count / total_checks) * 100 if total_checks > 0 else 0
            score = 100 if blacklist_pct == 0 else 80 if blacklist_pct < 20 else 50 if blacklist_pct < 50 else 0

            details = {
                "domain": domain,
                "mx_ips_checked": len(mx_ips[:2]),
                "total_rbl_checks": total_checks,
                "blacklisted_count": blacklisted_count,
                "blacklist_percentage": round(blacklist_pct, 1),
                "rbl_results": rbl_results,
                "rbl_lists_used": self.rbl_lists
            }
            err = f"IP encontrada en {blacklisted_count} listas RBL" if blacklisted_count > 0 else None
        except Exception as e:
            logger.error(f"Error RBL {domain}: {e}")
            return ValidationResult(False, 40, {"error": str(e)},
                                    (time.time() - start) * 1000, f"Error RBL: {str(e)}")

        return ValidationResult(blacklisted_count == 0, score, details, (time.time() - start) * 1000, err)

    # Obtiene IPs de servidores MX del dominio
    def _get_mx_ips(self, domain: str) -> List[str]:
        try:
            import dns.resolver
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            ips = []
            for mx in resolver.resolve(domain, 'MX'):
                mx_host = str(mx.exchange).rstrip('.')
                try:
                    ip = socket.gethostbyname(mx_host)
                    if ip not in ips:
                        ips.append(ip)
                except:
                    continue
            return ips[:3]
        except Exception as e:
            logger.warning(f"Error MX IPs {domain}: {e}")
            return []

    # Analiza una sola IP para reputación
    def _analyze_single_ip(self, ip: str) -> Dict[str, Any]:
        analysis = {"ip": ip, "score_adjustment": 0, "factors": []}
        try:
            if self._is_private_ip(ip):
                analysis["factors"].append("IP privada/local")
                analysis["score_adjustment"] = -20
                return analysis
            geo = self._get_basic_geo_info(ip)
            if geo:
                analysis["factors"].append(f"Geolocalización: {geo}")
                if geo.get('country') in ['CN', 'RU', 'BR', 'IN', 'PK']:
                    analysis["score_adjustment"] -= 10
                else:
                    analysis["score_adjustment"] += 5
            if self._is_corporate_ip(ip):
                analysis["factors"].append("IP corporativa conocida")
                analysis["score_adjustment"] += 15
        except Exception as e:
            logger.warning(f"Error analizando IP {ip}: {e}")
            analysis["factors"].append(f"Error: {str(e)}")
        return analysis

    # Verifica si IP está listada en una RBL
    def _check_ip_in_rbl(self, ip: str, rbl: str) -> bool:
        try:
            reversed_ip = '.'.join(reversed(ip.split('.')))
            socket.gethostbyname(f"{reversed_ip}.{rbl}")
            return True
        except socket.gaierror:
            return False
        except Exception as e:
            logger.warning(f"Error RBL {ip} en {rbl}: {e}")
            return False

    # Verifica si IP es privada o local
    def _is_private_ip(self, ip: str) -> bool:
        o = [int(x) for x in ip.split('.')]
        return o[0] == 10 or (o[0] == 172 and 16 <= o[1] <= 31) or (o[0] == 192 and o[1] == 168) or o[0] == 127

    # Verifica si IP pertenece a rango corporativo conocido
    def _is_corporate_ip(self, ip: str) -> bool:
        o = [int(x) for x in ip.split('.')]
        return (o[0] == 8 and o[1] in [8, 34]) or (o[0] == 1 and o[1] in [0, 1])

    # Obtiene info geográfica básica de la IP
    def _get_basic_geo_info(self, ip: str) -> Dict[str, Any]:
        try:
            r = requests.get(f"http://ip-api.com/json/{ip}?fields=country,isp", timeout=3)
            d = r.json()
            if d.get('status') == 'success':
                return {'country': d.get('countryCode', 'Unknown'), 'isp': d.get('isp', 'Unknown')}
        except:
            pass
        return None

    # Ejecuta todas las validaciones IP
    def check_all_ip_validations(self, email: str) -> Dict[str, ValidationResult]:
        return {
            "ip_reputation": self.check_ip_reputation(email),
            "rbl_lists": self.check_rbl_lists(email)
        }
