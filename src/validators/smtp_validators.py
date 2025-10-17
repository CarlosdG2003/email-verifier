# Validaciones SMTP 13-14: existencia de buzón y aceptación de mail
import smtplib, socket, time, logging, dns.resolver
from typing import Dict, Any, Optional
from src.models.validation_result import ValidationResult

logger = logging.getLogger(__name__)

# Clase para validaciones SMTP: buzón existente y aceptación de mail
class SMTPValidators:
    # Inicializa validador SMTP con timeout
    def __init__(self, timeout: int = 15):
        self.timeout = timeout
        socket.setdefaulttimeout(timeout)
        self.test_sender = "test@verification-system.com"
        logger.info(f"SMTPValidators inicializado con timeout: {timeout}s")

    # Obtiene servidor MX principal del dominio
    def _get_mx_server(self, domain: str) -> Optional[str]:
        try:
            r = dns.resolver.Resolver()
            r.timeout = 5
            r.nameservers = ['8.8.8.8', '1.1.1.1']
            mx = r.resolve(domain, 'MX')
            if mx:
                get_p = lambda m: getattr(m, 'priority', getattr(m, 'preference', 0))
                return str(sorted(mx, key=get_p)[0].exchange).rstrip('.')
        except:
            return None

    # Verifica existencia del buzón con SMTP RCPT TO
    def check_mailbox_exists(self, email: str) -> ValidationResult:
        start = time.time()
        domain = email.split('@')[-1].lower() if '@' in email else ''
        if not domain:
            return ValidationResult(False, 0, {"error": "No se pudo extraer dominio"},
                                    (time.time() - start) * 1000, "Email sin dominio válido")

        exists, resp, err, blocks = False, "", "", False
        try:
            mx = self._get_mx_server(domain)
            if not mx:
                err = "No se encontró servidor MX"
                return ValidationResult(False, 0, {"error": err, "domain": domain},
                                        (time.time() - start) * 1000, err)

            with smtplib.SMTP(mx, 25, timeout=self.timeout) as s:
                s.helo(socket.getfqdn())
                s.mail(self.test_sender)
                try:
                    code, r = s.rcpt(email)
                    resp = f"{code} {r.decode() if isinstance(r, bytes) else r}"
                    if code == 250:
                        exists = True
                    elif code in [251, 252]:
                        exists, blocks = True, True
                    elif code in [450, 451, 452]:
                        err = f"Error temporal: {resp}"
                    elif code in [550, 551, 553]:
                        err = f"Buzón no existe: {resp}"
                    else:
                        err = f"Respuesta inesperada: {resp}"
                except smtplib.SMTPRecipientsRefused:
                    err = "Buzón rechazado"
                except smtplib.SMTPResponseException as e:
                    resp = f"{e.smtp_code} {e.smtp_error}"
                    if e.smtp_code in [252, 450]:
                        blocks = True
                        err = "Servidor bloquea verificación"
                    else:
                        err = f"Error SMTP: {resp}"

        except smtplib.SMTPConnectError:
            err = "No se pudo conectar al servidor SMTP"
        except smtplib.SMTPServerDisconnected:
            err = "Servidor SMTP desconectó"
        except socket.timeout:
            err = f"Timeout SMTP tras {self.timeout}s"
        except socket.gaierror:
            err = "Error resolviendo MX"
        except Exception as e:
            err = f"Error SMTP: {e}"

        score = (100 if exists and not blocks else
                 80 if exists and blocks else
                 60 if blocks else
                 50 if err and ("timeout" in err.lower() or "temporal" in err.lower()) else 0)

        details = {
            "domain": domain,
            "mx_server": mx if 'mx' in locals() else "unknown",
            "mailbox_exists": exists,
            "smtp_response": resp,
            "server_blocks_verification": blocks,
            "verification_method": "SMTP RCPT TO"
        }
        return ValidationResult(exists or blocks, score, details, (time.time() - start) * 1000, err)

    # Verifica aceptación de mail completo (SMTP DATA)
    def check_mail_acceptance(self, email: str) -> ValidationResult:
        start = time.time()
        domain = email.split('@')[-1].lower() if '@' in email else ''
        if not domain:
            return ValidationResult(False, 0, {"error": "No se pudo extraer dominio"},
                                    (time.time() - start) * 1000, "Email sin dominio válido")

        accepts, log, err = False, [], None
        try:
            mx = self._get_mx_server(domain)
            if not mx:
                err = "No se encontró servidor MX"
                return ValidationResult(False, 0, {"error": err, "domain": domain},
                                        (time.time() - start) * 1000, err)

            with smtplib.SMTP(mx, 25, timeout=self.timeout) as s:
                log.append(f"HELO: {s.helo(socket.getfqdn())[0]}")
                log.append(f"MAIL FROM: {s.mail(self.test_sender)[0]}")
                try:
                    r = s.rcpt(email)
                    log.append(f"RCPT TO: {r[0]}")
                    if r[0] in [250, 251, 252]:
                        try:
                            d = s.docmd("DATA")
                            log.append(f"DATA: {d[0]}")
                            if d[0] == 354:
                                accepts = True
                                s.quit()
                            else:
                                err = f"Rechazó DATA: {d[1]}"
                        except smtplib.SMTPResponseException as e:
                            if e.smtp_code == 354:
                                accepts = True
                                s.quit()
                            else:
                                err = f"Error DATA: {e.smtp_code} {e.smtp_error}"
                    else:
                        err = f"RCPT TO falló: {r[0]}"
                except smtplib.SMTPRecipientsRefused:
                    err = "Destinatario rechazado"
                    log.append("RCPT TO: Rechazado")

        except smtplib.SMTPConnectError:
            err = "No se pudo conectar al servidor SMTP"
        except socket.timeout:
            err = f"Timeout SMTP tras {self.timeout}s"
        except Exception as e:
            err = f"Error SMTP: {e}"

        score = (100 if accepts else
                 50 if err and any(x in err.lower() for x in ["timeout", "conectar"]) else
                 0 if err and "rechazado" in err.lower() else 30)

        details = {
            "domain": domain,
            "mx_server": mx if 'mx' in locals() else "unknown",
            "accepts_mail": accepts,
            "transaction_log": log,
            "verification_method": "SMTP Full Transaction"
        }
        return ValidationResult(accepts, score, details, (time.time() - start) * 1000, err)

    # Ejecuta todas las validaciones SMTP
    def check_all_smtp_validations(self, email: str) -> Dict[str, ValidationResult]:
        return {
            "mailbox_exists": self.check_mailbox_exists(email),
            "mail_acceptance": self.check_mail_acceptance(email)
        }

    # Actualiza timeout SMTP
    def set_timeout(self, timeout: int) -> None:
        self.timeout = timeout
        socket.setdefaulttimeout(timeout)
