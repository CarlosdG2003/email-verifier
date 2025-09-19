"""
Validaciones SMTP 13-14: Existencia de Buzón y Aceptación de Mail
"""

import smtplib
import socket
import time
import logging
from typing import Dict, Any, Optional
from src.models.validation_result import ValidationResult

logger = logging.getLogger(__name__)

class SMTPValidators:
    
    def __init__(self, timeout: int = 15):
        self.timeout = timeout
        socket.setdefaulttimeout(timeout)
        
        # Email ficticio para pruebas SMTP
        self.test_sender = "test@verification-system.com"
        
        logger.info(f"SMTPValidators inicializado con timeout: {timeout}s")
    
    def check_mailbox_exists(self, email: str) -> ValidationResult:
        """
        13. Existencia del Buzón - Conecta vía SMTP para verificar si el email existe
        
        Usa comando RCPT TO para verificar si el buzón existe sin enviar email.
        Muchos servidores modernos bloquean o falsifican esta verificación.
        """
        start_time = time.time()
        
        domain = email.split("@")[-1].lower() if "@" in email else ""
        if not domain:
            return ValidationResult(
                False, 0, {"error": "No se pudo extraer dominio"},
                (time.time() - start_time) * 1000, "Email sin dominio válido"
            )
        
        mailbox_exists = False
        smtp_response = ""
        error_msg = None
        server_blocks_verification = False
        
        try:
            # Obtener servidor MX
            mx_server = self._get_mx_server(domain)
            if not mx_server:
                error_msg = "No se encontró servidor MX"
                return ValidationResult(False, 0, 
                    {"error": error_msg, "domain": domain}, 
                    (time.time() - start_time) * 1000, error_msg)
            
            # Conectar a servidor SMTP
            with smtplib.SMTP(mx_server, 25, timeout=self.timeout) as server:
                server.set_debuglevel(0)
                
                # HELO
                server.helo(socket.getfqdn())
                
                # MAIL FROM
                server.mail(self.test_sender)
                
                # RCPT TO - Aquí se verifica si el buzón existe
                try:
                    code, response = server.rcpt(email)
                    smtp_response = f"{code} {response.decode() if isinstance(response, bytes) else response}"
                    
                    # Códigos SMTP estándar
                    if code == 250:
                        mailbox_exists = True
                    elif code in [251, 252]:
                        # 251: User not local, will forward
                        # 252: Cannot verify user, but will accept message
                        mailbox_exists = True  # Probable que exista
                        server_blocks_verification = True
                    elif code in [450, 451, 452]:
                        # Errores temporales
                        error_msg = f"Error temporal del servidor: {smtp_response}"
                    elif code in [550, 551, 553]:
                        # Buzón no existe o rechazado
                        mailbox_exists = False
                        error_msg = f"Buzón no existe: {smtp_response}"
                    else:
                        error_msg = f"Respuesta inesperada: {smtp_response}"
                        
                except smtplib.SMTPRecipientsRefused:
                    mailbox_exists = False
                    error_msg = "Buzón rechazado por el servidor"
                except smtplib.SMTPResponseException as e:
                    smtp_response = f"{e.smtp_code} {e.smtp_error}"
                    if e.smtp_code in [252, 450]:
                        server_blocks_verification = True
                        error_msg = "Servidor bloquea verificación de buzones"
                    else:
                        mailbox_exists = False
                        error_msg = f"Error SMTP: {smtp_response}"
                
        except smtplib.SMTPConnectError:
            error_msg = "No se pudo conectar al servidor SMTP"
        except smtplib.SMTPServerDisconnected:
            error_msg = "Servidor SMTP desconectó durante verificación"
        except socket.timeout:
            error_msg = f"Timeout SMTP tras {self.timeout}s"
        except socket.gaierror:
            error_msg = "Error resolviendo servidor MX"
        except Exception as e:
            error_msg = f"Error SMTP: {str(e)}"
        
        # Calcular score
        if mailbox_exists and not server_blocks_verification:
            score = 100  # Confirmado que existe
        elif mailbox_exists and server_blocks_verification:
            score = 80   # Probablemente existe pero servidor no confirma
        elif server_blocks_verification:
            score = 60   # No se pudo verificar, asumir neutral
        elif error_msg and ("timeout" in error_msg.lower() or "temporal" in error_msg.lower()):
            score = 50   # Error temporal, no concluyente
        else:
            score = 0    # Confirmado que no existe
        
        details = {
            "domain": domain,
            "mx_server": mx_server if 'mx_server' in locals() else "unknown",
            "mailbox_exists": mailbox_exists,
            "smtp_response": smtp_response,
            "server_blocks_verification": server_blocks_verification,
            "verification_method": "SMTP RCPT TO"
        }
        
        processing_time = (time.time() - start_time) * 1000
        
        return ValidationResult(mailbox_exists or server_blocks_verification, score, 
                               details, processing_time, error_msg)
    
    def check_mail_acceptance(self, email: str) -> ValidationResult:
        """
        14. Aceptación de Mail - Simula envío de email completo
        
        Realiza una transacción SMTP completa hasta DATA pero sin enviar contenido.
        Más exhaustivo que check_mailbox_exists pero también más intrusivo.
        """
        start_time = time.time()
        
        domain = email.split("@")[-1].lower() if "@" in email else ""
        if not domain:
            return ValidationResult(
                False, 0, {"error": "No se pudo extraer dominio"},
                (time.time() - start_time) * 1000, "Email sin dominio válido"
            )
        
        accepts_mail = False
        transaction_log = []
        error_msg = None
        
        try:
            # Obtener servidor MX
            mx_server = self._get_mx_server(domain)
            if not mx_server:
                error_msg = "No se encontró servidor MX"
                return ValidationResult(False, 0, 
                    {"error": error_msg, "domain": domain}, 
                    (time.time() - start_time) * 1000, error_msg)
            
            # Transacción SMTP completa
            with smtplib.SMTP(mx_server, 25, timeout=self.timeout) as server:
                server.set_debuglevel(0)
                
                # HELO
                response = server.helo(socket.getfqdn())
                transaction_log.append(f"HELO: {response[0]} {response[1].decode()}")
                
                # MAIL FROM
                response = server.mail(self.test_sender)
                transaction_log.append(f"MAIL FROM: {response[0]} {response[1].decode()}")
                
                # RCPT TO
                try:
                    response = server.rcpt(email)
                    transaction_log.append(f"RCPT TO: {response[0]} {response[1].decode()}")
                    
                    if response[0] in [250, 251, 252]:
                        # Intentar comando DATA
                        try:
                            response = server.docmd("DATA")
                            transaction_log.append(f"DATA: {response[0]} {response[1]}")
                            
                            if response[0] == 354:  # 354 = Ready for message data
                                accepts_mail = True
                                # Enviar QUIT sin datos para cancelar
                                server.quit()
                            else:
                                error_msg = f"Servidor rechazó DATA: {response[1]}"
                                
                        except smtplib.SMTPResponseException as e:
                            if e.smtp_code == 354:
                                accepts_mail = True
                                server.quit()
                            else:
                                error_msg = f"Error en DATA: {e.smtp_code} {e.smtp_error}"
                                
                    else:
                        error_msg = f"RCPT TO falló: {response[0]} {response[1].decode()}"
                        
                except smtplib.SMTPRecipientsRefused:
                    error_msg = "Destinatario rechazado"
                    transaction_log.append("RCPT TO: Rechazado")
                    
        except smtplib.SMTPConnectError:
            error_msg = "No se pudo conectar al servidor SMTP"
        except socket.timeout:
            error_msg = f"Timeout SMTP tras {self.timeout}s"
        except Exception as e:
            error_msg = f"Error en transacción SMTP: {str(e)}"
        
        # Calcular score
        if accepts_mail:
            score = 100  # Acepta mail completamente
        elif error_msg and any(keyword in error_msg.lower() for keyword in ["timeout", "conectar"]):
            score = 50   # Error de conectividad, no concluyente  
        elif "rechazado" in error_msg.lower():
            score = 0    # Explícitamente rechazado
        else:
            score = 30   # Otros errores, probablemente problemático
        
        details = {
            "domain": domain,
            "mx_server": mx_server if 'mx_server' in locals() else "unknown", 
            "accepts_mail": accepts_mail,
            "transaction_log": transaction_log,
            "verification_method": "SMTP Full Transaction"
        }
        
        processing_time = (time.time() - start_time) * 1000
        
        return ValidationResult(accepts_mail, score, details, processing_time, error_msg)
    
    def _get_mx_server(self, domain: str) -> Optional[str]:
        """Obtiene el servidor MX principal del dominio"""
        try:
            import dns.resolver
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            resolver.nameservers = ['8.8.8.8', '1.1.1.1']
            
            mx_records = resolver.resolve(domain, 'MX')
            if mx_records:
                # Ordenar por prioridad (menor número = mayor prioridad)
                sorted_mx = sorted(mx_records, key=lambda x: x.priority)
                return str(sorted_mx[0].exchange).rstrip('.')
        except:
            pass
        return None
    
    def check_all_smtp_validations(self, email: str) -> Dict[str, ValidationResult]:
        """Ejecuta todas las validaciones SMTP"""
        return {
            "mailbox_exists": self.check_mailbox_exists(email),
            "mail_acceptance": self.check_mail_acceptance(email)
        }
    
    def set_timeout(self, timeout: int) -> None:
        """Actualiza el timeout SMTP"""
        self.timeout = timeout
        socket.setdefaulttimeout(timeout)