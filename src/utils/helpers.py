"""
Funciones auxiliares para el Email Verifier
"""

import json
from typing import Dict, List, Any, Set

class EmailHelpers:
    
    @staticmethod
    def extract_domain(email: str) -> str:
        """Extrae el dominio de un email"""
        if "@" not in email:
            return ""
        
        parts = email.split("@")
        if len(parts) != 2:
            return ""
        
        return parts[1].lower().strip()
    
    @staticmethod
    def extract_username(email: str) -> str:
        """Extrae el username de un email"""
        if "@" not in email:
            return email
        
        return email.split("@")[0].strip()
    
    @staticmethod
    def normalize_email(email: str) -> str:
        """Normaliza un email para comparaciones"""
        return email.lower().strip()
    
    @staticmethod
    def is_role_based_email(email: str) -> bool:
        """Verifica si es un email role-based (admin@, support@, etc.)"""
        username = EmailHelpers.extract_username(email).lower()
        
        role_patterns = [
            'admin', 'support', 'info', 'contact', 'sales', 'marketing',
            'webmaster', 'postmaster', 'abuse', 'security',
            'noreply', 'no-reply', 'donotreply', 'help', 'service'
        ]
        
        return username in role_patterns or any(
            username.startswith(pattern) for pattern in role_patterns
        )

class ScoreCalculator:
    
    @staticmethod
    def calculate_confidence_score(scores: List[int]) -> float:
        """Calcula la confianza promedio"""
        if not scores:
            return 0.0
        
        return round(sum(scores) / len(scores), 2)
    
    @staticmethod
    def calculate_risk_score(confidence: float) -> float:
        """Calcula risk score basado en la confianza"""
        return round((100 - confidence) / 10, 1)
    
    @staticmethod
    def determine_overall_status(confidence: float, fraud_indicators: List[str]) -> str:
        """Determina el estado general"""
        critical_indicators = [
            "Dominio en lista negra",
            "Formato de email inválido", 
            "Dominio temporal/desechable detectado"
        ]
        
        has_critical_fraud = any(
            indicator in fraud_indicators for indicator in critical_indicators
        )
        
        if has_critical_fraud:
            return "invalid"
        elif confidence >= 80:
            return "valid"
        elif confidence >= 60:
            return "risky"
        else:
            return "invalid"

class ReportGenerator:
    
    @staticmethod
    def generate_fraud_indicators(validation_results: Dict[str, Any]) -> List[str]:
        """Genera lista de indicadores de fraude"""
        indicators = []
        
        for section_name, section_results in validation_results.items():
            if not isinstance(section_results, dict):
                continue
                
            for check_name, check_data in section_results.items():
                if not isinstance(check_data, dict):
                    continue
                    
                score = check_data.get("score", 100)
                details = check_data.get("details", {})
                
                if check_name == "disposable_domain" and details.get("is_disposable"):
                    indicators.append("Dominio temporal/desechable detectado")
                    
                elif check_name == "dbl_domain" and details.get("is_blacklisted"):
                    indicators.append("Dominio en lista negra")
                    
                elif check_name == "suspicious_username" and score < 50:
                    indicators.append("Patrón de username sospechoso")
                    
                elif check_name == "format" and not check_data.get("is_valid"):
                    indicators.append("Formato de email inválido")
                    
                elif check_name == "mx_record" and not check_data.get("is_valid"):
                    indicators.append("Dominio no puede recibir emails")
        
        return list(set(indicators))
    
    @staticmethod
    def generate_recommendations(confidence: float, 
                               fraud_indicators: List[str]) -> List[str]:
        """Genera recomendaciones"""
        recommendations = []
        
        if fraud_indicators:
            recommendations.append("Se detectaron indicadores de riesgo en este email")
        
        if confidence >= 90:
            recommendations.append("Email parece legítimo y seguro")
        elif confidence >= 60:
            recommendations.append("Considerar verificación adicional")
        else:
            recommendations.append("Email de alto riesgo, usar con precaución")
        
        return recommendations
    
    @staticmethod
    def format_json_report(report_data: Dict[str, Any], pretty: bool = True) -> str:
        """Formatea el reporte como JSON"""
        if pretty:
            return json.dumps(report_data, indent=2, ensure_ascii=False)
        else:
            return json.dumps(report_data, ensure_ascii=False)

class DataLoader:
    
    @staticmethod
    def load_domain_list(file_path: str) -> Set[str]:
        """Carga lista de dominios desde archivo"""
        domains = set()
        
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                for line in file:
                    domain = line.strip().lower()
                    if domain and not domain.startswith('#'):
                        domains.add(domain)
        except FileNotFoundError:
            pass
        except Exception:
            pass
        
        return domains
    
    @staticmethod
    def load_patterns_from_json(file_path: str) -> List[str]:
        """Carga patrones regex desde archivo JSON"""
        patterns = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                data = json.load(file)
                
                if isinstance(data, list):
                    patterns = data
                elif isinstance(data, dict) and "patterns" in data:
                    patterns = data["patterns"]
        except (FileNotFoundError, json.JSONDecodeError, Exception):
            pass
        
        return patterns