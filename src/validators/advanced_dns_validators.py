"""Validaciones DNS avanzadas 11-12: Consistencia MX y Registro de Dominio"""
import dns.resolver,time,logging,whois
from typing import Dict,Any,List
from src.models.validation_result import ValidationResult
logger=logging.getLogger(__name__)

class AdvancedDNSValidators:
    def __init__(self,timeout:int=10):
        # Inicializa validador DNS avanzado
        self.timeout=timeout
        self.resolver=dns.resolver.Resolver()
        self.resolver.timeout=timeout;self.resolver.lifetime=timeout+2
        self.resolver.nameservers=['8.8.8.8','1.1.1.1']
        logger.info(f"AdvancedDNSValidators inicializado con timeout: {timeout}s")

    def check_mx_domain_consistency(self,email:str)->ValidationResult:
        # 11. Verifica consistencia MX con el dominio
        start=time.time();domain=email.split("@")[-1].lower()if"@"in email else""
        if not domain:return ValidationResult(False,0,{"error":"No se pudo extraer dominio"},(time.time()-start)*1000,"Email sin dominio válido")
        mx_records,mx_hosts,analysis,error=[],[],{},None;score=100
        try:
            mx_records=[str(r)for r in self.resolver.resolve(domain,'MX')]
            for r in mx_records:
                parts=r.split(' ',1)
                if len(parts)==2:mx_hosts.append(parts[1].rstrip('.'))
            if not mx_hosts:return ValidationResult(False,0,{"error":"Sin registros MX válidos"},(time.time()-start)*1000,"Sin MX records")
            analysis=self._analyze_mx_consistency(domain,mx_hosts);score=analysis["consistency_score"]
        except dns.resolver.NXDOMAIN:error="Dominio inexistente";score=0
        except dns.resolver.NoAnswer:error="Sin registros MX";score=0
        except Exception as e:error=f"Error MX consistency: {e}";score=0
        details={"domain":domain,"mx_records":mx_records,"mx_hosts":mx_hosts,"consistency_analysis":analysis,
                 "uses_external_mx":analysis.get("uses_external_service",False),"external_service":analysis.get("external_service")}
        return ValidationResult(score>0,score,details,(time.time()-start)*1000,error)

    def _analyze_mx_consistency(self,domain:str,mx_hosts:List[str])->Dict[str,Any]:
        # Analiza la consistencia entre dominio y sus MX
        analysis={"consistency_score":100,"uses_external_service":False,"external_service":None,"consistency_issues":[]}
        services={'google':['gmail.com','google.com'],'microsoft':['outlook.com','protection.outlook.com'],
                  'zoho':['zoho.com'],'amazon':['amazonses.com']}
        root='.'.join(domain.split('.')[-2:])if'.'in domain else domain
        for mx in mx_hosts:
            mxl=mx.lower()
            if domain in mxl or root in mxl:continue
            ext=False
            for s,pat in services.items():
                if any(p in mxl for p in pat):analysis.update(uses_external_service=True,external_service=s);ext=True;break
            if not ext:analysis["consistency_issues"].append(f"MX desconocido: {mx}")
        if analysis["uses_external_service"]:analysis["consistency_score"]=85
        elif analysis["consistency_issues"]:
            penalty=min(50,len(analysis["consistency_issues"])*20)
            analysis["consistency_score"]=max(30,100-penalty)
        return analysis

    def check_domain_registration(self,email:str)->ValidationResult:
        # 12. Verifica si el dominio está registrado (WHOIS)
        start=time.time();domain=email.split("@")[-1].lower()if"@"in email else""
        if not domain:return ValidationResult(False,0,{"error":"No se pudo extraer dominio"},(time.time()-start)*1000,"Email sin dominio válido")
        is_reg=False;info={};score=0;err=None
        try:
            w=whois.whois(domain)
            if w:is_reg=True;info={"domain_name":getattr(w,'domain_name',None),"creation_date":str(getattr(w,'creation_date','Unknown')),
                                   "expiration_date":str(getattr(w,'expiration_date','Unknown')),"registrar":getattr(w,'registrar','Unknown'),
                                   "name_servers":getattr(w,'name_servers',[]),"status":getattr(w,'status',[])};score=self._calculate_registration_score(w,domain)
            else:err="Sin información WHOIS disponible";score=20
        except Exception as e:
            err=f"Error WHOIS: {e}"
            try:self.resolver.resolve(domain,'A');is_reg=True;score=60;info={"fallback":"Verificado via DNS"}
            except:is_reg=False;score=0;err="Dominio no registrado o inaccesible"
        details={"domain":domain,"is_registered":is_reg,"registration_info":info,"whois_available":bool(info and not info.get("fallback"))}
        return ValidationResult(is_reg,score,details,(time.time()-start)*1000,err)

    def _calculate_registration_score(self,w,domain:str)->int:
        # Calcula score basado en información WHOIS
        score=100
        try:
            c=getattr(w,'creation_date',None)
            if c and not isinstance(c,list):c=[c]
            if c:
                f=c[0]
                if hasattr(f,'year'):
                    import datetime
                    days=(datetime.datetime.now()-f).days
                    if days<30:score-=30
                    elif days<90:score-=15
            s=getattr(w,'status',[])
            if isinstance(s,list)and s:
                if any(x.upper()in str(s).upper()for x in['HOLD','LOCK','SUSPEND']):score-=40
        except Exception as e:logger.warning(f"Error calculando registration score: {e}");score=70
        return max(0,min(100,score))

    def check_all_advanced_dns(self,email:str)->Dict[str,ValidationResult]:
        # Ejecuta todas las validaciones avanzadas
        return{"mx_domain_consistency":self.check_mx_domain_consistency(email),
               "domain_registration":self.check_domain_registration(email)}
