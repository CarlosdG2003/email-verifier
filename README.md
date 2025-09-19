#  Email Verifier Project

##  Descripción
Sistema completo de verificación de emails con 23+ validaciones diferentes.

##  Instalación
```bash
pip install -r requirements.txt
```

##  Uso Básico
```python
from src.email_verifier import EmailVerifier

verifier = EmailVerifier()
result = verifier.verify_email("test@example.com", level="basic")
print(result)
```

##  Documentación
- [API Reference](docs/API_REFERENCE.md)
- [Validaciones](docs/VALIDATIONS.md)
- [Configuración](docs/CONFIGURATION.md)

##  Tests
```bash
python -m pytest tests/
```

##  Licencia
MIT License
