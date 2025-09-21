"""
Email Verifier API - Aplicación principal compacta
"""

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
import uvicorn
import logging
import sys
import time
from pathlib import Path
from datetime import datetime
import os

# Configurar path e imports
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.insert(0, parent_dir)

# Logging básico
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Crear aplicación FastAPI
app = FastAPI(
    title="Email Verifier API",
    version="1.0.0",
    description="API para validación de emails",
    docs_url="/docs"
)

# CORS para Streamlit
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Incluir rutas
try:
    from api.routes import router
    app.include_router(router, prefix="/api/v1")
    logger.info("Rutas cargadas correctamente")
except ImportError as e:
    logger.error(f"Error cargando rutas: {e}")

# Endpoint raíz simple
@app.get("/")
async def root():
    return {
        "service": "Email Verifier API",
        "version": "1.0.0",
        "docs": "/docs",
        "health": "/api/v1/health"
    }

# Manejador de errores básico
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(
        status_code=422,
        content={
            "error": "Validation Error",
            "message": "Datos inválidos",
            "details": exc.errors()
        }
    )

# Middleware de logging
@app.middleware("http")
async def log_requests(request: Request, call_next):
    start_time = time.time()
    response = await call_next(request)
    process_time = time.time() - start_time
    logger.info(f"{request.method} {request.url} - {response.status_code} - {process_time:.3f}s")
    return response

# Eventos de inicio
@app.on_event("startup")
async def startup_event():
    logger.info("Email Verifier API iniciada")
    Path("logs").mkdir(exist_ok=True)

def main():
    uvicorn.run("api.main:app", host="0.0.0.0", port=8000, reload=True)

if __name__ == "__main__":
    main()