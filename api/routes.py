from fastapi import APIRouter, HTTPException, BackgroundTasks, Depends
from pydantic import BaseModel, EmailStr, validator
from typing import List, Dict, Any
import asyncio, uuid, time, logging
from datetime import datetime

logger = logging.getLogger(__name__)
router = APIRouter()

# Cargar EmailVerifier
try:
    from src.email_verifier import EmailVerifier
    email_verifier = EmailVerifier()
    logger.info("EmailVerifier cargado")
except Exception as e:
    logger.error(f"Error cargando EmailVerifier: {e}")
    email_verifier = None

# Storage temporal
tasks_storage: Dict[str, Any] = {}
api_stats = {"total_validations": 0, "start_time": time.time(), "errors": 0}

# Modelos
class EmailValidationRequest(BaseModel):
    email: EmailStr
    level: str = "basic"

    @validator("level")
    def validate_level(cls, v):
        if v not in ["basic", "standard", "professional"]:
            raise ValueError("Level debe ser: basic, standard, professional")
        return v

class BulkEmailValidationRequest(BaseModel):
    emails: List[EmailStr]
    level: str = "basic"

    @validator("emails")
    def validate_emails_count(cls, v):
        if not 1 <= len(v) <= 100:
            raise ValueError("Entre 1 y 100 emails permitidos")
        return v

# Dependencia para verificar EmailVerifier
def verify_email_verifier():
    if not email_verifier:
        raise HTTPException(status_code=503, detail="EmailVerifier no disponible")
    return email_verifier


# Endpoints
@router.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "service": "Email Verifier API",
        "email_verifier": "available" if email_verifier else "unavailable"
    }

@router.post("/validate")
async def validate_single_email(request: EmailValidationRequest, verifier: EmailVerifier = Depends(verify_email_verifier)):
    try:
        logger.info(f"Validando: {request.email}")
        result = await asyncio.to_thread(verifier.verify_email, request.email, request.level)
        api_stats["total_validations"] += 1
        return result
    except Exception as e:
        logger.error(f"Error validando {request.email}: {e}")
        api_stats["errors"] += 1
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/validate/bulk")
async def validate_bulk_emails(request: BulkEmailValidationRequest, background_tasks: BackgroundTasks, verifier: EmailVerifier = Depends(verify_email_verifier)):
    task_id = str(uuid.uuid4())
    tasks_storage[task_id] = {
        "task_id": task_id,
        "status": "pending",
        "progress": 0,
        "total_emails": len(request.emails),
        "processed_emails": 0,
        "created_at": datetime.utcnow().isoformat()
    }
    background_tasks.add_task(process_bulk_validation, task_id, request.emails, request.level, verifier)
    return {
        "task_id": task_id,
        "status": "accepted",
        "total_emails": len(request.emails),
        "check_status_url": f"/api/v1/validate/bulk/{task_id}/status"
    }

@router.get("/validate/bulk/{task_id}/status")
async def get_bulk_status(task_id: str):
    task = tasks_storage.get(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task ID no encontrado")
    return task

@router.get("/validate/bulk/{task_id}/results")
async def get_bulk_results(task_id: str):
    task = tasks_storage.get(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task ID no encontrado")
    if task.get("status") != "completed":
        raise HTTPException(status_code=202, detail=f"Estado: {task.get('status')}")
    results_key = f"{task_id}_results"
    results = tasks_storage.get(results_key)
    if not results:
        raise HTTPException(status_code=404, detail="Resultados no encontrados")
    return results

@router.get("/stats")
async def get_stats():
    uptime = time.time() - api_stats["start_time"]
    active_tasks = len([t for t in tasks_storage.values() if t.get("status") == "processing"])
    return {
        "total_validations": api_stats["total_validations"],
        "errors": api_stats["errors"],
        "uptime_seconds": round(uptime, 2),
        "active_bulk_tasks": active_tasks,
        "service": "Email Verifier API"
    }


# Background processing
async def process_bulk_validation(task_id: str, emails: List[str], level: str, verifier: EmailVerifier):
    task = tasks_storage.get(task_id)
    if not task:
        return
    task["status"] = "processing"
    results = []
    try:
        for i, email in enumerate(emails):
            try:
                result = await asyncio.to_thread(verifier.verify_email, email, level)
                results.append(result)
                task["processed_emails"] = i + 1
                task["progress"] = int((i + 1) / len(emails) * 100)
            except Exception as e:
                logger.error(f"Error validando {email}: {e}")
                continue

        # Resumen
        summary = {
            "total_emails": len(emails),
            "valid_emails": sum(1 for r in results if r.get("overall_status") == "valid"),
            "invalid_emails": sum(1 for r in results if r.get("overall_status") == "invalid"),
            "risky_emails": sum(1 for r in results if r.get("overall_status") == "risky"),
            "average_confidence": round(sum(r.get("confidence",0) for r in results)/len(results),2) if results else 0
        }

        # Guardar resultados
        tasks_storage[f"{task_id}_results"] = {
            "task_id": task_id,
            "results": results,
            "summary": summary,
            "timestamp": datetime.utcnow().isoformat()
        }
        task["status"] = "completed"
        task["completed_at"] = datetime.utcnow().isoformat()
    except Exception as e:
        logger.error(f"Error en task {task_id}: {e}")
        task["status"] = "failed"
