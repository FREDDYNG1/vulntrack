from fastapi import FastAPI
from app.vulnerabilities.router import router as vulnerabilities_router

# Instancia principal de la aplicación FastAPI
app = FastAPI(
    title="VulnTrack API",
    description="API para consultar y gestionar vulnerabilidades de software",
    version="0.1.0",
)


# Registramos el router de vulnerabilidades en la aplicación
# A partir de aquí FastAPI conoce todos los endpoints de ese router
app.include_router(vulnerabilities_router)


# Endpoint de salud para verificar que el servidor está funcionando
@app.get("/health")
def health_check():
    return {"status": "ok", "service": "vulntrack-api"}
