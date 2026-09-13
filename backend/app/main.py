from fastapi import FastAPI


app = FastAPI(
    title="VulnTrack API",
    description="API para consultar y gestionar vulnerabilidades de software",
    version="0.1.0",
)


@app.get("/health")
def health_check():
    return {"status": "ok", "service": "vulntrack-api"}
