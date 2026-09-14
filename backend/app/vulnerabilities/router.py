from fastapi import APIRouter, HTTPException
from app.vulnerabilities.schemas import VulnerabilityResponse
from app.vulnerabilities.service import get_vulnerability_by_id

# APIRouter agrupa endpoints relacionados
# prefix: todas las rutas de este router empiezan con /vulnerabilities
# tags: agrupa los endpoints en la documentación Swagger
router = APIRouter(
    prefix="/vulnerabilities",
    tags=["vulnerabilities"],
)


@router.get("/{cve_id}", response_model=VulnerabilityResponse)
def get_vulnerability(cve_id: str):
    # Delegamos toda la lógica al service
    # El router no sabe cómo funciona NVD
    vulnerability = get_vulnerability_by_id(cve_id)

    # Si el service devolvió None, el CVE no existe
    # HTTPException convierte esto en una respuesta 404
    if vulnerability is None:
        raise HTTPException(
            status_code=404,
            detail=f"CVE {cve_id} not found",
        )

    return vulnerability
