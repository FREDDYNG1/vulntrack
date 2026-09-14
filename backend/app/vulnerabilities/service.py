import httpx
from app.vulnerabilities.schemas import CVSSData, VulnerabilityResponse

# URL base de la API pública de NVD
NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def get_vulnerability_by_id(cve_id: str) -> VulnerabilityResponse:
    # Construimos la URL completa con el CVE ID como parámetro
    url = f"{NVD_BASE_URL}?cveId={cve_id}"

    # httpx.Client() maneja la conexión HTTP
    # 'with' garantiza que la conexión se cierra aunque ocurra un error
    with httpx.Client() as client:
        response = client.get(url, timeout=10.0)
        # Si NVD devuelve un error HTTP (4xx, 5xx), lanza una excepción
        response.raise_for_status()
        # Convertimos la respuesta JSON a un diccionario Python
        data = response.json()

    # NVD devuelve una lista de vulnerabilidades, extraemos esa lista
    vulnerabilities = data.get("vulnerabilities", [])

    # Si la lista está vacía, el CVE no existe
    if not vulnerabilities:
        return None

    # Tomamos el primer (y único) resultado
    cve = vulnerabilities[0]["cve"]

    # NVD incluye descripciones en varios idiomas
    # Buscamos la descripción en inglés con next()
    # Si no hay ninguna, usamos un texto por defecto
    description = next(
        (d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"),
        "No description available",
    )

    # CVSS puede no estar disponible en todas las vulnerabilidades
    cvss = None
    metrics = cve.get("metrics", {})

    # Intentamos obtener métricas CVSS versión 3.1
    if "cvssMetricV31" in metrics:
        cvss_data = metrics["cvssMetricV31"][0]["cvssData"]
        cvss = CVSSData(
            score=cvss_data["baseScore"],
            severity=cvss_data["baseSeverity"],
        )

    # Extraemos solo las URLs de las referencias
    references = [ref["url"] for ref in cve.get("references", [])]

    # Construimos y devolvemos nuestro schema propio
    # Angular recibirá exactamente esta estructura, nunca el JSON crudo de NVD
    return VulnerabilityResponse(
        cve_id=cve["id"],
        description=description,
        published=cve["published"],
        last_modified=cve["lastModified"],
        cvss=cvss,
        references=references,
    )
