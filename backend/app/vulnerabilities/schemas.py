from pydantic import BaseModel
from typing import Optional


class CVSSData(BaseModel):
      score: float
      severity:str

class VulnerabilityResponse(BaseModel):
      cve_id: str
      description: str
      published: str
      last_modified: str
      cvss: Optional[CVSSData] = None
      references: list[str]

