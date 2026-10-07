from dataclasses import dataclass
from typing import Optional


@dataclass
class ScanHistoryRecord:
    id: Optional[int]
    url: str
    prediction: str
    risk_score: int
    confidence: float
    scan_time: str
    threat_level: Optional[str] = "LOW"
    detection_time_ms: Optional[float] = 0.0

    def to_dict(self):
        return {
            "id": self.id,
            "url": self.url,
            "prediction": self.prediction,
            "risk_score": self.risk_score,
            "confidence": self.confidence,
            "threat_level": self.threat_level,
            "detection_time_ms": self.detection_time_ms,
            "scan_time": self.scan_time
        }
