"""Defensive telemetry and alert ingestion endpoints."""

from fastapi import APIRouter, Depends, status

from purple_range.api.deps import get_repository
from purple_range.api.schemas import AlertIngestRequest
from purple_range.db.repository import PurpleRangeRepository
from purple_range.detection.normalizer import AlertNormalizer
from purple_range.models.detection import DetectionAlert

router = APIRouter(prefix="/telemetry", tags=["Telemetry"])


@router.post("/alerts", response_model=DetectionAlert, status_code=status.HTTP_201_CREATED)
def ingest_alert(
    payload: AlertIngestRequest,
    repo: PurpleRangeRepository = Depends(get_repository),
) -> DetectionAlert:
    """Ingest and normalize a defensive sensor alert into the purple-team correlation buffer."""
    raw_dict = {
        "sensor_name": payload.sensor_name,
        "host": payload.host,
        "alert_signature": payload.alert_signature,
        "technique_id": payload.technique_id,
        "severity": payload.severity.value,
        "command_line": payload.command_line,
        "process_name": payload.process_name,
        "process_pid": payload.process_pid,
        **payload.raw_log,
    }
    alert = AlertNormalizer.normalize_raw_log(raw_dict, sensor_name=payload.sensor_name)
    repo.save_alert(alert)
    return alert


@router.get("/alerts", response_model=list[DetectionAlert])
def list_alerts(
    limit: int = 100,
    repo: PurpleRangeRepository = Depends(get_repository),
) -> list[DetectionAlert]:
    """Query ingested defensive alerts available for correlation."""
    return repo.list_alerts(limit=limit)
