from fastapi import APIRouter, Depends, Response
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from sqlalchemy.orm import Session

from app.db import get_db
from app.metrics import REGISTRY, collect_domain_metrics
from app.models.admin import Admin
from app.utils import responses

router = APIRouter(tags=["Metrics"], prefix="/api", responses={401: responses._401})


@router.get("/metrics", include_in_schema=True)
def get_metrics(
    db: Session = Depends(get_db),
    admin: Admin = Depends(Admin.get_current),
):
    """
    Prometheus exposition endpoint.

    Requires a valid admin access token, same as every other /api route.
    """
    collect_domain_metrics(db)

    return Response(
        content=generate_latest(REGISTRY),
        media_type=CONTENT_TYPE_LATEST,
    )