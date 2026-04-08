from collections import defaultdict
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.schemas import SyntheticRequest, InferResponse
from app.db.deps import get_db
from app.db.models import KPIProfileModel, RAREventModel
from app.services.traffic import generate_synthetic_events
from app.services.detector import SSDDetector, bucket_index
from app.services.storage import save_events, save_alarms, save_policies
from app.services.config_service import get_config

router = APIRouter(prefix="/infer", tags=["infer"])

@router.post("/ingested", response_model=InferResponse)
def infer_ingested(
    cell_id: str = "cell_1",
    window_sec: int = 60,
    lookback_minutes: int = 10,
    db: Session = Depends(get_db),
):
    # TEMPORARY / PROTOTYPE-SAFE VERSION:
    # take the most recent ingested rows instead of filtering by UTC cutoff
    q = db.execute(
        select(RAREventModel)
        .where(RAREventModel.cell_id == cell_id)
        .order_by(RAREventModel.ts.desc())
        .limit(200)
    )
    rows = list(reversed(q.scalars().all()))

    if not rows:
        return InferResponse(windows_processed=0, alarms=0, policies=0)

    cfg = get_config(db)
    detector = SSDDetector(
        threshold=cfg["threshold"],
        sigma_floor=cfg["sigma_floor"],
        persistence_windows=cfg["persistence_windows"],
        block_duration_sec=cfg["block_duration_sec"],
        neighbor_ta_span=cfg["neighbor_ta_span"],
        action_ladder=cfg["action_ladder"],
    )

    grouped = defaultdict(list)
    for e in rows:
        epoch = int(e.ts.timestamp())
        window_start = epoch - (epoch % window_sec)
        grouped[window_start].append(e)

    total_alarms = 0
    total_policies = 0

    for _, w_events in grouped.items():
        counts = defaultdict(int)

        # Count only storm-relevant events
        for e in w_events:
            if e.event_type in {
                "initial_registration",
                "rrc_setup_request",
                "registration_failed",
                "registration_rejected",
            }:
                counts[e.ta] += 1

        if not counts:
            continue

        bucket = bucket_index(w_events[0].ts, window_sec)
        q = db.execute(
            select(KPIProfileModel).where(
                KPIProfileModel.cell_id == cell_id,
                KPIProfileModel.time_bucket == bucket
            )
        )
        profiles = q.scalars().all()
        profiles_map = {(p.ta, p.time_bucket): {"mu": p.mu, "sigma": p.sigma} for p in profiles}

        alarms, policies = detector.detect(cell_id, w_events[0].ts, dict(counts), profiles_map, window_sec)

        if alarms:
            save_alarms(db, alarms)
            total_alarms += len(alarms)

        if policies:
            save_policies(db, policies)
            total_policies += len(policies)

    return InferResponse(
        windows_processed=len(grouped),
        alarms=total_alarms,
        policies=total_policies,
    )