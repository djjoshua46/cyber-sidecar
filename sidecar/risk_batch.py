"""
Batch risk analyzer for exports.

Run from the project root:

    python -m sidecar.risk_batch

This will:
  - Load all Exports.
  - Skip exports that already have a RiskFinding.
  - Compute a risk score (using risk_engine).
  - Insert RiskFindings for anything suspicious.
"""

from __future__ import annotations

from sqlalchemy import select

from .db import SessionLocal
from .models import Export, RiskFinding
from .risk_engine import compute_risk_for_export


def run_batch() -> None:
    """
    Run risk analysis for all Exports that don't yet have a RiskFinding.
    """
    db = SessionLocal()
    try:
        exports = db.execute(select(Export)).scalars().all()

        created_count = 0

        for exp in exports:
            # Skip if we already have a RiskFinding for this ExportId
            existing = db.execute(
                select(RiskFinding).where(RiskFinding.export_id == exp.export_id)
            ).scalar_one_or_none()

            if existing is not None:
                continue

            finding = compute_risk_for_export(exp)
            if finding is not None:
                db.add(finding)
                created_count += 1

        if created_count > 0:
            db.commit()
        else:
            db.rollback()

        print(f"Risk batch complete. New findings created: {created_count}")

    finally:
        db.close()


if __name__ == "__main__":
    run_batch()
