"""
PDF rendering for scan reports.

Single source of truth for turning a completed ScanJob's AI report into a PDF,
shared by the download route (routes/scans.py) and the background worker
(services/scan_service.py) that attaches the PDF to the Telegram notification.
Must be called inside a Flask app context (uses render_template + config).
"""

import datetime as _dt
import re

import markdown as _md
from flask import current_app, render_template


def render_scan_pdf(job) -> tuple[bytes | None, str | None]:
    """
    Render a completed ScanJob into PDF bytes.

    Returns (pdf_bytes, filename), or (None, None) if WeasyPrint is unavailable
    or rendering fails. Never raises — callers decide how to handle a None.
    """
    try:
        from weasyprint import HTML as WeasyHTML
    except Exception:  # ImportError, or OSError from missing Pango/Cairo libs
        current_app.logger.warning(
            "WeasyPrint unavailable - scan PDF generation disabled", exc_info=True)
        return None, None

    report_html = _md.markdown(
        job.result or "",
        extensions=["tables", "fenced_code"],
    )
    html_str = render_template(
        "scan_pdf_report.html",
        job=job,
        report_html=report_html,
        now=_dt.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
    )

    try:
        pdf = WeasyHTML(string=html_str).write_pdf()
    except Exception:
        current_app.logger.error(
            "WeasyPrint render failed for scan %s", getattr(job, "scan_id", "?"),
            exc_info=True)
        return None, None

    # Filename = site + scan date, so repeat scans never collide.
    safe_target = re.sub(r"[^A-Za-z0-9]+", "_", job.target).strip("_")[:40] or "scan"
    stamp = (job.completed_at or job.created_at
             or _dt.datetime.utcnow()).strftime("%Y-%m-%d_%H%M")
    return pdf, f"Scan_{safe_target}_{stamp}.pdf"
