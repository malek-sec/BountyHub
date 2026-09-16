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

# Allow-list for the HTML that reaches the PDF template, which renders it with
# `| safe`. Markdown reports are stored text: anything that is not one of the
# tags python-markdown emits for our extension set is raw HTML that has no
# business in a scan report.
#
# This is not only an XSS control. WeasyPrint resolves URLs while rendering, so
# an <img src="file:///etc/passwd"> smuggled into a report body would pull local
# file content into the generated PDF. Restricting protocols to http/https/mailto
# closes that path.
_ALLOWED_TAGS = [
    "p", "br", "hr", "div", "span",
    "h1", "h2", "h3", "h4", "h5", "h6",
    "ul", "ol", "li", "dl", "dt", "dd",
    "blockquote", "pre", "code",
    "em", "strong", "b", "i", "u", "sub", "sup", "del",
    "a", "img",
    "table", "thead", "tbody", "tfoot", "tr", "th", "td",
]
_ALLOWED_ATTRS = {
    "a":    ["href", "title"],
    "img":  ["src", "alt", "title", "width", "height"],
    "th":   ["align", "colspan", "rowspan"],
    "td":   ["align", "colspan", "rowspan"],
    "code": ["class"],
    "pre":  ["class"],
    "span": ["class"],
    "div":  ["class"],
}
_ALLOWED_PROTOCOLS = ["http", "https", "mailto"]


def render_scan_pdf(job) -> tuple[bytes | None, str | None]:
    """
    Render a completed ScanJob into PDF bytes.

    Returns (pdf_bytes, filename), or (None, None) if WeasyPrint or bleach is
    unavailable, or if rendering fails. Never raises — callers decide how to
    handle a None.

    The report body is sanitised before it reaches the template, which renders
    it with `| safe`. See tests/test_pdf_sanitizer.py for the threat model.
    """
    try:
        from weasyprint import HTML as WeasyHTML
    except Exception:  # ImportError, or OSError from missing Pango/Cairo libs
        current_app.logger.warning(
            "WeasyPrint unavailable - scan PDF generation disabled", exc_info=True)
        return None, None

    try:
        import bleach
    except ImportError:
        # Fail closed. Rendering unsanitised HTML would be worse than not
        # producing the PDF at all, so this never degrades into a fallback.
        current_app.logger.error(
            "bleach is not installed - refusing to render an unsanitised PDF. "
            "Install it with: pip install -r requirements.txt")
        return None, None

    report_html = bleach.clean(
        _md.markdown(job.result or "", extensions=["tables", "fenced_code"]),
        tags=_ALLOWED_TAGS,
        attributes=_ALLOWED_ATTRS,
        protocols=_ALLOWED_PROTOCOLS,
        # Escape disallowed markup rather than dropping it. A scan report has to
        # be able to SHOW a payload as evidence -- stripping would silently eat
        # the <script> out of an XSS proof of concept and leave a bare alert(1).
        # Escaped markup renders as literal text and is equally inert.
        strip=False,
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
