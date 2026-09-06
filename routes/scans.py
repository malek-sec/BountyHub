import datetime
import json
import os
import re
import tempfile
import threading
import uuid
from pathlib import Path

from flask import Blueprint, abort, current_app, jsonify, render_template, request
from flask_login import current_user, login_required

from extensions import db, limiter
from models import ActivityLog, ScanJob, Vulnerability
from services.scan_service import ScanService
from services.cve_service  import CVEService

bp = Blueprint('scans', __name__)


@bp.route('/api/start_scan', methods=['POST'])
@limiter.limit("5 per minute")
@login_required
def api_start_scan():
    """
    Start a background scan for a given target domain.

    Request body (JSON): { "target": "example.com" }

    Responses
    ---------
    202  Scan queued
    400  Missing or invalid target
    409  A scan for this target is already running
    503  Scan engine not available
    """
    from flask import request

    if not ScanService._engine_available:
        return jsonify({
            "error":  "Scan engine unavailable. Ensure core modules are present.",
            "detail": ScanService._engine_error,
        }), 503

    body   = request.get_json(silent=True) or {}
    raw    = (body.get("target") or "").strip()
    target = raw.lower()

    # Scan depth toggle: Fast (passive only, default) vs Deep (adds the Active
    # Recon & Fuzzing phase). Accept a few truthy spellings for convenience.
    # A global kill-switch in the engine Config can force this off regardless
    # of what the client requests.
    raw_flag = body.get("run_active_recon", False)
    if isinstance(raw_flag, str):
        run_active_recon = raw_flag.strip().lower() in ("1", "true", "yes", "on")
    else:
        run_active_recon = bool(raw_flag)
    engine_cfg = getattr(ScanService, "EngineConfig", None)
    if engine_cfg is not None and not getattr(engine_cfg, "ACTIVE_RECON_ENABLED", True):
        run_active_recon = False

    # AI cost mode: "free" (default) runs JS analysis + report deterministically
    # offline with ZERO API cost; "ai" spends credit for per-file Claude analysis
    # and an Opus-synthesized report. The default is env-tunable so an operator
    # can make paid AI the default, but out of the box no scan spends credit.
    default_mode = os.environ.get("BOUNTYHUB_DEFAULT_AI_MODE", "free").strip().lower()
    if default_mode not in ("free", "ai"):
        default_mode = "free"
    raw_mode = body.get("ai_mode")
    if raw_mode is None and "use_ai" in body:          # convenience boolean
        raw_mode = "ai" if body.get("use_ai") else "free"
    ai_mode = str(raw_mode).strip().lower() if raw_mode is not None else default_mode
    if ai_mode not in ("free", "ai"):
        ai_mode = default_mode

    if not target:
        return jsonify({"error": "Missing required field: 'target'"}), 400

    if not ScanService.validate_target(target):
        return jsonify({
            "error": (
                f"'{raw}' is not a valid target. "
                "Provide a bare domain name only (e.g. example.com). "
                "URLs, IP addresses, and special characters are rejected."
            )
        }), 400

    # Prevent duplicate concurrent scans for the same user + target
    with ScanService._scans_lock:
        for sid, job in ScanService._scans.items():
            if (job["target"]  == target
                    and job["user_id"] == current_user.id
                    and job["status"]  == "running"):
                return jsonify({
                    "error":    f"A scan for '{target}' is already running.",
                    "scan_id":  sid,
                    "poll_url": f"/api/scan_status/{sid}",
                }), 409

    scan_id    = uuid.uuid4().hex
    output_dir = Path(tempfile.gettempdir()) / "bountyhub_scans" / scan_id
    output_dir.mkdir(parents=True, exist_ok=True)

    with ScanService._scans_lock:
        ScanService._scans[scan_id] = {
            "scan_id":          scan_id,
            "target":           target,
            "user_id":          current_user.id,
            "username":         current_user.username,
            "status":           "running",
            "stage":            "recon",
            "stage_label":      "Passive subdomain enumeration + live host probing + screenshots",
            "started_at":       datetime.datetime.utcnow().isoformat(),
            "completed_at":     None,
            "hosts_discovered": 0,
            "hosts_scanned":    0,
            "recon_note":       None,
            "result":           None,
            "analyses":         None,
            "screenshots":      {},
            "diff":             None,
            "error":            None,
            "log":              [],
            "output_dir":       str(output_dir),
            "run_active_recon": run_active_recon,
            "scan_depth":       "deep" if run_active_recon else "fast",
            "ai_mode":          ai_mode,
        }

    try:
        new_job = ScanJob(
            scan_id=scan_id,
            user_id=current_user.id,
            target=target,
            status='queued',
            scan_depth=("deep" if run_active_recon else "fast"),
        )
        db.session.add(new_job)
        db.session.commit()
    except Exception as exc:
        current_app.logger.error(
            "Failed to create ScanJob row for %s: %s", scan_id, exc)
        db.session.rollback()

    app = current_app._get_current_object()
    thread = threading.Thread(
        target=ScanService.run_worker,
        args=(app, scan_id, target, output_dir),
        kwargs={"run_active_recon": run_active_recon, "ai_mode": ai_mode},
        daemon=True,
        name=f"bh-scan-{scan_id[:8]}",
    )
    thread.start()

    return jsonify({
        "scan_id":    scan_id,
        "target":     target,
        "status":     "running",
        "scan_depth": "deep" if run_active_recon else "fast",
        "ai_mode":    ai_mode,
        "poll_url":   f"/api/scan_status/{scan_id}",
    }), 202


@bp.route('/api/scan_status/<scan_id>', methods=['GET'])
@limiter.exempt  # High-frequency live-log poll (~1 req / 3s). It is read-only
                 # and user-scoped, so it must not be governed by the global
                 # abuse limit ("50 per hour") — otherwise an active scan trips
                 # HTTP 429 within minutes and the terminal spams poll errors.
@login_required
def api_scan_status(scan_id):
    """Poll status of a running or completed scan."""
    job = ScanService.get(scan_id)

    if not job:
        db_job = ScanJob.query.filter_by(
            scan_id=scan_id, user_id=current_user.id).first()
        if db_job:
            return jsonify({
                'scan_id':       db_job.scan_id,
                'target':        db_job.target,
                'status':        db_job.status,
                'scan_depth':    db_job.scan_depth or 'fast',
                'stage':         db_job.stage,
                'stage_label':   db_job.stage_label,
                'hosts_found':   db_job.hosts_found,
                'hosts_scanned': db_job.hosts_scanned,
                'result':        db_job.result,
                'analyses':      json.loads(db_job.analyses or 'null'),
                'diff':          json.loads(db_job.diff or 'null'),
                'log':           json.loads(db_job.log or '[]'),
                'error':         db_job.error,
                'created_at':    db_job.created_at.isoformat() if db_job.created_at else None,
                'completed_at':  db_job.completed_at.isoformat() if db_job.completed_at else None,
                'source':        'db',
            }), 200
        return jsonify({"error": "Scan not found"}), 404

    if job["user_id"] != current_user.id:
        return jsonify({"error": "Forbidden"}), 403

    _INTERNAL = {"user_id", "output_dir"}
    response  = {k: v for k, v in job.items() if k not in _INTERNAL}
    response["log"] = list(response.get("log", []))
    return jsonify(response), 200


@bp.route('/api/scan/<scan_id>/cancel', methods=['POST'])
@login_required
def api_cancel_scan(scan_id):
    """
    Cancel a running/queued scan.

    Ownership is verified against the in-memory record first, then the DB.
    A live worker (same process) stops at its next stage boundary; an orphaned
    DB-only job is simply marked 'cancelled'. Terminal scans are left as-is.
    """
    _TERMINAL = {"completed", "failed", "cancelled"}

    job = ScanService.get(scan_id)
    if job is not None:
        if job.get("user_id") != current_user.id:
            return jsonify({"error": "Forbidden"}), 403
        if job.get("status") in _TERMINAL:
            return jsonify({"status": job.get("status"),
                            "message": "Scan already finished — nothing to cancel."}), 200
    else:
        db_job = ScanJob.query.filter_by(
            scan_id=scan_id, user_id=current_user.id).first()
        if not db_job:
            return jsonify({"error": "Scan not found"}), 404
        if db_job.status in _TERMINAL:
            return jsonify({"status": db_job.status,
                            "message": "Scan already finished — nothing to cancel."}), 200

    ScanService.request_cancel(scan_id)
    return jsonify({"scan_id": scan_id, "status": "cancelled",
                    "message": "Scan cancelled."}), 200


@bp.route('/api/scan_result/<scan_id>', methods=['GET'])
@login_required
def api_scan_result(scan_id):
    """Return the full result + analyses for a completed scan."""
    job = ScanService.get(scan_id)

    if job:
        if job["user_id"] != current_user.id:
            return jsonify({"error": "Forbidden"}), 403
        if job["status"] != "completed":
            return jsonify({"error": "Scan not completed yet",
                            "status": job["status"]}), 409
        return jsonify({
            "scan_id":  scan_id,
            "result":   job.get("result"),
            "analyses": job.get("analyses"),
            "diff":     job.get("diff"),
            "source":   "memory",
        }), 200

    db_job = ScanJob.query.filter_by(
        scan_id=scan_id, user_id=current_user.id).first()
    if not db_job:
        return jsonify({"error": "Scan not found"}), 404
    if db_job.status != "completed":
        return jsonify({"error": "Scan not completed yet",
                        "status": db_job.status}), 409
    return jsonify({
        "scan_id":  db_job.scan_id,
        "result":   db_job.result,
        "analyses": json.loads(db_job.analyses or 'null'),
        "diff":     json.loads(db_job.diff or 'null'),
        "source":   "db",
    }), 200


@bp.route('/api/scans', methods=['GET'])
@login_required
def api_list_scans():
    """
    Return a summary list of all scans for the current user.

    Memory-first, then DB — the same shape as api_scan_status,
    api_scan_result and api_latest_scan. ScanService._scans is an in-process
    cache that empties on every restart, so a memory-only listing silently
    reports "no scans" while the database still holds them.

    In-memory records win on scan_id collision: a scan running in THIS process
    is fresher than its last-synced DB row.
    """
    _OMIT = {"result", "analyses", "log", "screenshots", "diff",
             "output_dir", "user_id"}

    with ScanService._scans_lock:
        user_scans = [
            {k: v for k, v in job.items() if k not in _OMIT}
            for job in ScanService._scans.values()
            if job["user_id"] == current_user.id
        ]

    seen = {j.get("scan_id") for j in user_scans}
    for db_job in (ScanJob.query
                   .filter_by(user_id=current_user.id)
                   .order_by(ScanJob.created_at.desc(), ScanJob.id.desc())
                   .all()):
        if db_job.scan_id in seen:
            continue
        user_scans.append({
            "scan_id":          db_job.scan_id,
            "target":           db_job.target,
            "status":           db_job.status,
            "scan_depth":       db_job.scan_depth or "fast",
            "stage":            db_job.stage,
            "stage_label":      db_job.stage_label,
            "hosts_discovered": db_job.hosts_found,
            "hosts_scanned":    db_job.hosts_scanned,
            "error":            db_job.error,
            "started_at":       (db_job.created_at.isoformat()
                                 if db_job.created_at else None),
            "completed_at":     (db_job.completed_at.isoformat()
                                 if db_job.completed_at else None),
            "source":           "db",
        })

    user_scans.sort(key=lambda j: j.get("started_at") or "", reverse=True)
    return jsonify({"scans": user_scans, "total": len(user_scans)}), 200


@bp.route('/api/scan/latest', methods=['GET'])
@login_required
def api_latest_scan():
    """
    Return the most recent scan record for the current user.

    ScanService._scans is an in-process cache that is empty after every server
    restart, so a memory-only lookup reports "no scans" even when completed
    scans exist in the database. Fall back to ScanJob exactly like
    api_scan_status and api_scan_result already do — otherwise the dashboard
    never restores the last report and the Export PDF button stays hidden.
    """
    _INTERNAL = {"user_id", "output_dir"}

    with ScanService._scans_lock:
        user_jobs = [
            job for job in ScanService._scans.values()
            if job["user_id"] == current_user.id
        ]

    if user_jobs:
        latest   = max(user_jobs, key=lambda j: j.get("started_at", ""))
        response = {k: v for k, v in latest.items() if k not in _INTERNAL}
        response["log"]    = list(response.get("log", []))
        response["found"]  = True
        response["source"] = "memory"
        return jsonify(response), 200

    db_job = (ScanJob.query
              .filter_by(user_id=current_user.id)
              .order_by(ScanJob.created_at.desc(), ScanJob.id.desc())
              .first())
    if not db_job:
        return jsonify({"found": False}), 200

    return jsonify({
        'found':         True,
        'scan_id':       db_job.scan_id,
        'target':        db_job.target,
        'status':        db_job.status,
        'scan_depth':    db_job.scan_depth or 'fast',
        'stage':         db_job.stage,
        'stage_label':   db_job.stage_label,
        'hosts_found':   db_job.hosts_found,
        'hosts_scanned': db_job.hosts_scanned,
        'result':        db_job.result,
        'analyses':      json.loads(db_job.analyses or 'null'),
        'diff':          json.loads(db_job.diff or 'null'),
        'log':           json.loads(db_job.log or '[]'),
        'error':         db_job.error,
        'created_at':    db_job.created_at.isoformat() if db_job.created_at else None,
        'completed_at':  db_job.completed_at.isoformat() if db_job.completed_at else None,
        # Screenshots live only in the in-process cache (they are copied to
        # static/screenshots/<scan_id>/ at scan time); a restored DB record
        # simply has none. restoreCompletedScan() handles the empty case.
        'screenshots':   {},
        'source':        'db',
    }), 200


@bp.route('/api/scan/<scan_id>/cves', methods=['GET'])
@login_required
def api_scan_cves(scan_id):
    """Query NIST NVD for CVEs matching technologies detected in a completed scan."""
    from flask import request as _req

    db_job = ScanJob.query.filter_by(scan_id=scan_id).first()
    if not db_job:
        return jsonify({"error": "Scan not found"}), 404
    if db_job.user_id != current_user.id:
        return jsonify({"error": "Forbidden"}), 403
    if db_job.status != 'completed':
        return jsonify({"error": "Scan not complete yet"}), 425

    # output_dir lives only in the in-memory store — not persisted to DB.
    mem_job = ScanService.get(scan_id)
    if not mem_job:
        return jsonify({
            "error": (
                "Scan output not available after server restart. "
                "Re-run the scan to use CVE lookup."
            )
        }), 503

    fp_file = Path(mem_job["output_dir"]) / "fingerprint.json"
    if not fp_file.exists():
        return jsonify({"error": "Fingerprint data not found"}), 404

    try:
        fp_data = json.loads(fp_file.read_text())
    except Exception:
        return jsonify({"error": "Fingerprint data could not be parsed"}), 500

    technologies = CVEService.extract_technologies(fp_data)
    if not technologies:
        return jsonify({"technologies": [], "cves": {}, "cache_hits": 0}), 200

    from models.cve_cache import CVECache
    cache_hits = sum(
        1 for t in technologies
        if CVECache.get(t.strip().lower()) is not None
    )

    cve_data = CVEService.batch_search(technologies, max_per_tech=5)

    return jsonify({
        "technologies": technologies,
        "cache_hits":   cache_hits,
        "total":        len(technologies),
        "cves": {
            tech: [vars(c) for c in results]
            for tech, results in cve_data.items()
        },
    }), 200


@bp.route('/scans/<scan_id>/export-pdf')
@login_required
def export_scan_pdf(scan_id):
    """Generate and download a PDF of the AI report for a completed scan."""
    from services.pdf_service import render_scan_pdf

    job = ScanJob.query.filter_by(
        scan_id=scan_id, user_id=current_user.id).first()
    if not job:
        abort(404)
    if job.status != 'completed':
        abort(409)

    pdf, filename = render_scan_pdf(job)
    if pdf is None:
        abort(503)

    from flask import make_response
    resp = make_response(pdf)
    resp.headers['Content-Type']        = 'application/pdf'
    resp.headers['Content-Disposition'] = (
        f'attachment; filename="{filename}"')
    return resp


@bp.route('/api/bulk_delete', methods=['POST'])
@login_required
def bulk_delete():
    data = request.get_json(silent=True) or {}
    ids  = data.get('ids', [])
    kind = data.get('type', '')

    if not ids or kind not in ('vulnerability', 'scan'):
        return jsonify({'success': False, 'error': 'Invalid request'}), 400

    deleted = 0

    if kind == 'vulnerability':
        for vid in ids:
            try:
                bug = Vulnerability.query.filter_by(
                    id=int(vid), user_id=current_user.id).first()
                if bug:
                    ActivityLog.query.filter_by(vulnerability_id=bug.id).delete()
                    db.session.delete(bug)
                    deleted += 1
            except (ValueError, TypeError):
                continue

    elif kind == 'scan':
        for scan_id in ids:
            job = ScanJob.query.filter_by(
                scan_id=str(scan_id), user_id=current_user.id).first()
            if job:
                db.session.delete(job)
                deleted += 1

    db.session.commit()
    return jsonify({'success': True, 'deleted': deleted})


@bp.route('/scans/history')
@login_required
def scan_history():
    jobs = (ScanJob.query
            .filter_by(user_id=current_user.id)
            .order_by(ScanJob.created_at.desc())
            .limit(50).all())
    return render_template('scan_history.html', jobs=jobs)
