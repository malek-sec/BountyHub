import datetime
import json
import os
import re
import shutil
import sys
import tempfile
import threading
import uuid
from pathlib import Path

from flask import current_app


# Strict domain regex — only well-formed hostnames are accepted.
_DOMAIN_RE = re.compile(
    r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$'
)

# Extension allow-list for screenshot copies.
_ALLOWED_SCREENSHOT_EXT = {".png", ".jpg", ".jpeg", ".webp"}


class ScanService:
    # In-memory store — class-level, thread-safe fast path cache.
    _scans:      dict           = {}
    _scans_lock: threading.Lock = threading.Lock()

    # Set of scan_ids the user asked to cancel. The running worker checks this
    # at every stage boundary and aborts cooperatively. Guarded by _scans_lock.
    _cancel_requested: set = set()

    # ── Scan engine availability (resolved once at startup) ───────────────────
    _engine_available: bool = False
    _engine_error:     str | None = None

    @classmethod
    def init_engine(cls, v2_root: str) -> None:
        """Wire the scan-engine package onto sys.path and import core modules."""
        if v2_root not in sys.path:
            sys.path.insert(0, v2_root)
        try:
            global ReconModule, FingerprintModule, AIAdvisorModule, EngineConfig
            global ActiveReconModule
            from core.recon        import ReconModule
            from core.fingerprint  import FingerprintModule
            from core.active_recon import ActiveReconModule
            from core.ai_advisor   import AIAdvisorModule
            from core              import Config as EngineConfig
            # Expose the engine Config on the class so routes can read the
            # active-recon kill-switch / defaults without re-importing core.
            cls.EngineConfig      = EngineConfig
            cls._engine_available = True
            cls._engine_error     = None
        except Exception as exc:
            cls._engine_available = False
            cls._engine_error     = str(exc)

    # ── In-memory helpers ─────────────────────────────────────────────────────

    @classmethod
    def get(cls, scan_id: str) -> dict | None:
        with cls._scans_lock:
            return cls._scans.get(scan_id)

    # ── Cancellation ──────────────────────────────────────────────────────────

    @classmethod
    def _is_cancelled(cls, scan_id: str) -> bool:
        """True if a cancel was requested for this scan (checked by the worker)."""
        with cls._scans_lock:
            return scan_id in cls._cancel_requested

    @classmethod
    def request_cancel(cls, scan_id: str) -> None:
        """
        Flag a scan for cancellation and immediately mark it 'cancelled' in the
        in-memory cache and the DB. A live worker (same process) notices the
        flag at its next stage boundary and stops; an orphaned DB-only job is
        simply marked done here. Idempotent.
        """
        with cls._scans_lock:
            cls._cancel_requested.add(scan_id)

        cls.append_log(scan_id, [{
            "level": "warning",
            "msg":   "Scan cancelled by user — stopping the pipeline.",
        }])
        cls.update(scan_id,
                   status="cancelled",
                   stage=None,
                   stage_label=None,
                   error="Scan cancelled by user.",
                   completed_at=datetime.datetime.utcnow().isoformat())

    @classmethod
    def reconcile_orphaned_scans(cls) -> int:
        """
        On process start, no scan worker threads exist yet (they live only in
        the process that launched them). Any DB row still marked 'running' or
        'queued' is therefore orphaned — its worker died with a previous
        process. Mark such rows 'failed' so the dashboard never resurrects a
        dead scan via its reconnect-on-load logic. Returns the count fixed.
        """
        from extensions import db
        from models.scan_job import ScanJob

        try:
            stale = ScanJob.query.filter(
                ScanJob.status.in_(["running", "queued"])).all()
            for job in stale:
                job.status       = "failed"
                job.stage        = None
                job.stage_label  = None
                job.error        = ("Interrupted — the server restarted while this "
                                     "scan was in progress. Please start a new scan.")
                job.completed_at = datetime.datetime.utcnow()
            if stale:
                db.session.commit()
            return len(stale)
        except Exception:
            db.session.rollback()
            return 0

    @classmethod
    def validate_target(cls, raw: str) -> bool:
        t = raw.strip().lower()
        if not t or len(t) > 253:
            return False
        return bool(_DOMAIN_RE.match(t))

    @classmethod
    def update(cls, scan_id: str, **kwargs) -> None:
        """Thread-safe field update on a scan record."""
        with cls._scans_lock:
            if scan_id in cls._scans:
                cls._scans[scan_id].update(kwargs)
        cls.db_sync(scan_id, kwargs)

    @classmethod
    def append_log(cls, scan_id: str, events: list) -> None:
        """Append public-safe events from a core module result to the scan log."""
        from extensions import db
        from models.scan_job import ScanJob

        _SKIP = {"cmd", "hosts_sample", "host_header", "analysis"}
        public = []
        for ev in events:
            lvl = ev.get("level", "")
            if lvl in _SKIP:
                continue
            if lvl == "data":
                public.append({"level": "info",
                                "msg": f"{ev.get('label')}: {ev.get('value')}"})
            else:
                public.append({"level": lvl, "msg": ev.get("msg", "")})

        with cls._scans_lock:
            if scan_id in cls._scans:
                cls._scans[scan_id]["log"].extend(public)

        try:
            job = ScanJob.query.filter_by(scan_id=scan_id).first()
            if job:
                existing = json.loads(job.log or '[]')
                existing.extend(public)
                job.log = json.dumps(existing)
                db.session.commit()
        except Exception as exc:
            current_app.logger.error("ScanJob log sync failed: %s", exc)
            db.session.rollback()

    @classmethod
    def db_sync(cls, scan_id: str, data: dict) -> None:
        """
        Write a subset of scan fields to the ScanJob DB row.
        Never raises — DB errors are logged only.
        Must be called inside an app_context.
        """
        from extensions import db
        from models.scan_job import ScanJob

        try:
            job = ScanJob.query.filter_by(scan_id=scan_id).first()
            if not job:
                return
            if 'hosts_discovered' in data:
                job.hosts_found = data['hosts_discovered']
            if 'hosts_scanned' in data:
                job.hosts_scanned = data['hosts_scanned']
            if 'status' in data:
                job.status = data['status']
            if 'stage' in data:
                job.stage = data['stage']
            if 'stage_label' in data:
                job.stage_label = data['stage_label']
            if 'result' in data:
                job.result = data['result']
            if 'error' in data:
                job.error = data['error']
            if 'completed_at' in data:
                job.completed_at = (
                    datetime.datetime.fromisoformat(data['completed_at'])
                    if isinstance(data['completed_at'], str)
                    else data['completed_at']
                )
            if 'analyses' in data:
                job.analyses = json.dumps(data['analyses'])
            if 'diff' in data:
                job.diff = json.dumps(data['diff'])
            db.session.commit()
        except Exception as exc:
            current_app.logger.error(
                "ScanJob DB sync failed for %s: %s", scan_id, exc)
            db.session.rollback()

    @classmethod
    def compute_diff(
        cls,
        target: str,
        user_id: int,
        new_fp: list,
        current_scan_id: str,
    ) -> dict:
        """
        Compare new fingerprint data against the most recent previous completed
        scan for the same target + user within this server session.
        """
        def _envelope(baseline: str) -> dict:
            """
            baseline:
              "none"        no earlier completed scan exists — nothing to compare
              "unavailable" an earlier scan exists but its fingerprint data is
                            not reachable from this process
              "compared"    a real comparison was performed
            """
            return {
                "has_diff":         False,
                "new_hosts":        [],
                "new_ports":        {},
                "previous_scan_at": None,
                "baseline":         baseline,
                "comparable":       baseline == "compared",
            }

        prev_output_dir:   str | None = None
        prev_completed_at: str | None = None

        with cls._scans_lock:
            for sid, job in cls._scans.items():
                if (sid != current_scan_id
                        and job.get("target")  == target
                        and job.get("user_id") == user_id
                        and job.get("status")  == "completed"):
                    c_at = job.get("completed_at") or ""
                    if prev_completed_at is None or c_at > prev_completed_at:
                        prev_completed_at = c_at
                        prev_output_dir   = job.get("output_dir")

        if not prev_output_dir:
            # compute_diff needs the previous scan's fingerprint.json, reachable
            # only through output_dir — a filesystem path the ScanJob schema does
            # not store. So no DB fallback is possible here without a migration.
            # What we CAN do is ask the DB whether a baseline exists at all, and
            # refuse to report "nothing changed" when the truth is "nothing to
            # compare against". Silently conflating the two is the same class of
            # false negative as reporting 0 live hosts for a crashed probe.
            from models.scan_job import ScanJob

            prior = (ScanJob.query
                     .filter(ScanJob.user_id == user_id,
                             ScanJob.target == target,
                             ScanJob.status == 'completed',
                             ScanJob.scan_id != current_scan_id)
                     .first())
            return _envelope("unavailable" if prior else "none")

        fp_file = Path(prev_output_dir) / EngineConfig.FILE_FINGERPRINT
        if not fp_file.exists():
            return _envelope("unavailable")

        try:
            old_fp: list = json.loads(fp_file.read_text())
        except Exception:
            return _envelope("unavailable")

        old_map = {item["host"]: item for item in old_fp if isinstance(item, dict)}
        new_map = {item["host"]: item for item in new_fp  if isinstance(item, dict)}

        new_hosts = [h for h in new_map if h not in old_map]
        new_ports: dict = {}
        for host, data in new_map.items():
            if host in old_map:
                old_set = set(old_map[host].get("open_ports", []))
                new_set = set(data.get("open_ports", []))
                added   = sorted(new_set - old_set)
                if added:
                    new_ports[host] = added

        return {
            "has_diff":         bool(new_hosts or new_ports),
            "new_hosts":        new_hosts,
            "new_ports":        new_ports,
            "previous_scan_at": prev_completed_at,
            "baseline":         "compared",
            "comparable":       True,
        }

    @classmethod
    def copy_screenshots(cls, scan_id: str, screenshots: dict) -> dict:
        """
        Copy screenshot files from the temp scan directory into Flask's static
        tree so they can be served via HTTP.

        Security controls
        -----------------
        * Directory-boundary check: prevents path traversal from a malicious
          httpx JSON output.
        * Extension allow-list: only .png/.jpg/.jpeg/.webp accepted.

        Returns a {host_url: "/static/screenshots/<scan_id>/<file>.png"} map.
        """
        if not screenshots:
            return {}

        screenshots_folder = current_app.config['SCREENSHOTS_FOLDER']
        target_dir = os.path.join(screenshots_folder, scan_id)
        os.makedirs(target_dir, exist_ok=True)

        public: dict = {}
        for host, fs_path in screenshots.items():
            try:
                if not fs_path or not os.path.isfile(fs_path):
                    continue

                resolved    = os.path.realpath(fs_path)
                allowed_dir = os.path.realpath(str(Path(fs_path).parent))

                if not resolved.startswith(allowed_dir + os.sep) and resolved != allowed_dir:
                    if os.path.dirname(resolved) != allowed_dir:
                        current_app.logger.warning(
                            "Screenshot path traversal blocked: %s", fs_path)
                        continue

                ext = os.path.splitext(resolved)[1].lower()
                if ext not in _ALLOWED_SCREENSHOT_EXT:
                    current_app.logger.warning(
                        "Screenshot with disallowed extension blocked: %s", ext)
                    continue

                fname = os.path.basename(resolved)
                dest  = os.path.join(target_dir, fname)
                shutil.copy2(resolved, dest)
                public[host] = f"/static/screenshots/{scan_id}/{fname}"
            except Exception:
                pass

        return public

    @classmethod
    def run_worker(cls, app, scan_id: str, target: str, output_dir: Path,
                   run_active_recon: bool = False) -> None:
        """
        Execute the full recon → fingerprint → AI pipeline in a daemon thread.
        Accepts app as a parameter to call app.app_context() without importing
        from app.py (prevents circular imports).
        """
        from services.notify_service import NotifyService

        with app.app_context():
            with cls._scans_lock:
                user_id: int = cls._scans[scan_id].get("user_id", 0)

            try:
                # ── Stage 1: Reconnaissance ───────────────────────────────
                cls.update(scan_id,
                           stage="recon",
                           stage_label="Passive subdomain enumeration + live host probing + screenshots")

                if cls._is_cancelled(scan_id):
                    return
                recon = ReconModule(target, output_dir).execute()
                cls.append_log(scan_id, recon["events"])

                live_hosts = recon["live_hosts"]

                # Branch on WHY recon produced nothing. A broken probe and a
                # dead target are different outcomes and must read differently.
                if recon.get("status") == "error":
                    cls.update(scan_id,
                               status="failed",
                               error=(
                                   "Live-host detection failed — this is a scanner "
                                   "fault, NOT a verdict about the target. "
                                   f"{recon.get('error_reason') or 'cause unknown'}. "
                                   "No results were produced; fix the tooling and re-run."
                               ),
                               completed_at=datetime.datetime.utcnow().isoformat())
                    return

                if not live_hosts:
                    cls.update(scan_id,
                               status="failed",
                               error=(
                                   "Target appears dead — reconnaissance completed "
                                   "successfully but found 0 hosts responding on "
                                   "HTTP/HTTPS. Verify the domain is correct and "
                                   "publicly accessible."
                               ),
                               completed_at=datetime.datetime.utcnow().isoformat())
                    return

                fallback_note = (
                    " (DEGRADED: hosts unverified by httpx)"
                    if recon.get("degraded") else ""
                )
                cls.update(scan_id,
                           degraded=bool(recon.get("degraded")),
                           hosts_discovered=len(live_hosts),
                           recon_note=f"{len(live_hosts)} host(s) found{fallback_note}")

                raw_screenshots = recon.get("screenshots", {})
                if raw_screenshots:
                    public_screenshots = cls.copy_screenshots(scan_id, raw_screenshots)
                    cls.update(scan_id, screenshots=public_screenshots)
                    cls.append_log(scan_id, [{
                        "level": "info",
                        "msg":   f"Visual recon: {len(public_screenshots)} screenshot(s) ready",
                    }])

                # Log enrichment stage results (non-blocking; empty lists are silent)
                enrich_log = []
                http_resp = recon.get("http_responses", [])
                crtsh     = recon.get("crtsh_subdomains", [])
                hist      = recon.get("historical_urls", [])
                js_files  = recon.get("js_files", [])
                if http_resp:
                    enrich_log.append({
                        "level": "info",
                        "msg":   f"HTTP capture: full headers collected for {len(http_resp)} host(s)",
                    })
                if crtsh:
                    enrich_log.append({
                        "level": "info",
                        "msg":   f"crt.sh: {len(crtsh)} subdomain(s) from certificate transparency",
                    })
                if hist:
                    enrich_log.append({
                        "level": "info",
                        "msg":   f"Historical URLs: {len(hist)} interesting endpoint(s) archived",
                    })
                if js_files:
                    enrich_log.append({
                        "level": "info",
                        "msg":   f"JS discovery: {len(js_files)} JavaScript file(s) queued for analysis",
                    })
                if enrich_log:
                    cls.append_log(scan_id, enrich_log)

                # ── Stage 2: Fingerprinting ───────────────────────────────
                cls.update(scan_id,
                           stage="fingerprint",
                           stage_label="Port scanning + technology stack fingerprinting")

                if cls._is_cancelled(scan_id):
                    return
                fp = FingerprintModule(live_hosts, output_dir).execute()
                cls.append_log(scan_id, fp["events"])

                fp_data = fp["results"]
                if not fp_data:
                    cls.update(scan_id,
                               status="failed",
                               error="Fingerprinting produced no results.",
                               completed_at=datetime.datetime.utcnow().isoformat())
                    return

                cls.update(scan_id, hosts_scanned=len(fp_data))

                diff = cls.compute_diff(target, user_id, fp_data, scan_id)
                cls.update(scan_id, diff=diff)
                if diff.get("baseline") == "unavailable":
                    cls.append_log(scan_id, [{
                        "level": "warning",
                        "msg": ("[DIFF] A previous scan of this target exists, but "
                                "its fingerprint data is not reachable from this "
                                "process (server restarted). No comparison was "
                                "performed — this is NOT a report of 'no changes'."),
                    }])
                if diff["has_diff"]:
                    parts = []
                    if diff["new_hosts"]:
                        parts.append(f"{len(diff['new_hosts'])} new host(s)")
                    if diff["new_ports"]:
                        parts.append(
                            f"new open ports on {len(diff['new_ports'])} host(s)")
                    cls.append_log(scan_id, [{
                        "level": "warning",
                        "msg":   f"[DIFF] Changes detected vs previous scan: {', '.join(parts)}",
                    }])

                # ── Stage 2.5: Active Recon & Fuzzing (Deep scan only) ────
                # Crawl, directory/param fuzzing, wide port scan and template
                # scanning. Runs concurrently inside the module; each tool is
                # rate-capped and time-bounded so the worker never floods a
                # target or hangs the pipeline. Skipped entirely for a Fast
                # (passive-only) scan — the pipeline jumps straight to JS-Oracle.
                if cls._is_cancelled(scan_id):
                    return
                active_data: dict = {}
                if run_active_recon:
                    cls.update(scan_id,
                               stage="active_recon",
                               stage_label=("Active recon & fuzzing — katana crawl, ffuf, "
                                            "arjun params, naabu ports, nuclei templates"))
                    try:
                        active = ActiveReconModule(
                            target,
                            live_hosts,
                            output_dir,
                            seed_endpoints=recon.get("historical_urls", []),
                            seed_js=recon.get("js_files", []),
                        ).execute()
                        cls.append_log(scan_id, active["events"])
                        active_data = active

                        ac = active.get("crawl", {})
                        nx = active.get("nuclei", {})
                        cls.update(
                            scan_id,
                            crawl_endpoints=ac.get("count", 0),
                            fuzz_paths=active.get("fuzz", {}).get("count", 0),
                            hidden_params=active.get("params", {}).get("count", 0),
                            wide_ports=active.get("ports", {}).get("count", 0),
                            nuclei_findings=nx.get("count", 0),
                        )
                    except Exception as exc:
                        cls.append_log(scan_id, [{
                            "level": "warning",
                            "msg":   f"Active Recon module failed: {exc}",
                        }])
                else:
                    cls.append_log(scan_id, [{
                        "level": "info",
                        "msg":   ("Fast scan (passive only) — Active Recon & Fuzzing "
                                  "phase skipped. Re-run as a Deep scan to enable "
                                  "crawling, fuzzing, wide port scan and nuclei."),
                    }])

                # ── Stage 3: JS-Oracle Analysis ───────────────────────────
                cls.update(scan_id,
                           stage="js_oracle",
                           stage_label="JavaScript file analysis — JS-Oracle + Claude AI")

                if cls._is_cancelled(scan_id):
                    return
                js_data: dict = {}
                # Merge JS files from passive recon and the active crawl (katana
                # -jc). dict.fromkeys() de-duplicates while preserving order.
                js_urls = list(dict.fromkeys(
                    (recon.get("js_files", []) or [])
                    + (active_data.get("crawl", {}).get("js_files", []) or [])
                ))
                if js_urls:
                    try:
                        from core.js_oracle import JSOracle
                        js_result = JSOracle(output_dir).execute(target, js_urls)
                        cls.append_log(scan_id, js_result["events"])
                        js_data = js_result

                        # Report live vs archived distinctly — an operator must
                        # never read a coverage number inflated with dead
                        # archived files that were never actually analyzed.
                        cls.update(
                            scan_id,
                            js_live_analyzed=js_result.get("js_files_analyzed", 0),
                            js_archived_parked=js_result.get("archived_count", 0),
                        )
                        cls.append_log(scan_id, [{
                            "level": "info",
                            "msg": (
                                f"JS coverage — live JS analyzed: "
                                f"{js_result.get('js_files_analyzed', 0)} | "
                                f"archived JS parked: "
                                f"{js_result.get('archived_count', 0)}"
                            ),
                        }])
                    except Exception as exc:
                        cls.append_log(scan_id, [{
                            "level": "warning",
                            "msg":   f"JS-Oracle module failed: {exc}",
                        }])
                else:
                    cls.append_log(scan_id, [{
                        "level": "info",
                        "msg":   "JS-Oracle skipped — no JavaScript files discovered in Module 1",
                    }])

                # ── Stage 4: AI Vulnerability Advisor ─────────────────────
                cls.update(scan_id,
                           stage="ai_analysis",
                           stage_label="Claude AI batch vulnerability analysis")

                if cls._is_cancelled(scan_id):
                    return
                ai = AIAdvisorModule(fp_data, output_dir,
                                     js_data=js_data,
                                     active_data=active_data).execute()
                cls.append_log(scan_id, ai["events"])

                analyses = ai.get("analyses", {})
                if not analyses or all(
                        v == "Analysis unavailable." for v in analyses.values()):
                    cls.update(scan_id,
                               status="failed",
                               error=(
                                   "AI analysis returned no results. "
                                   "Verify ANTHROPIC_API_KEY is set and the account has API access."
                               ),
                               completed_at=datetime.datetime.utcnow().isoformat())
                    return

                # ── Compile final Markdown report ─────────────────────────
                parts = []
                for host_url, analysis in analyses.items():
                    if analysis and analysis not in (
                        "Analysis unavailable.",
                        "Analysis not generated for this host.",
                    ):
                        parts.append(f"## {host_url}\n\n{analysis}")

                full_report = "\n\n---\n\n".join(parts) if parts else "No analysis generated."

                # Final cancel check — don't overwrite a 'cancelled' verdict with
                # 'completed' if the user cancelled during the AI stage.
                if cls._is_cancelled(scan_id):
                    return

                cls.update(scan_id,
                           status="completed",
                           stage=None,
                           stage_label=None,
                           result=full_report,
                           analyses=analyses,
                           hosts_scanned=len(fp_data),
                           completed_at=datetime.datetime.utcnow().isoformat())

                NotifyService.notify_all(
                    f"✅ <b>Scan Completed:</b> {target}\n"
                    f"🔍 <b>Hosts Scanned:</b> {len(fp_data)}\n"
                    f"🤖 <b>AI Report Generated.</b>"
                )

                # Attach the full AI report as a PDF to the Telegram notification.
                # Best-effort: a rendering/network failure is logged but never
                # affects the scan's completed status.
                try:
                    from models.scan_job import ScanJob
                    from services.pdf_service import render_scan_pdf
                    job_row = ScanJob.query.filter_by(scan_id=scan_id).first()
                    if job_row:
                        pdf_bytes, pdf_name = render_scan_pdf(job_row)
                        if pdf_bytes:
                            NotifyService.send_document(
                                pdf_bytes, pdf_name,
                                caption=(f"📄 <b>Scan Report</b> — {target}\n"
                                         f"🔍 Hosts scanned: {len(fp_data)}"))
                            cls.append_log(scan_id, [{
                                "level": "info",
                                "msg":   "PDF report sent to Telegram.",
                            }])
                except Exception as exc:
                    cls.append_log(scan_id, [{
                        "level": "warning",
                        "msg":   f"Could not send PDF report to Telegram: {exc}",
                    }])

            except Exception as exc:
                # Surface the failure in BOTH the persisted status AND the live
                # scan log the operator is watching — a bare status flip with no
                # log line reads like the scan silently vanished mid-run.
                cls.update(scan_id,
                           status="failed",
                           error=f"Unexpected internal error: {exc}",
                           completed_at=datetime.datetime.utcnow().isoformat())
                cls.append_log(scan_id, [{
                    "level": "error",
                    "msg":   f"Scan aborted — unexpected internal error: {exc}",
                }])
                # Best-effort failure ping (successes already notify). Never let a
                # notification error mask the original exception.
                try:
                    NotifyService.notify_all(
                        f"❌ <b>Scan Failed:</b> {target}\n"
                        f"⚠️ <b>Error:</b> {exc}")
                except Exception:
                    pass
