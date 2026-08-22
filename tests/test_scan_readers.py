"""
Regression tests for Pattern 2 — readers of the in-memory ScanService._scans
cache that diverge from the memory-first-then-DB contract their siblings use.

Background
----------
ScanService._scans is a per-process cache. It is empty after every restart,
while the ScanJob table still holds every scan. api_scan_status and
api_scan_result always read memory-first-then-DB; api_latest_scan was fixed to
match. Two readers still diverged:

  * api_list_scans          — memory only, so /api/scans returned an empty list
                              after a restart while the DB held completed scans.
  * ScanService.compute_diff — memory only, so after a restart it found no
                              baseline and returned has_diff=False, which the
                              UI and scan log render as "nothing changed". A
                              false negative dressed as a clean result.

Deliberate exceptions, asserted here so nobody "fixes" them by mistake:

  * api_start_scan's duplicate check is memory-only ON PURPOSE. Only *running*
    scans matter, and a running scan is by definition in this process. A DB
    fallback would resurrect stale 'running' rows from a killed process and
    permanently block re-scanning that target.
  * api_scan_cves needs output_dir, a filesystem path the schema never stores.
    It already fails LOUDLY with 503 rather than silently.
"""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, "/home/kali/scan-engine")

os.environ.setdefault("FLASK_SECRET_KEY", "t" * 64)

from config import Config as BaseConfig  # noqa: E402


_TMPDB = tempfile.NamedTemporaryFile(suffix=".db", delete=False)


class _TestConfig(BaseConfig):
    TESTING = True
    WTF_CSRF_ENABLED = False
    SQLALCHEMY_DATABASE_URI = "sqlite:///" + _TMPDB.name


class _ScanReaderCase(unittest.TestCase):
    """Fresh app + empty in-memory cache, mirroring a just-restarted server."""

    @classmethod
    def setUpClass(cls):
        from app import create_app
        cls.app = create_app(_TestConfig)

    def setUp(self):
        from extensions import db
        from models import ScanJob
        from services.scan_service import ScanService

        self.db = db
        self.ScanJob = ScanJob
        self.ScanService = ScanService

        # A restarted process: the cache is empty, the database is not.
        ScanService._scans.clear()
        self.addCleanup(ScanService._scans.clear)

        with self.app.app_context():
            ScanJob.query.delete()
            db.session.commit()
            from models.user import User
            user = User.query.filter_by(username="admin").first()
            self.uid = user.id

        self.client = self.app.test_client()
        with self.client.session_transaction() as sess:
            sess["_user_id"] = str(self.uid)
            sess["_fresh"] = True

    def add_db_scan(self, scan_id, target, status="completed"):
        import datetime
        with self.app.app_context():
            job = self.ScanJob(
                scan_id=scan_id, user_id=self.uid, target=target,
                status=status, hosts_found=1, hosts_scanned=1,
                created_at=datetime.datetime.utcnow(),
                completed_at=datetime.datetime.utcnow(),
            )
            self.db.session.add(job)
            self.db.session.commit()

    def add_memory_scan(self, scan_id, target, status="running", **extra):
        rec = {
            "scan_id": scan_id, "target": target, "user_id": self.uid,
            "status": status, "started_at": "2026-01-01T00:00:00",
            "completed_at": None, "hosts_discovered": 0, "hosts_scanned": 0,
            "log": [], "output_dir": "/tmp/nonexistent",
        }
        rec.update(extra)
        self.ScanService._scans[scan_id] = rec
        return rec


class TestApiListScansDbFallback(_ScanReaderCase):
    """
    THE regression: /api/scans must not report "no scans" after a restart.
    Every assertion fails under the old memory-only implementation.
    """

    def test_db_scans_returned_when_memory_empty(self):
        self.add_db_scan("aaa", "example.com")
        self.add_db_scan("bbb", "other.com")
        data = json.loads(self.client.get("/api/scans").data)
        self.assertEqual(data["total"], 2,
                         "memory-only listing hid scans held in the DB")
        self.assertEqual({s["scan_id"] for s in data["scans"]}, {"aaa", "bbb"})

    def test_records_are_labelled_with_their_source(self):
        self.add_db_scan("aaa", "example.com")
        data = json.loads(self.client.get("/api/scans").data)
        self.assertEqual(data["scans"][0]["source"], "db")

    def test_memory_and_db_are_merged_without_duplicates(self):
        self.add_db_scan("aaa", "example.com")
        self.add_memory_scan("bbb", "live.com")
        data = json.loads(self.client.get("/api/scans").data)
        self.assertEqual(data["total"], 2)
        self.assertEqual(len({s["scan_id"] for s in data["scans"]}), 2)

    def test_memory_record_wins_over_stale_db_row(self):
        """A scan running in THIS process is fresher than its DB snapshot."""
        self.add_db_scan("aaa", "example.com", status="running")
        self.add_memory_scan("aaa", "example.com", status="completed")
        data = json.loads(self.client.get("/api/scans").data)
        self.assertEqual(data["total"], 1)
        self.assertEqual(data["scans"][0]["status"], "completed")

    def test_other_users_scans_are_not_leaked(self):
        import datetime
        with self.app.app_context():
            self.db.session.add(self.ScanJob(
                scan_id="zzz", user_id=self.uid + 999, target="secret.com",
                status="completed", created_at=datetime.datetime.utcnow()))
            self.db.session.commit()
        data = json.loads(self.client.get("/api/scans").data)
        self.assertNotIn("zzz", {s["scan_id"] for s in data["scans"]})

    def test_empty_everywhere_is_still_valid(self):
        data = json.loads(self.client.get("/api/scans").data)
        self.assertEqual(data["total"], 0)
        self.assertEqual(data["scans"], [])


class TestSiblingEndpointsAgree(_ScanReaderCase):
    """
    All scan readers that CAN fall back to the DB must behave alike after a
    restart. This is the consistency check that would have caught the family.
    """

    def test_every_reader_sees_a_db_only_scan(self):
        self.add_db_scan("aaa", "example.com")

        status = self.client.get("/api/scan_status/aaa")
        result = self.client.get("/api/scan_result/aaa")
        latest = json.loads(self.client.get("/api/scan/latest").data)
        listing = json.loads(self.client.get("/api/scans").data)

        self.assertEqual(status.status_code, 200, "api_scan_status lost the scan")
        self.assertEqual(result.status_code, 200, "api_scan_result lost the scan")
        self.assertTrue(latest["found"], "api_latest_scan lost the scan")
        self.assertEqual(listing["total"], 1, "api_list_scans lost the scan")


class TestDeliberateMemoryOnlyExceptions(_ScanReaderCase):
    """These readers are memory-only by design — pin that so it stays deliberate."""

    def test_duplicate_check_does_not_resurrect_stale_running_rows(self):
        """
        A 'running' row left by a killed process must NOT block a new scan.
        Giving api_start_scan a DB fallback would deadlock the target forever.
        """
        self.add_db_scan("ghost", "example.com", status="running")
        resp = self.client.post("/api/start_scan",
                                json={"target": "example.com"})
        self.assertNotEqual(
            resp.status_code, 409,
            "a stale DB 'running' row blocked a new scan — the duplicate "
            "check must stay memory-only")

    def test_cves_endpoint_fails_loudly_not_silently(self):
        """output_dir is not in the schema; the failure must be explicit."""
        self.add_db_scan("aaa", "example.com")
        resp = self.client.get("/api/scan/aaa/cves")
        self.assertEqual(resp.status_code, 503)
        self.assertIn("restart", json.loads(resp.data)["error"].lower())


class TestComputeDiffBaselineHonesty(_ScanReaderCase):
    """
    compute_diff cannot take a full DB fallback (it needs output_dir, which the
    schema does not store). It must therefore never conflate "no baseline
    available" with "nothing changed".
    """

    def _diff(self, target, current_sid="current"):
        with self.app.app_context():
            return self.ScanService.compute_diff(target, self.uid, [], current_sid)

    def test_no_prior_scan_reports_baseline_none(self):
        d = self._diff("never-seen.com")
        self.assertEqual(d["baseline"], "none")
        self.assertFalse(d["comparable"])

    def test_prior_scan_out_of_reach_is_not_reported_as_no_changes(self):
        """
        THE regression: a previous scan exists but its fingerprint data is not
        reachable after a restart. Reporting has_diff=False alone reads as
        "nothing changed" — a false negative.
        """
        self.add_db_scan("old", "example.com")
        d = self._diff("example.com")
        self.assertEqual(d["baseline"], "unavailable",
                         "an unreachable baseline was reported as a clean diff")
        self.assertFalse(d["comparable"])

    def test_unavailable_is_distinguishable_from_none(self):
        self.add_db_scan("old", "example.com")
        self.assertNotEqual(self._diff("example.com")["baseline"],
                            self._diff("never-seen.com")["baseline"])

    def test_real_comparison_is_marked_comparable(self):
        import datetime
        from core import Config as EngineConfig
        with tempfile.TemporaryDirectory() as tmp:
            fp = os.path.join(tmp, EngineConfig.FILE_FINGERPRINT)
            with open(fp, "w") as fh:
                json.dump([{"host": "https://a.example.com",
                            "open_ports": [80]}], fh)
            self.add_memory_scan("old", "example.com", status="completed",
                                 completed_at="2026-01-01T00:00:00",
                                 output_dir=tmp)
            with self.app.app_context():
                d = self.ScanService.compute_diff(
                    "example.com", self.uid,
                    [{"host": "https://a.example.com", "open_ports": [80, 443]}],
                    "current")
        self.assertEqual(d["baseline"], "compared")
        self.assertTrue(d["comparable"])
        self.assertTrue(d["has_diff"])
        self.assertEqual(d["new_ports"], {"https://a.example.com": [443]})

    def test_comparable_flag_separates_clean_from_unknown(self):
        """A genuinely unchanged comparison and an absent baseline must differ."""
        with tempfile.TemporaryDirectory() as tmp:
            from core import Config as EngineConfig
            fp = os.path.join(tmp, EngineConfig.FILE_FINGERPRINT)
            same = [{"host": "https://a.example.com", "open_ports": [80]}]
            with open(fp, "w") as fh:
                json.dump(same, fh)
            self.add_memory_scan("old", "example.com", status="completed",
                                 completed_at="2026-01-01T00:00:00",
                                 output_dir=tmp)
            with self.app.app_context():
                clean = self.ScanService.compute_diff(
                    "example.com", self.uid, same, "current")
        self.ScanService._scans.clear()
        unknown = self._diff("never-seen.com")

        self.assertEqual(clean["has_diff"], unknown["has_diff"])   # both False
        self.assertNotEqual(clean["comparable"], unknown["comparable"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
