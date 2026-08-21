import json
import re
import time
from dataclasses import dataclass

import requests

NVD_BASE       = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_REQUEST_DELAY = 6.5   # seconds between NVD calls — stays under 5/30s

_VERSION_RE = re.compile(r'\d+\.\d+')
_IGNORE     = {'HTML', 'CSS', 'JavaScript', 'jQuery', 'Bootstrap'}


@dataclass
class CVEResult:
    cve_id:      str
    description: str
    cvss_score:  float | None
    cvss_vector: str | None
    severity:    str        # CRITICAL | HIGH | MEDIUM | LOW | UNKNOWN
    published:   str        # ISO date string
    url:         str        # https://nvd.nist.gov/vuln/detail/<id>


class CVEService:

    @staticmethod
    def _severity_from_score(score: float | None) -> str:
        if score is None: return 'UNKNOWN'
        if score >= 9.0:  return 'CRITICAL'
        if score >= 7.0:  return 'HIGH'
        if score >= 4.0:  return 'MEDIUM'
        return 'LOW'

    @staticmethod
    def _parse_cve_item(item: dict) -> CVEResult:
        try:
            cve  = item.get('cve', {})
            cid  = cve.get('id', '')

            desc = ''
            for d in cve.get('descriptions', []):
                if d.get('lang') == 'en':
                    desc = d.get('value', '')
                    break

            published = cve.get('published', '')
            metrics   = cve.get('metrics', {})

            score  = None
            vector = None
            for key in ('cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2'):
                entries = metrics.get(key, [])
                if entries:
                    cvss_data = entries[0].get('cvssData', {})
                    raw = cvss_data.get('baseScore')
                    if raw is not None:
                        score  = float(raw)
                        vector = cvss_data.get('vectorString')
                    break

            return CVEResult(
                cve_id      = cid,
                description = desc,
                cvss_score  = score,
                cvss_vector = vector,
                severity    = CVEService._severity_from_score(score),
                published   = published,
                url         = f"https://nvd.nist.gov/vuln/detail/{cid}",
            )
        except Exception:
            return CVEResult(
                cve_id='', description='', cvss_score=None,
                cvss_vector=None, severity='UNKNOWN', published='', url='',
            )

    @staticmethod
    def _fetch_from_nvd(keyword: str, max_results: int) -> list[CVEResult]:
        try:
            resp = requests.get(
                NVD_BASE,
                params={'keywordSearch': keyword, 'resultsPerPage': max_results},
                timeout=10,
                headers={'Accept': 'application/json'},
            )
            if resp.status_code != 200:
                return []
            data = resp.json()
        except Exception:
            return []

        results = []
        for item in data.get('vulnerabilities', []):
            try:
                r = CVEService._parse_cve_item(item)
                if r.cve_id:
                    results.append(r)
            except Exception:
                continue

        results.sort(key=lambda c: (c.cvss_score is None, -(c.cvss_score or 0)))
        return results

    @staticmethod
    def search(keyword: str, max_results: int = 10) -> list[CVEResult]:
        from models.cve_cache import CVECache

        key = keyword.strip().lower()

        cached = CVECache.get(key)
        if cached is not None:
            return [CVEResult(**d) for d in cached]

        results = CVEService._fetch_from_nvd(keyword, max_results)
        CVECache.set(key, [vars(r) for r in results])
        return results

    @staticmethod
    def batch_search(
        technologies: list[str],
        max_per_tech: int = 5,
    ) -> dict[str, list[CVEResult]]:
        from models.cve_cache import CVECache

        out: dict[str, list[CVEResult]] = {}
        for tech in technologies:
            key        = tech.strip().lower()
            cache_hit  = CVECache.get(key) is not None

            results = CVEService.search(tech, max_results=max_per_tech)
            if results:
                out[tech] = results

            if not cache_hit:
                time.sleep(_REQUEST_DELAY)

        return out

    @staticmethod
    def extract_technologies(fp_data: list[dict]) -> list[str]:
        seen:  set[str]  = set()
        techs: list[str] = []

        for host in fp_data:
            if not isinstance(host, dict):
                continue

            candidates: list[str] = list(host.get('technologies') or [])
            srv = host.get('server')
            if srv:
                candidates.append(srv)
            xpb = host.get('x_powered_by')
            if xpb:
                candidates.append(xpb)

            for raw in candidates:
                if not isinstance(raw, str):
                    continue
                normalized = raw.replace('/', ' ').strip()
                if not _VERSION_RE.search(normalized):
                    continue
                base = normalized.split()[0] if normalized else ''
                if base in _IGNORE:
                    continue
                norm_lower = normalized.lower()
                if norm_lower not in seen:
                    seen.add(norm_lower)
                    techs.append(normalized)
                    if len(techs) >= 15:
                        return techs

        return techs
