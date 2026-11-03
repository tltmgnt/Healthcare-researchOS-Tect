"""DOI metadata checks against Crossref, not scientific-content verification.

Network requests use a fixed HTTPS host and a strictly validated DOI path.
"""
import json
import re
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

from .storage import load_claim

_DOI = re.compile(r"^10\.\d{4,9}/[A-Za-z0-9._;()/:+-]+$", re.ASCII)


def normalize_doi(locator: str) -> str | None:
    if not isinstance(locator, str):
        return None
    value = locator.strip()
    for prefix in ("https://doi.org/", "http://doi.org/", "doi:"):
        if value.lower().startswith(prefix):
            value = value[len(prefix):]
            break
    if not _DOI.fullmatch(value) or len(value) > 255:
        return None
    return value.lower()


def crossref_resolver(doi: str) -> dict:
    """Retrieve public metadata from a fixed Crossref API endpoint."""
    url = "https://api.crossref.org/works/" + quote(doi, safe="")
    request = Request(url, headers={"Accept": "application/json", "User-Agent": "ResearchOS-TECT/0.1 (DOI metadata verification)"})
    # Disable redirects so an untrusted response cannot redirect to an internal host.
    from urllib.request import build_opener, HTTPRedirectHandler
    class NoRedirect(HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None
    with build_opener(NoRedirect()).open(request, timeout=5) as response:
        body = response.read(1_000_001)
    if len(body) > 1_000_000:
        raise ValueError("Metadata response too large")
    return json.loads(body)["message"]


def verify_evidence_doi(claim_id: str, version: int, evidence_id: str, *, resolver=None) -> dict:
    """Check DOI metadata for an evidence reference in a saved claim version."""
    claim = load_claim(claim_id, version)
    if claim is None:
        return {"status": "claim_not_found"}
    matches = [item for item in claim.evidence if item.id == evidence_id]
    if len(matches) != 1:
        return {"status": "evidence_not_unique_or_missing"}
    doi = normalize_doi(matches[0].locator)
    if doi is None:
        return {"status": "unsupported_locator"}
    try:
        metadata = (resolver or crossref_resolver)(doi)
    except (HTTPError, URLError, TimeoutError, ValueError, KeyError, OSError):
        return {"status": "metadata_unavailable", "doi": doi}
    if not isinstance(metadata, dict) or normalize_doi(metadata.get("DOI", "")) != doi:
        return {"status": "metadata_mismatch", "doi": doi}
    titles = metadata.get("title", [])
    title = titles[0] if isinstance(titles, list) and titles and isinstance(titles[0], str) else None
    return {"status": "metadata_matched", "doi": doi, "title": title,
            "publisher": metadata.get("publisher"), "type": metadata.get("type"),
            "note": "Bibliographic DOI metadata only; excerpt and scientific claims not verified"}
