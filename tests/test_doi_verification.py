import pytest
from tect.doi_verification import normalize_doi, verify_evidence_doi
from tect.models import Claim, Evidence, Relation
from tect.storage import save_claim


@pytest.fixture(autouse=True)
def isolated_db(tmp_path, monkeypatch):
    monkeypatch.setenv("TECT_DB_PATH", str(tmp_path / "claims.sqlite3"))


def make_claim(locator="doi:10.1234/example"):
    save_claim(Claim(id="c", text="Synthetic", evidence=[
        Evidence(id="e", source="Synthetic", locator=locator,
                 excerpt="Synthetic excerpt", relation=Relation.SUPPORTS)]), expected_version=0)


def test_normalization():
    assert normalize_doi("https://doi.org/10.1234/ABC") == "10.1234/abc"


def test_reject_unsafe_locator():
    assert normalize_doi("http://127.0.0.1/private") is None
    assert normalize_doi("10.1234/abc?redirect=http://internal") is None


def test_metadata_match():
    make_claim()
    result = verify_evidence_doi("c", 1, "e", resolver=lambda doi: {
        "DOI": doi, "title": ["Synthetic publication"], "publisher": "Fixture"})
    assert result["status"] == "metadata_matched"
    assert result["title"] == "Synthetic publication"


def test_metadata_mismatch():
    make_claim()
    result = verify_evidence_doi("c", 1, "e", resolver=lambda doi: {"DOI": "10.1234/other"})
    assert result["status"] == "metadata_mismatch"


def test_network_failure():
    make_claim()
    def failed(_):
        raise TimeoutError()
    assert verify_evidence_doi("c", 1, "e", resolver=failed)["status"] == "metadata_unavailable"


def test_unsupported_locator():
    make_claim("https://example.org/paper")
    assert verify_evidence_doi("c", 1, "e")["status"] == "unsupported_locator"


def test_missing_claim():
    assert verify_evidence_doi("missing", 1, "e")["status"] == "claim_not_found"


def test_missing_evidence():
    make_claim()
    assert verify_evidence_doi("c", 1, "missing")["status"] == "evidence_not_unique_or_missing"
