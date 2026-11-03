import pytest
from tect.models import Claim, Evidence, Relation
from tect.storage import connect, save_claim
from tect.verification_records import record_doi_verification, verify_doi_verification_log


@pytest.fixture(autouse=True)
def isolated_db(tmp_path, monkeypatch):
    monkeypatch.setenv("TECT_DB_PATH", str(tmp_path / "audit.sqlite3"))
    save_claim(Claim(id="c", text="Synthetic", evidence=[
        Evidence(id="e", source="Fixture", locator="doi:10.1234/test",
                 excerpt="Synthetic", relation=Relation.SUPPORTS)]), expected_version=0)


def resolved(doi):
    return {"DOI": doi, "title": ["Fixture publication"]}


def test_record_and_verify():
    event = record_doi_verification("c", 1, "e", resolver=resolved)
    assert event["result"]["status"] == "metadata_matched"
    assert verify_doi_verification_log()["valid"]


def test_multiple_observations():
    record_doi_verification("c", 1, "e", resolver=resolved)
    record_doi_verification("c", 1, "e", resolver=resolved)
    assert verify_doi_verification_log()["events_checked"] == 2


def test_modified_result_detected():
    record_doi_verification("c", 1, "e", resolver=resolved)
    with connect() as db:
        db.execute("UPDATE evidence_verification_events SET result_json='{}'")
        db.commit()
    assert not verify_doi_verification_log()["valid"]


def test_deleted_first_event_detected():
    record_doi_verification("c", 1, "e", resolver=resolved)
    record_doi_verification("c", 1, "e", resolver=resolved)
    with connect() as db:
        db.execute("DELETE FROM evidence_verification_events WHERE seq=1")
        db.commit()
    assert not verify_doi_verification_log()["valid"]


def test_claim_payload_change_detected():
    record_doi_verification("c", 1, "e", resolver=resolved)
    with connect() as db:
        db.execute("UPDATE claims SET payload='{}'")
        db.commit()
    assert not verify_doi_verification_log()["valid"]


def test_missing_evidence_rejected():
    with pytest.raises(ValueError):
        record_doi_verification("c", 1, "missing", resolver=resolved)


def test_unavailable_metadata_recorded():
    def fail(_):
        raise TimeoutError()
    event = record_doi_verification("c", 1, "e", resolver=fail)
    assert event["result"]["status"] == "metadata_unavailable"
    assert verify_doi_verification_log()["valid"]
