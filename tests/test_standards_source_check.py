import copy
import hashlib

from tools.check_skill_standards_sources import check_sources


class Response:
    def __init__(self, content=b"reviewed", status=200):
        self.content, self.status_code = content, status
    def __enter__(self):
        return self
    def __exit__(self, *args):
        return False
    def iter_content(self, size):
        yield self.content


class Session:
    def __init__(self, response):
        self.response, self.calls = response, []
    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return self.response


def catalog(url="https://agentskills.io/specification.md"):
    return {"sources": [{"id": "format", "url": url,
                         "source_sha256": hashlib.sha256(b"reviewed").hexdigest()}]}


def test_unchanged_source_is_compared_without_mutation_or_rule_activation():
    source = catalog()
    original = copy.deepcopy(source)
    client = Session(Response())
    result = check_sources(source, client)
    assert result["results"][0]["status"] == "unchanged_reviewed_snapshot"
    assert result["automatic_rule_activation"] is False
    assert source == original
    assert client.calls[0][1]["allow_redirects"] is False


def test_changed_source_requires_review_without_changing_the_pinned_hash():
    source = catalog()
    result = check_sources(source, Session(Response(b"changed")))
    assert result["results"][0]["status"] == "changed_review_required"
    assert result["review_required"] is True
    assert source["sources"][0]["source_sha256"] == hashlib.sha256(b"reviewed").hexdigest()


def test_redirect_and_oversized_sources_are_unverified(monkeypatch):
    assert check_sources(catalog(), Session(Response(status=302)))["results"][0]["status"] == "unknown_unverified"
    monkeypatch.setattr("tools.check_skill_standards_sources.MAX_SOURCE_BYTES", 2)
    assert check_sources(catalog(), Session(Response()))["results"][0]["status"] == "unknown_unverified"


def test_unreviewed_destinations_are_not_contacted():
    client = Session(Response())
    for url in ("https://unknown.invalid/doc", "https://user:password@agentskills.io/doc", "http://agentskills.io/doc"):
        assert check_sources(catalog(url), client)["results"][0]["status"] == "unknown_unverified"
    assert client.calls == []


def test_empty_catalog_cannot_report_a_completed_source_review():
    result = check_sources({"sources": []}, Session(Response()))
    assert result["results"] == [] and result["review_required"] is True
