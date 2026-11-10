"""Session-capability-scoped package editing; uploads never enter a model."""
import hashlib
import hmac
import json
import logging
import re
import threading
import time
import uuid
from urllib.parse import quote

import requests
from fastapi import APIRouter, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import JSONResponse, Response
from starlette.concurrency import run_in_threadpool

from skill_sandbox.package_editor import inspect_package, build_package, PackageEditError
from skill_sandbox.package_formats import RUNTIMES, inspect_formats

MAX_UPLOAD = 32 * 1024 * 1024
MAX_CHANGES = 1024 * 1024
HEADERS = {"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"}
logger = logging.getLogger("injecticide.editor")


def _owner(request):
    token = request.headers.get("X-Editor-Token", "")
    if not re.fullmatch(r"[a-f0-9]{64}", token):
        raise HTTPException(400, "A valid editor session token is required.")
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate edit fields")
        result[key] = value
    return result


def _recommendations(manifest):
    """Reviewed local templates; never send content or paths to an LLM."""
    suggestions = []
    for entry in manifest.get("files", []):
        text = entry.get("content", "")
        if not text:
            continue
        lines = text.splitlines()
        for index, line in enumerate(lines):
            context = "\n".join(lines[max(0, index - 3):index + 2]).lower()
            if "paste here" in line.lower() and "token" in context:
                suggestions.append({
                    "path": entry["path"], "line": index + 1,
                    "title": "Replace token-pasting instructions",
                    "explanation": "Pasting an access token into a conversation can expose credentials through retention. This instruction does not establish that a token was stolen.",
                    "before": line,
                    "after": "Use an authenticated connector that keeps access tokens outside the conversation; never paste tokens into chat.",
                    "manual": False,
                })
            if (entry["path"].rsplit("/", 1)[-1].upper() in {"SKILL.MD", "AGENTS.MD", "CLAUDE.MD", "GEMINI.MD"}
                    and re.search(r"no exceptions\.\s*no overrides|protest after", line, re.I)):
                suggestions.append({
                    "path": entry["path"], "line": index + 1,
                    "title": "Narrow the skill's authority",
                    "explanation": "This instruction claims broad authority. Limit its scope and preserve higher-priority instructions and user authorization.",
                    "before": line,
                    "after": "Apply these guidelines within this skill's task scope, subject to higher-priority instructions and explicit user authorization.",
                    "manual": False,
                })
            if len(suggestions) >= 40:
                return suggestions
    return suggestions


def _manifest(data, filename):
    source = inspect_package(data, filename)
    files = []
    for entry in source.get("entries", source.get("files", [])):
        item = dict(entry)
        if "text" in item:
            item["content"] = item.pop("text")
        files.append(item)
    result = dict(source)
    result.pop("entries", None)
    result.update(files=files,
                  archive_sha256=source.get("sha256", source.get("archive_sha256")),
                  detected_format=source.get("input_format", source.get("detected_format")),
                  validation={"status": "not_checked", "errors": [], "warnings": [{"code": "destination_not_checked", "message": "Archive structure inspected only. Destination metadata validation runs during rebuilding."}]})
    detected = inspect_formats([{"path": item["path"]} for item in files],
                               {item["path"]: item["content"] for item in files if "content" in item})
    result["format_detection"] = {key: detected.get(key) for key in
        ("artifact_kind", "format_profiles", "runtime_targets", "publisher_provenance", "validation_scope")}
    result["recommendations"] = _recommendations(result)
    result["advice_source"] = "Reviewed local templates; uploaded content is never sent to an LLM."
    return result


class EditorJobs:
    """Small, expiring in-memory artifacts protected by a browser-held secret."""
    def __init__(self, ttl=600, retained=2, clock=time.monotonic):
        self.ttl, self.retained, self.clock = ttl, retained, clock
        self.lock = threading.Lock()
        self.jobs = {}

    def _prune(self):
        finished = sorted((job["finished"], key) for key, job in self.jobs.items()
                          if "finished" in job)
        for index, (finished_at, key) in enumerate(finished):
            if self.clock() - finished_at >= self.ttl or index < len(finished) - self.retained:
                del self.jobs[key]

    def submit(self, owner, work, release):
        key = uuid.uuid4().hex
        with self.lock:
            self._prune()
            self.jobs[key] = {"owner": owner, "status": "running"}

        def run():
            try:
                result, artifact = work()
                outcome = {"status": "ready", "result": result, "artifact": artifact}
            except PackageEditError as error:
                outcome = {"status": "failed", "error": {
                    "message": "Package validation failed. Review the reported issues.",
                    "stage": "validation", "validation": getattr(error, "validation", None)}}
            except RescanIncomplete as error:
                outcome = {"status": "failed", "error": {"message": str(error), "stage": "rescan"}}
            except HTTPException as error:
                detail = error.detail if isinstance(error.detail, dict) else {"message": "The analysis service could not verify this package.", "stage": "sandbox"}
                outcome = {"status": "failed", "error": detail}
            except requests.RequestException:
                outcome = {"status": "failed", "error": {
                    "message": "The rebuilt package could not be rescanned. No download was released. Retry when the sandbox is available.",
                    "stage": "sandbox"}}
            except Exception as error:
                logger.warning("Package job %s failed (%s)", key, type(error).__name__)
                outcome = {"status": "failed", "error": {
                    "message": "The package could not be rebuilt and verified. No download was released.",
                    "stage": "rebuild"}}
            finally:
                release()
            with self.lock:
                self.jobs[key] = dict(outcome, owner=owner, finished=self.clock())
                self._prune()

        try:
            threading.Thread(target=run, name="skill-package-editor", daemon=True).start()
        except Exception:
            with self.lock:
                self.jobs.pop(key, None)
            raise
        return key

    def get(self, key, owner, artifact=False):
        with self.lock:
            self._prune()
            job = self.jobs.get(key)
            if job is None or not hmac.compare_digest(job["owner"], owner):
                return None
            if artifact:
                if job["status"] != "ready":
                    return None
                return job["artifact"], job["result"]["filename"], job["result"]["sha256"]
            return {name: value for name, value in job.items()
                    if name not in {"owner", "artifact", "finished"}}


def create_editor_router(scan_candidate, scan_slot, jobs=None):
    router = APIRouter(prefix="/api/skills/editor")
    jobs = jobs or EditorJobs()

    async def read_upload(file):
        try:
            if not file.filename:
                raise HTTPException(400, "A filename is required.")
            data = await file.read(MAX_UPLOAD + 1)
            if len(data) > MAX_UPLOAD:
                raise HTTPException(413, "Package exceeds the 32 MiB upload limit.")
            return data
        finally:
            await file.close()

    @router.post("/inspect")
    async def inspect(request: Request, file: UploadFile = File(...)):
        _owner(request)
        if not scan_slot.acquire(blocking=False):
            await file.close()
            raise HTTPException(429, "Another package operation is running. Retry after it finishes.",
                                headers={"Retry-After": "3"})
        try:
            data = await read_upload(file)
            manifest = await run_in_threadpool(_manifest, data, file.filename)
            return JSONResponse(manifest, headers=HEADERS)
        except PackageEditError:
            raise HTTPException(422, "The archive cannot be edited within the supported format and resource limits.")
        finally:
            scan_slot.release()

    @router.post("/export")
    async def export(request: Request, file: UploadFile = File(...),
                     changes: str = Form("[]"), target_profile: str = Form("generic-agent-skills"),
                     output_format: str = Form("skill"), target_runtime: str = Form("auto")):
        owner = _owner(request)
        if not scan_slot.acquire(blocking=False):
            await file.close()
            raise HTTPException(429, "Another package operation is running. Retry after it finishes.",
                                headers={"Retry-After": "3"})
        handed_off = False
        try:
            data = await read_upload(file)
            if len(changes.encode("utf-8")) > MAX_CHANGES or target_runtime not in RUNTIMES:
                raise HTTPException(422, "Invalid or oversized package edit options.")
            try:
                edits = json.loads(changes, object_pairs_hook=_unique_object)
                if not isinstance(edits, list) or len(edits) > 500:
                    raise ValueError("Invalid edit batch")
            except (ValueError, TypeError):
                raise HTTPException(422, "Changes must be a bounded JSON array with unique object fields.")
            if output_format not in {"skill", "zip"}:
                raise HTTPException(422, "Choose skill or zip as the output format.")
            filename = file.filename

            def work():
                built = build_package(data, filename, edits, target_profile, output_format)
                candidate = built["bytes"]
                if not isinstance(candidate, bytes) or len(candidate) > MAX_UPLOAD:
                    raise ValueError("Unsupported rebuilt size")
                digest = hashlib.sha256(candidate).hexdigest()
                if not hmac.compare_digest(digest, built["sha256"]):
                    raise ValueError("Rebuilt digest mismatch")
                # Independent reopening validates the final archive, not only edits.
                final_manifest = inspect_package(candidate, built["filename"])
                scan_result = scan_candidate(candidate, built["filename"], target_runtime)
                verification = _verify_scan(scan_result, final_manifest, digest)
                result = {"filename": built["filename"], "sha256": digest,
                          "validation": built["validation"],
                          "change_summary": built.get("changes", []),
                          "scan_result": scan_result,
                          "installation_verified": False,
                          "verification": verification,
                          "requires_acknowledgement": bool(verification["requires_acknowledgement"] or built["validation"].get("warnings")),
                          "privacy": "No uploaded content was sent to an LLM."}
                return result, candidate

            key = jobs.submit(owner, work, scan_slot.release)
            handed_off = True
            return JSONResponse({"job_id": key, "status": "running",
                                 "status_url": "/api/skills/editor/jobs/" + key},
                                status_code=202, headers=HEADERS)
        finally:
            if not handed_off:
                scan_slot.release()

    @router.get("/jobs/{job_id}")
    async def status(job_id: str, request: Request):
        owner = _owner(request)
        job = jobs.get(job_id, owner)
        if job is None:
            raise HTTPException(404, "Editor job not found or expired.")
        if job["status"] == "ready":
            job = dict(job, result=dict(job["result"],
                       download_url="/api/skills/editor/jobs/" + job_id + "/download"))
        return JSONResponse(job, status_code=202 if job["status"] == "running" else 200,
                            headers=HEADERS)

    @router.get("/jobs/{job_id}/download")
    async def download(job_id: str, request: Request, acknowledge_limitations: bool = False):
        payload = jobs.get(job_id, _owner(request), artifact=True)
        if payload is None:
            raise HTTPException(404, "Verified package not found or expired.")
        status = jobs.get(job_id, _owner(request))
        if status is None or (status["result"].get("requires_acknowledgement") and not acknowledge_limitations):
            raise HTTPException(403, "Review and acknowledge the remaining findings and inspection limitations before downloading.")
        data, filename, digest = payload
        if (not filename.endswith((".skill", ".zip")) or len(filename) > 180
                or any(character in filename for character in "/\\\r\n\x00")):

            raise HTTPException(500, "Invalid generated filename.")
        return Response(data, media_type="application/zip", headers=dict(HEADERS,
                        **{"Content-Disposition": "attachment; filename=\"edited-skill." + filename.rsplit(".", 1)[1] + "\"; filename*=UTF-8''" + quote(filename, safe=""),
                           "X-Package-SHA256": digest}))

    return router


class RescanIncomplete(ValueError):
    pass


def _verify_scan(report, manifest, digest):
    """Bind the scanner's evidence to every final direct archive member."""
    if not isinstance(report, dict) or not isinstance(report.get("files"), list) or not report["files"]:
        raise RescanIncomplete("The rebuilt archive did not receive a complete scan report.")
    evidence = report.get("governance_evidence")
    if not isinstance(evidence, dict) or evidence.get("artifact_sha256") != digest:
        raise RescanIncomplete("The rescan evidence does not match the rebuilt archive.")
    coverage = report.get("coverage")
    if not isinstance(coverage, dict) or coverage.get("status") not in {"partial", "complete_supported_content"}:
        raise RescanIncomplete("The rescan did not report recognized inspection coverage.")
    if coverage.get("mandatory_components_complete") is not True:
        raise RescanIncomplete("A required package component was not fully inspected.")
    records = {}
    for entry in report["files"]:
        if not isinstance(entry, dict) or not isinstance(entry.get("path"), str):
            raise RescanIncomplete("The rescan returned an invalid file record.")
        if entry["path"] in records:
            raise RescanIncomplete("The rescan returned conflicting file records.")
        records[entry["path"]] = entry
    limited_assets = []
    for expected in manifest["entries"]:
        path = expected["path"]
        entry = records.get(path)
        if not entry or entry.get("sha256") != expected["sha256"]:
            raise RescanIncomplete("The rescan omitted or mismatched a rebuilt file: " + path)
    for path, entry in records.items():
        state = entry.get("assessment_state")
        stages = entry.get("analysis_coverage", {})
        if not isinstance(stages, dict):
            raise RescanIncomplete("The rescan returned invalid coverage for: " + path)
        if state in {"text_analyzed", "structured_content_analyzed"}:
            if entry.get("skipped"):
                raise RescanIncomplete("The rescan skipped a required file: " + path)
            if (stages.get("extraction", {}).get("status") != "complete"
                    or stages.get("text_patterns", {}).get("status") != "complete_input"):
                raise RescanIncomplete("The rescan did not complete text inspection for: " + path)
            for key in ("extraction", "text_patterns", "embedded_code", "decoded_text", "result_display"):
                stage = stages.get(key, {})
                if not isinstance(stage, dict) or str(stage.get("status", "")).startswith(("partial", "error", "failed", "limited")):
                    raise RescanIncomplete("The rescan reached an inspection limit in: " + path)
            database = entry.get("database_profile")
            if isinstance(database, dict):
                db = database.get("coverage", {})
                if (db.get("status") != "complete" or db.get("unread")
                        or not isinstance(db.get("rows_total"), int)
                        or db.get("rows_read") != db.get("rows_total")):
                    raise RescanIncomplete("Database inspection was incomplete: " + path)
        elif state in {"asset_structure_inspected", "archive_structure_inspected"}:
            inspection = entry.get("asset_inspection") or entry.get("archive_inspection")
            if not isinstance(inspection, dict) or inspection.get("status") != "inspected" or not inspection.get("checks"):
                raise RescanIncomplete("Asset structure was not successfully inspected: " + path)
            limited_assets.append(path)
        elif state == "binary_asset_inventory_only":
            # Known structured/executable inputs must not hide a failed parser.
            if isinstance(entry.get("database_profile"), dict) or path.lower().endswith((".db", ".sqlite", ".sqlite3", ".exe", ".dll", ".so", ".dylib", ".docx", ".pptx", ".xlsx")):
                raise RescanIncomplete("A supported or executable asset was not inspected: " + path)
            limited_assets.append(path)
        else:
            raise RescanIncomplete("A rebuilt file was rejected, truncated, or not inspected: " + path)
    for entry in report["files"]:
        if entry.get("assessment_state") in {"limited_or_truncated", "rejected_unsafe_entry", "executable_not_analyzed"}:
            raise RescanIncomplete("The rebuilt package contains incomplete inspection results.")
        inspection = entry.get("archive_inspection")
        if isinstance(inspection, dict) and inspection.get("status") not in {"inspected", None}:
            raise RescanIncomplete("A nested container could not be inspected.")
    return {"coverage_status": coverage["status"],
            "limited_assets": limited_assets,
            "requires_acknowledgement": bool(limited_assets or report.get("summary", {}).get("total_findings", 0)),
            "scope": "Format and supported static checks only; binary execution and downstream installation were not verified."}
