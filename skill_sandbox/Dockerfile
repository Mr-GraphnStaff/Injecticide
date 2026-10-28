FROM python:3.11-slim

RUN useradd --create-home --shell /bin/bash appuser

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY app.py /app/app.py
COPY artifact_text.py /app/artifact_text.py
COPY asset_inspection.py /app/asset_inspection.py
COPY nested_archives.py /app/nested_archives.py
COPY package_graph.py /app/package_graph.py
COPY process_diagram.py /app/process_diagram.py
COPY script_launchers.py /app/script_launchers.py
COPY standards_assessment.py /app/standards_assessment.py
COPY text_projections.py /app/text_projections.py
COPY code_security.py /app/code_security.py
COPY behavior_analysis.py /app/behavior_analysis.py
COPY contextual_rules.py /app/contextual_rules.py
COPY disposition.py /app/disposition.py
COPY finding_enrichment.py /app/finding_enrichment.py
COPY governance.py /app/governance.py
COPY scan_rules.py /app/scan_rules.py
COPY sensitive_data.py /app/sensitive_data.py
COPY package_formats.py /app/package_formats.py
COPY package_threats.py /app/package_threats.py
COPY package_evidence.py /app/package_evidence.py
COPY package_analysis.py /app/package_analysis.py
COPY review_evidence.py /app/review_evidence.py
COPY package_checks.py /app/package_checks.py
COPY inspection_evidence.py /app/inspection_evidence.py
COPY evidence_redaction.py /app/evidence_redaction.py
COPY official_validators.py /app/official_validators.py
COPY vendor_validators /app/vendor_validators
COPY schemas /app/schemas
COPY rules /app/rules

USER appuser

ENTRYPOINT ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "9001"]
