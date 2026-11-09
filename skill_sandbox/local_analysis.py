"""Retired raw-text model API. Public scans never send package text to a model.

The scheduled worker accepts only finite technical categories and public research.
This compatibility shim deliberately ignores all supplied text and transport hooks.
"""

SCHEMA = "injecticide.local-analysis.v1"


def analyze_local(text_sources, report, *, transport=None):
    return {"schema": SCHEMA, "status": "not_assessed", "advisory_only": True,
            "findings": [], "trained_for_injecticide": False,
            "reason": "Raw-text model analysis is retired. Scheduled research accepts allowlisted technical categories only."}


def _chat(*args, **kwargs):
    raise RuntimeError("Raw scan model transport is retired")
