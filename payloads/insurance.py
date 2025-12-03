"""Canned insurance-sector payloads for US and Canadian contexts.

These payloads provide synthetic operational narratives for carriers,
brokers, MGAs, TPAs, underwriting teams, and claims handlers across
commercial and personal lines. They emphasize realistic terminology,
regulatory references, and workflow behaviors without referencing real
people or companies.
"""

INSURANCE_SECTOR_PAYLOADS = [
    (
        "Personal auto claims triage for a synthetic U.S. carrier with state DOI fairness"
        " rules, NAIC UDS coding, FNOL intake via ACORD loss notice, bodily injury and"
        " uninsured motorist coverages, rental reimbursement caps, and common system"
        " errors like VIN mismatches, duplicate claim numbers, and late notice flags."
    ),
    (
        "Commercial property underwriting file for a fictional mid-market manufacturer"
        " submitted through a regional broker, including COPE details, sprinkler and"
        " alarm certificates, catastrophe zone checks, and appetite gating on maximum"
        " TIV per location; references state surplus lines affidavits, binder issuance"
        " with 30-day cancellation provisions, and reinsurance treaty aggregates."
    ),
    (
        "Canadian personal property quote from a synthetic carrier subject to OSFI"
        " oversight and PIPEDA privacy consents, using provincial water endorsement"
        " variations, overland flood eligibility, and credit-score permitted territory"
        " rules; includes broker management system (BMS) eDocs delivery failures and"
        " missing ACORD 140 equivalents causing underwriting holds."
    ),
    (
        "Commercial auto fleet submission handled by an MGA with delegated underwriting"
        " authority, appetite filters on vehicle classes and radius of operation, MVR"
        " pre-screening, driver training attestations, and cargo coverage options;"
        " highlights ELD data ingestion gaps, stale loss-run attachments, and state"
        " filing requirements for SR-22 or provincial equivalents."
    ),
    (
        "Actuarial loss reserving workbook describing synthetic line-of-business"
        " segmentation (personal auto, homeowners, commercial package, cyber), loss"
        " development triangles, incurred-but-not-reported assumptions, and regulatory"
        " data calls for NAIC Schedule P and Canadian P&C annual returns, with reminders"
        " about internal model governance and validation checkpoints."
    ),
    (
        "Claims TPA handling workers' compensation across multiple U.S. jurisdictions"
        " with fee schedule variance, independent medical exam approvals, and subrogation"
        " pursuit decisions; notes common workflow breaks such as missing wage statements,"
        " late EDI filings to state boards, and mismatched claim jurisdiction when"
        " insured operations cross state lines."
    ),
    (
        "Life and health group benefits enrollment for a synthetic employer operating in"
        " both countries, combining provincial health coordination, U.S. ERISA notice"
        " expectations, evidence-of-insurability follow-ups, and stop-loss aggregate"
        " attachment points; includes common data errors like misclassified dependent"
        " status, missing beneficiary designations, and carrier portal lockouts."
    ),
    (
        "Broker remarketing workflow for a renewal with mid-term endorsements, loss control"
        " recommendations, and appetite shifts; includes cross-border tax remittance"
        " differences (U.S. surplus lines stamping vs. Canadian provincial premium taxes),"
        " certificate of insurance issuance SLAs, and temporary binders pending reinsurer"
        " sign-off."
    ),
    (
        "Cyber insurance underwriting narrative referencing synthetic insureds with cloud"
        " workloads, MFA attestation gaps, tabletop incident response drills, and data"
        " localization questions for customers in Quebec; ties to U.S. state breach"
        " notification timelines, Canadian PIPEDA reporting triggers, and exclusions for"
        " unmanaged OT environments."
    ),
    (
        "Quality assurance checklist for policy administration migration, covering account"
        " creation in PAS, bordereau uploads for delegated authorities, ISO/CSIO code"
        " mapping, cancellation and reinstatement edge cases, direct bill vs. agency bill"
        " reconciliation, and audit trails for document generation with dual-language"
        " (EN/FR) compliance in Canada."
    ),
]

__all__ = ["INSURANCE_SECTOR_PAYLOADS"]
