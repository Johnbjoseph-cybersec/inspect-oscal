"""Package-wide constants. ``__version__`` is read by hatch from this file."""

from __future__ import annotations

import uuid

__version__ = "0.1.0"

TOOL_NAME = "inspect-oscal"
OSCAL_VERSION = "1.2.1"
NS = "https://github.com/Johnbjoseph-cybersec/inspect-oscal/ns/1.0"
UUID_NAMESPACE = uuid.uuid5(uuid.NAMESPACE_URL, NS)

CATALOG_FILENAME = "NIST_AI-RMF_v1_catalog.json"
AI_RMF_CATALOG_SHA256 = "09de09ecd15f861c4ec05aa192872dc2faafc3bef41c4bc57e19247e84f92545"
CATALOG_SOURCE = (
    "https://github.com/usnistgov/oscal-content/blob/v1.6.0/"
    "nist.gov/AI100-1/ver1/json/NIST_AI-RMF_v1_catalog.json"
)
CATALOG_KEY = "nist-ai-rmf-1.0"

HASH_ALGORITHM = "SHA-256"

MAPPING_STATEMENT = "derived"
MAPPING_NOTICE = (
    "Derived mapping, not NIST-endorsed. Evidence from Inspect eval logs. Where a finding is "
    "present, its status records only whether a user-declared threshold was met on that "
    "evidence; it is not a determination about any subcategory."
)
STATUS_MEANING = (
    "status records whether the user-declared threshold was met; "
    "not a determination about the subcategory"
)
PARTIAL_EVIDENCE = (
    "Threshold met on eval evidence. This is partial evidence and does not establish that "
    "the subcategory is met."
)
PARTIAL_EVIDENCE_MISSED = (
    "Threshold not met on eval evidence. This is partial evidence and not a determination "
    "about the subcategory."
)
MANIFEST_STATEMENT = (
    "Evidence from Inspect eval logs. Derived mapping, not NIST-endorsed. Any finding status "
    "records only a user-declared threshold result. The manifest detects accidental change; "
    "it is not tamper-proof."
)

BUNDLE_FILES = {
    "ar": "assessment-results.json",
    "ap": "assessment-plan.json",
    "ssp": "ssp.json",
    "profile": "profile.json",
}
MANIFEST_FILENAME = "MANIFEST.json"
DEFAULT_OCLI_TIMEOUT = 300
