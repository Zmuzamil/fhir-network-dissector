"""Map an HTTP method + URL to a FHIR RESTful interaction (segment-based, not one regex).

Example::

    >>> classify("GET", "/fhir/Patient/123/_history/2")["interaction"]
    'vread'
"""
from __future__ import annotations

import re
from typing import Any, Optional
from urllib.parse import parse_qsl, unquote, urlsplit

# FHIR R4 (4.0.1) and R5 (5.0.0) resource types.
RESOURCE_TYPES: frozenset[str] = frozenset("""
Account ActivityDefinition ActorDefinition AdministrableProductDefinition AdverseEvent
AllergyIntolerance Appointment AppointmentResponse ArtifactAssessment AuditEvent Basic Binary
BiologicallyDerivedProduct BiologicallyDerivedProductDispense BodyStructure Bundle
CapabilityStatement CarePlan CareTeam CatalogEntry ChargeItem ChargeItemDefinition Citation Claim
ClaimResponse ClinicalImpression ClinicalUseDefinition CodeSystem Communication
CommunicationRequest CompartmentDefinition Composition ConceptMap Condition ConditionDefinition
Consent Contract Coverage CoverageEligibilityRequest CoverageEligibilityResponse DetectedIssue
Device DeviceAssociation DeviceDefinition DeviceDispense DeviceMetric DeviceRequest DeviceUsage
DeviceUseStatement DiagnosticReport DocumentManifest DocumentReference EffectEvidenceSynthesis
Encounter EncounterHistory Endpoint EnrollmentRequest EnrollmentResponse EpisodeOfCare
EventDefinition Evidence EvidenceReport EvidenceVariable ExampleScenario ExplanationOfBenefit
FamilyMemberHistory Flag FormularyItem GenomicStudy Goal GraphDefinition Group GuidanceResponse
HealthcareService ImagingSelection ImagingStudy Immunization ImmunizationEvaluation
ImmunizationRecommendation ImplementationGuide Ingredient InsurancePlan InventoryItem
InventoryReport Invoice Library Linkage List Location ManufacturedItemDefinition Measure
MeasureReport Media Medication MedicationAdministration MedicationDispense MedicationKnowledge
MedicationRequest MedicationStatement MedicinalProduct MedicinalProductAuthorization
MedicinalProductContraindication MedicinalProductDefinition MedicinalProductIndication
MedicinalProductIngredient MedicinalProductInteraction MedicinalProductManufactured
MedicinalProductPackaged MedicinalProductPharmaceutical MedicinalProductUndesirableEffect
MessageDefinition MessageHeader MolecularSequence NamingSystem NutritionIntake NutritionOrder
NutritionProduct Observation ObservationDefinition OperationDefinition OperationOutcome
Organization OrganizationAffiliation PackagedProductDefinition Parameters Patient PaymentNotice
PaymentReconciliation Permission Person PlanDefinition Practitioner PractitionerRole Procedure
Provenance Questionnaire QuestionnaireResponse RegulatedAuthorization RelatedPerson RequestGroup
RequestOrchestration Requirements ResearchDefinition ResearchElementDefinition ResearchStudy
ResearchSubject RiskAssessment RiskEvidenceSynthesis Schedule SearchParameter ServiceRequest Slot
Specimen SpecimenDefinition StructureDefinition StructureMap Subscription SubscriptionStatus
SubscriptionTopic Substance SubstanceDefinition SubstanceNucleicAcid SubstancePolymer
SubstanceProtein SubstanceReferenceInformation SubstanceSourceMaterial SubstanceSpecification
SupplyDelivery SupplyRequest Task TerminologyCapabilities TestPlan TestReport TestScript Transport
ValueSet VerificationResult VisionPrescription
""".split())

_TYPE_LIKE = re.compile(r"^[A-Z][A-Za-z]+$")
_SPECIAL = ("metadata", "_history")


def _is_type(seg: str) -> bool:
    return seg in RESOURCE_TYPES or bool(_TYPE_LIKE.match(seg))


def _is_anchor(seg: str) -> bool:
    return seg in RESOURCE_TYPES or seg in _SPECIAL or seg.startswith("$")


def split_path(target: str) -> tuple[list[str], str]:
    """Return (decoded path segments, raw query string) of a request target."""
    parts = urlsplit(target if target.startswith(("/", "http")) else "/" + target)
    segs = [unquote(s) for s in parts.path.split("/") if s]
    return segs, parts.query


def classify(method: str, target: str, bundle_type: Optional[str] = None,
             form_body: Optional[bytes] = None) -> dict[str, Any]:
    """Classify a request.

    Args:
        method: HTTP method.
        target: request target (path + query).
        bundle_type: ``type`` of a Bundle sent in the request body (for POST [base]).
        form_body: ``application/x-www-form-urlencoded`` body (for POST ``_search``).

    Returns a dict with ``interaction``, ``resource_type``, ``resource_id``,
    ``version_id``, ``operation``, ``level``, ``compartment``, ``base``,
    ``search_param_names`` and ``search_params`` (list of ``(name, value)``).
    """
    method = (method or "").upper()
    segs, query = split_path(target or "/")
    params = parse_qsl(query, keep_blank_values=True)
    if form_body:
        try:
            params += parse_qsl(form_body.decode("utf-8", "replace"), keep_blank_values=True)
        except Exception:
            pass

    # 1) anchor = first known resource type / metadata / _history / $op;
    # 2) else first "Type-like" segment; 3) else the whole path is the base.
    idx = next((i for i, s in enumerate(segs) if _is_anchor(s)), None)
    if idx is None:
        idx = next((i for i, s in enumerate(segs) if _TYPE_LIKE.match(s)), len(segs))
    base = "/" + "/".join(segs[:idx]) if idx else ""
    rest = segs[idx:]

    res: dict[str, Any] = {
        "interaction": "unknown",
        "resource_type": None,
        "resource_id": None,
        "version_id": None,
        "operation": None,
        "level": None,
        "compartment": None,
        "base": base,
        "search_param_names": [],
        "search_params": [],
    }
    n = len(rest)
    inter = "unknown"

    if n == 0:
        if method == "POST":
            inter = bundle_type if bundle_type in ("batch", "transaction") else "batch/transaction"
        elif method == "GET" and query:
            inter = "search-system"
    elif n == 1 and rest[0] == "metadata":
        inter = "capabilities" if method in ("GET", "HEAD", "OPTIONS") else "unknown"
    elif n == 1 and rest[0] == "_history":
        inter = "history-system" if method == "GET" else "unknown"
    elif rest[0].startswith("$"):
        if n == 1:
            inter, res["operation"], res["level"] = "operation", rest[0], "system"
    elif _is_type(rest[0]):
        rtype = rest[0]
        res["resource_type"] = rtype
        if n == 1:
            inter = {"GET": "search-type", "HEAD": "search-type", "POST": "create",
                     "PUT": "conditional-update", "PATCH": "conditional-patch",
                     "DELETE": "conditional-delete"}.get(method, "unknown")
        elif n == 2 and rest[1] == "_search":
            inter = "search-type" if method in ("POST", "GET") else "unknown"
        elif n == 2 and rest[1] == "_history":
            inter = "history-type" if method == "GET" else "unknown"
        elif n == 2 and rest[1].startswith("$"):
            inter, res["operation"], res["level"] = "operation", rest[1], "type"
        elif n == 2:
            res["resource_id"] = rest[1]
            inter = {"GET": "read", "HEAD": "read", "PUT": "update", "PATCH": "patch",
                     "DELETE": "delete"}.get(method, "unknown")
        elif n == 3 and rest[2] == "_history":
            res["resource_id"] = rest[1]
            inter = "history-instance" if method == "GET" else "unknown"
        elif n == 3 and rest[2].startswith("$"):
            res["resource_id"] = rest[1]
            inter, res["operation"], res["level"] = "operation", rest[2], "instance"
        elif n == 3 and _is_type(rest[2]):
            if method == "GET":
                inter = "search-compartment"
                res["compartment"] = f"{rtype}/{rest[1]}"
                res["resource_type"] = rest[2]
        elif n == 4 and rest[2] == "_history":
            res["resource_id"], res["version_id"] = rest[1], rest[3]
            inter = "vread" if method == "GET" else "unknown"

    res["interaction"] = inter
    if inter.startswith("search") or inter.startswith("history") or inter == "operation" or params:
        res["search_params"] = params
        res["search_param_names"] = list(dict.fromkeys(k for k, _ in params))  # unique, in order
    return res


def has_resource_segment(target: str) -> bool:
    """True if any path segment is a known FHIR resource type."""
    segs, _ = split_path(target or "/")
    return any(s in RESOURCE_TYPES for s in segs)
