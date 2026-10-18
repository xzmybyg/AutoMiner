from app.schemas import JobInput
from app.test_catalog import catalog


def test_catalog_categories_have_unique_ids_and_explicit_coverage():
    categories = catalog()["categories"]
    assert len(categories) == 18
    assert len({entry["id"] for entry in categories}) == 18
    assert all(
        set(entry) == {"id", "name", "description", "status"} for entry in categories
    )
    assert {entry["status"] for entry in categories} <= {
        "available",
        "partial",
        "planned",
    }
    assert {entry["id"] for entry in categories if entry["status"] == "partial"} == {
        "configuration",
        "information_disclosure",
        "access_control",
        "injection",
        "xss",
        "csrf",
        "ssrf",
        "xxe",
        "file",
        "deserialization",
        "authentication",
        "supply_chain",
        "business_logic",
        "race_condition",
        "memory_safety",
        "denial_of_service",
        "cryptography",
        "other_web",
    }


def test_catalog_templates_match_execution_whitelist_without_enabling_planned_tests():
    data = catalog()
    templates = data["templates"]
    assert {entry["id"] for entry in templates} == {"baseline", "role_compare", "both", "injection_errors", "xss_passive", "csrf_passive", "ssrf_passive", "xxe_passive", "file_passive", "deserialization_passive", "auth_session_passive", "disclosure_passive", "configuration_passive", "crypto_passive", "supply_chain_passive", "business_logic_review", "other_web_passive", "race_condition_review", "memory_safety_passive", "dos_passive", "cors_verify", "access_verify", "sql_error_verify", "xss_reflection_verify", "redirect_verify"}
    assert len(templates) == 25
    whitelist = JobInput.model_json_schema()["properties"]["endpoint_test_types"][
        "additionalProperties"
    ]["enum"]
    assert {entry["id"] for entry in templates} == set(whitelist)
    categories = {entry["id"]: entry for entry in data["categories"]}
    for template in templates:
        assert set(template) == {"id", "title", "description", "category_ids", "execution", "requests_per_endpoint", "risk"}
        assert all(
            categories[ident]["status"] != "planned"
            for ident in template["category_ids"]
        )


def test_active_templates_declare_fixed_request_costs_and_low_risk():
    templates = {t["id"]: t for t in catalog()["templates"]}
    assert templates["cors_verify"]["requests_per_endpoint"] == 3
    assert templates["access_verify"]["requests_per_endpoint"] == 2
    for ident in ("cors_verify", "access_verify"):
        assert templates[ident]["execution"] == "active_verification"
        assert templates[ident]["risk"] == "low"


def test_catalog_returns_independent_snapshots():
    first = catalog()
    first["categories"][0]["status"] = "available"
    first["templates"][0]["category_ids"].clear()
    second = catalog()
    assert second["categories"][0]["status"] == "partial"
    assert second["templates"][0]["category_ids"]
