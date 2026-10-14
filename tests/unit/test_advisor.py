"""Unit tests for Phase 6: Detection Tuning Advisor and Sigma rule generation."""

from purple_range.advisor import DetectionTuningAdvisor
from purple_range.emulation.catalog import TechniqueRegistry
from purple_range.models import (
    DetectionVerdict,
    EmulationStep,
    MitreTactic,
    MitreTechnique,
    PurpleMatrixHeatmap,
    TechniqueCoverageCell,
    TechniqueSeverity,
)


def test_mitre_reference_formatting() -> None:
    """Verify subtechnique and root technique URLs."""
    advisor = DetectionTuningAdvisor()
    assert (
        advisor.format_mitre_reference("T1087.001")
        == "https://attack.mitre.org/techniques/T1087/001/"
    )
    assert advisor.format_mitre_reference("T1046") == "https://attack.mitre.org/techniques/T1046/"


def test_severity_level_mapping() -> None:
    """Verify severity to sigma level mapping."""
    advisor = DetectionTuningAdvisor()
    assert advisor.map_severity_level(TechniqueSeverity.LOW) == "low"
    assert advisor.map_severity_level(TechniqueSeverity.HIGH) == "high"
    assert advisor.map_severity_level(TechniqueSeverity.CRITICAL) == "critical"
    assert advisor.map_severity_level(TechniqueSeverity.INFORMATIONAL) == "informational"


def test_recommend_rules_for_builtins() -> None:
    """Verify rule generation for core MITRE ATT&CK techniques."""
    advisor = DetectionTuningAdvisor()
    registry = TechniqueRegistry()

    # 1. T1087.001 Discovery
    tech_1087 = registry.get("T1087.001")
    assert tech_1087 is not None
    rule_1087 = advisor.recommend_rule(tech_1087)
    assert "T1087.001" in rule_1087.title
    assert "attack.discovery" in rule_1087.tags
    assert rule_1087.logsource["product"] == "linux"

    # 2. T1046 Network Discovery
    tech_1046 = registry.get("T1046")
    assert tech_1046 is not None
    rule_1046 = advisor.recommend_rule(tech_1046)
    assert "Network Service Discovery" in rule_1046.title

    # 3. T1003.008 Credential Access
    tech_1003 = registry.get("T1003.008")
    assert tech_1003 is not None
    rule_1003 = advisor.recommend_rule(tech_1003)
    assert "Credential Access" in rule_1003.title
    assert rule_1003.level == "high"

    # 4. T1547.001 Persistence
    tech_1547 = registry.get("T1547.001")
    assert tech_1547 is not None
    rule_1547 = advisor.recommend_rule(tech_1547)
    assert "Persistence" in rule_1547.title

    # 5. T1548.003 PrivEsc
    tech_1548 = registry.get("T1548.003")
    assert tech_1548 is not None
    rule_1548 = advisor.recommend_rule(tech_1548)
    assert "Privilege Escalation" in rule_1548.title

    # 6. T1070.004 Defense Evasion
    tech_1070 = registry.get("T1070.004")
    assert tech_1070 is not None
    rule_1070 = advisor.recommend_rule(tech_1070)
    assert "Defense Evasion" in rule_1070.title


def test_fallback_custom_technique_rule_generation() -> None:
    """Verify dynamic rule synthesis for custom or unknown technique."""
    advisor = DetectionTuningAdvisor()
    custom_tech = MitreTechnique(
        technique_id="T1555.003",
        name="Credentials from Web Browsers",
        tactic=MitreTactic.CREDENTIAL_ACCESS,
        command_template="sqlite3 /tmp/Login_Data 'SELECT * FROM logins;'",
        description="Extracting stored passwords from browser database",
    )
    step = EmulationStep(
        campaign_id="camp-custom",
        technique_id="T1555.003",
        technique_name=custom_tech.name,
        tactic=custom_tech.tactic,
        command_executed="sqlite3 /tmp/Login_Data 'SELECT * FROM logins;'",
    )
    rule = advisor.recommend_rule(technique=custom_tech, step=step)
    assert "T1555.003" in rule.title
    assert "attack.credential-access" in rule.tags
    assert rule.detection["selection"]["Image|endswith"] == "/sqlite3"


def test_recommend_for_heatmap_and_export_bundle() -> None:
    """Verify batch recommendation from heatmap blind spots and YAML bundling."""
    advisor = DetectionTuningAdvisor()
    registry = TechniqueRegistry()

    cell_missed = TechniqueCoverageCell(
        technique_id="T1087.001",
        technique_name="Local Account Discovery",
        tactic=MitreTactic.DISCOVERY,
        verdict=DetectionVerdict.MISSED,
    )
    heatmap = PurpleMatrixHeatmap(
        total_techniques=1,
        missed_count=1,
        blind_spots=["T1087.001"],
        cells=[cell_missed],
    )

    rules = advisor.recommend_for_heatmap(heatmap, registry)
    assert len(rules) == 1
    assert "T1087.001" in rules[0].title

    yaml_bundle = advisor.export_rules_bundle(rules)
    assert "title: Suspicious Local Account Discovery" in yaml_bundle
    assert "attack.t1087.001" in yaml_bundle

    # Empty rules bundle
    assert advisor.export_rules_bundle([]) == ""
