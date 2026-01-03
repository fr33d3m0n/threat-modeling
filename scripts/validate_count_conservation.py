# Code-First Deep Threat Modeling Workflow | Version 2.1.0 | https://github.com/fr33d3m0n/skill-threat-modeling | License: BSD-3-Clause | Welcome to cite but please retain all sources and declarations

#!/usr/bin/env python3
"""
Count Conservation Validation Script
=====================================
Version: 2.1.0
Date: 2026-01-03

Validates data integrity in STRIDE threat modeling workflow:
1. P5 → P6 threat count conservation
2. VR threat_refs completeness
3. ID format compliance

Usage:
    python validate_count_conservation.py <report_dir>

Example:
    python validate_count_conservation.py ./Risk_Assessment_Report/
"""

import re
import sys
import os
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass
from enum import Enum


class ValidationStatus(Enum):
    PASS = "✅ PASS"
    FAIL = "❌ FAIL"
    WARN = "⚠️ WARN"


@dataclass
class ValidationResult:
    status: ValidationStatus
    message: str
    details: Optional[Dict] = None


# ============================================================
# ID Format Patterns
# ============================================================

PATTERNS = {
    'finding': re.compile(r'^F-P[1-8]-\d{3}$'),
    'threat': re.compile(r'^T-[STRIDE]-[A-Z]+\d+-\d{3}$'),
    'validated_risk': re.compile(r'^VR-\d{3}$'),
    'mitigation': re.compile(r'^M-\d{3}$'),
    # Forbidden formats
    'forbidden_risk': re.compile(r'^RISK-\d+$'),
    'forbidden_threat': re.compile(r'^T-[STRIDE]-[A-Z]+-\d{3}$'),  # e.g., T-E-RCE-001
}


def extract_threat_ids_from_p5(p5_content: str) -> Tuple[int, List[str]]:
    """Extract all threat IDs from P5-STRIDE-THREATS.md"""
    threats = []

    # Look for threat IDs in format T-X-XXX-NNN
    threat_pattern = re.compile(r'T-[STRIDE]-[A-Z]+\d+-\d{3}')
    matches = threat_pattern.findall(p5_content)
    threats = list(set(matches))  # Unique threats

    # Try to find total count from summary section
    total_pattern = re.compile(r'(?:total|总数|总计)[\s:]*(\d+)', re.IGNORECASE)
    total_match = total_pattern.search(p5_content)

    if total_match:
        declared_total = int(total_match.group(1))
    else:
        declared_total = len(threats)

    return declared_total, threats


def extract_vr_threat_refs_from_p6(p6_content: str) -> Dict[str, List[str]]:
    """Extract VR IDs and their threat_refs from P6 output"""
    vr_mapping = {}

    # Pattern to find VR entries with threat_refs
    # Look for patterns like: VR-001 ... threat_refs: [T-xxx, T-xxx]
    vr_pattern = re.compile(r'VR-\d{3}')
    threat_ref_pattern = re.compile(r'threat_refs?\s*[:\|]\s*\[?([^\]\n]+)\]?', re.IGNORECASE)

    # Split by VR entries and extract refs
    lines = p6_content.split('\n')
    current_vr = None

    for line in lines:
        vr_match = vr_pattern.search(line)
        if vr_match:
            current_vr = vr_match.group()
            if current_vr not in vr_mapping:
                vr_mapping[current_vr] = []

        ref_match = threat_ref_pattern.search(line)
        if ref_match and current_vr:
            refs = ref_match.group(1)
            # Parse comma-separated threat IDs
            threat_ids = re.findall(r'T-[STRIDE]-[A-Z]+\d+-\d{3}', refs)
            vr_mapping[current_vr].extend(threat_ids)

    # Deduplicate
    for vr_id in vr_mapping:
        vr_mapping[vr_id] = list(set(vr_mapping[vr_id]))

    return vr_mapping


def extract_excluded_threats_from_p6(p6_content: str) -> List[str]:
    """Extract excluded threat IDs from P6 threat_disposition"""
    excluded = []

    # Look for excluded section
    excluded_section = re.search(
        r'excluded_threats?.*?(?=\n#{2,}|\Z)',
        p6_content,
        re.IGNORECASE | re.DOTALL
    )

    if excluded_section:
        threat_ids = re.findall(r'T-[STRIDE]-[A-Z]+\d+-\d{3}', excluded_section.group())
        excluded = list(set(threat_ids))

    return excluded


def validate_count_conservation(
    p5_total: int,
    consolidated: List[str],
    excluded: List[str]
) -> ValidationResult:
    """Validate that P5.total = consolidated + excluded"""
    consolidated_count = len(consolidated)
    excluded_count = len(excluded)
    total_accounted = consolidated_count + excluded_count

    details = {
        'p5_total': p5_total,
        'consolidated': consolidated_count,
        'excluded': excluded_count,
        'accounted': total_accounted,
        'formula': f"{consolidated_count} + {excluded_count} = {total_accounted}"
    }

    if total_accounted == p5_total:
        return ValidationResult(
            ValidationStatus.PASS,
            f"Count conservation verified: {consolidated_count} + {excluded_count} = {p5_total}",
            details
        )
    elif total_accounted < p5_total:
        missing = p5_total - total_accounted
        return ValidationResult(
            ValidationStatus.FAIL,
            f"Missing {missing} threats! Expected {p5_total}, got {total_accounted}",
            details
        )
    else:
        excess = total_accounted - p5_total
        return ValidationResult(
            ValidationStatus.WARN,
            f"Excess {excess} threats counted. Expected {p5_total}, got {total_accounted}",
            details
        )


def validate_vr_threat_refs(vr_mapping: Dict[str, List[str]]) -> ValidationResult:
    """Validate that every VR has at least one threat_ref"""
    empty_vrs = [vr for vr, refs in vr_mapping.items() if not refs]

    if not vr_mapping:
        return ValidationResult(
            ValidationStatus.WARN,
            "No ValidatedRisk entries found",
            {'vr_count': 0}
        )

    if empty_vrs:
        return ValidationResult(
            ValidationStatus.FAIL,
            f"{len(empty_vrs)} VRs missing threat_refs: {empty_vrs}",
            {'empty_vrs': empty_vrs, 'total_vrs': len(vr_mapping)}
        )

    return ValidationResult(
        ValidationStatus.PASS,
        f"All {len(vr_mapping)} VRs have threat_refs",
        {'vr_count': len(vr_mapping)}
    )


def validate_id_formats(content: str) -> ValidationResult:
    """Check for forbidden ID formats"""
    issues = []

    # Check for RISK-xxx (should be VR-xxx)
    risk_ids = re.findall(r'\bRISK-\d+\b', content)
    if risk_ids:
        issues.append(f"Found forbidden RISK-xxx IDs: {list(set(risk_ids))[:5]}")

    # Check for T-X-CATEGORY-xxx (should keep ElementID)
    bad_threat_ids = re.findall(r'\bT-[STRIDE]-[A-Z]{3,}-\d{3}\b', content)
    # Filter out valid ElementID patterns
    truly_bad = [t for t in bad_threat_ids if not re.match(r'T-[STRIDE]-[A-Z]+\d+-\d{3}', t)]
    if truly_bad:
        issues.append(f"Found non-compliant threat IDs: {list(set(truly_bad))[:5]}")

    if issues:
        return ValidationResult(
            ValidationStatus.FAIL,
            " | ".join(issues),
            {'issues': issues}
        )

    return ValidationResult(
        ValidationStatus.PASS,
        "All ID formats compliant",
        {}
    )


def run_validation(report_dir: str) -> Dict[str, ValidationResult]:
    """Run all validations on a report directory"""
    results = {}
    report_path = Path(report_dir)

    # Find P5 and P6 files
    p5_file = None
    p6_file = None
    risk_inventory = None

    for f in report_path.glob('**/*.md'):
        name = f.name.upper()
        if 'P5' in name or 'STRIDE-THREAT' in name:
            p5_file = f
        elif 'P6' in name or 'RISK-VALIDATION' in name:
            p6_file = f
        elif 'RISK-INVENTORY' in name:
            risk_inventory = f

    # Read files
    p5_content = p5_file.read_text() if p5_file else ""
    p6_content = p6_file.read_text() if p6_file else ""
    inventory_content = risk_inventory.read_text() if risk_inventory else ""

    # Extract data
    p5_total, p5_threats = extract_threat_ids_from_p5(p5_content)
    vr_mapping = extract_vr_threat_refs_from_p6(p6_content)
    excluded = extract_excluded_threats_from_p6(p6_content)

    # Consolidate all threat_refs from VRs
    consolidated = []
    for refs in vr_mapping.values():
        consolidated.extend(refs)
    consolidated = list(set(consolidated))

    # Run validations
    results['count_conservation'] = validate_count_conservation(
        p5_total, consolidated, excluded
    )
    results['vr_threat_refs'] = validate_vr_threat_refs(vr_mapping)
    results['id_format_p6'] = validate_id_formats(p6_content)
    results['id_format_inventory'] = validate_id_formats(inventory_content)

    return results


def print_report(results: Dict[str, ValidationResult]):
    """Print validation report"""
    print("\n" + "="*60)
    print("  COUNT CONSERVATION VALIDATION REPORT")
    print("="*60 + "\n")

    all_passed = True
    for name, result in results.items():
        icon = result.status.value
        print(f"{icon} {name}")
        print(f"   {result.message}")
        if result.details:
            for k, v in result.details.items():
                print(f"   • {k}: {v}")
        print()

        if result.status == ValidationStatus.FAIL:
            all_passed = False

    print("="*60)
    if all_passed:
        print("  ✅ ALL VALIDATIONS PASSED")
    else:
        print("  ❌ SOME VALIDATIONS FAILED")
    print("="*60 + "\n")

    return 0 if all_passed else 1


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    report_dir = sys.argv[1]

    if not os.path.isdir(report_dir):
        print(f"Error: {report_dir} is not a directory")
        sys.exit(1)

    results = run_validation(report_dir)
    exit_code = print_report(results)
    sys.exit(exit_code)


if __name__ == '__main__':
    main()
