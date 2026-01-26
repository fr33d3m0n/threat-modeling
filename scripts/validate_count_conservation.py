#!/usr/bin/env python3
"""
Count Conservation Validation Script
=====================================
Version: 2.1.0
Date: 2026-01-26

Validates data integrity in STRIDE threat modeling workflow:
1. CP1: P5 → P6 threat count conservation
2. CP2: VR threat_refs completeness
3. CP3: P6 → Reports VR count conservation (NEW)
4. ID format compliance

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


# ============================================================
# CP3: P6 → Reports VR Count Conservation
# ============================================================

# Report files that should contain VR entries
FINAL_REPORTS = [
    'RISK-INVENTORY',
    'RISK-ASSESSMENT-REPORT',
    'MITIGATION-MEASURES',
    'PENETRATION-TEST-PLAN',
]


def extract_vr_ids_from_p6(p6_content: str) -> List[str]:
    """
    Extract all unique VR IDs from P6-RISK-VALIDATION.md.

    Args:
        p6_content: Full text content of P6-RISK-VALIDATION.md

    Returns:
        List of unique VR IDs in format VR-XXX (e.g., ['VR-001', 'VR-002', ...])
    """
    vr_pattern = re.compile(r'VR-\d{3}')
    matches = vr_pattern.findall(p6_content)
    return sorted(list(set(matches)))


def extract_report_vr_counts(report_dir: Path) -> Dict[str, Dict[str, any]]:
    """
    Extract VR counts from all four final reports.

    Args:
        report_dir: Path to Risk_Assessment_Report directory

    Returns:
        Dict with report name as key containing file, vr_ids, count, found
    """
    report_counts = {}
    vr_pattern = re.compile(r'VR-\d{3}')

    for report_name in FINAL_REPORTS:
        report_info = {
            'file': None,
            'vr_ids': [],
            'count': 0,
            'found': False
        }

        # Search for report file (case-insensitive, with project prefix)
        for f in report_dir.glob('**/*.md'):
            if report_name.upper() in f.name.upper():
                report_info['file'] = f
                report_info['found'] = True
                try:
                    content = f.read_text(encoding='utf-8')
                    matches = vr_pattern.findall(content)
                    report_info['vr_ids'] = sorted(list(set(matches)))
                    report_info['count'] = len(report_info['vr_ids'])
                except Exception as e:
                    report_info['error'] = str(e)
                break

        report_counts[report_name] = report_info

    return report_counts


def validate_cp3_report_conservation(
    p6_vr_count: int,
    p6_vr_ids: List[str],
    report_counts: Dict[str, Dict[str, any]]
) -> ValidationResult:
    """
    Validate CP3: P6 VR count equals each report's VR count.

    Args:
        p6_vr_count: Total unique VR IDs in P6
        p6_vr_ids: List of VR IDs from P6
        report_counts: Output from extract_report_vr_counts()

    Returns:
        ValidationResult with PASS/FAIL/WARN status
    """
    discrepancies = []
    missing_reports = []
    all_match = True

    for report_name, info in report_counts.items():
        if not info['found']:
            missing_reports.append(report_name)
            continue

        if info['count'] != p6_vr_count:
            all_match = False
            # Find which VRs are missing or extra
            p6_set = set(p6_vr_ids)
            report_set = set(info['vr_ids'])
            missing_in_report = p6_set - report_set
            extra_in_report = report_set - p6_set

            discrepancies.append({
                'report': report_name,
                'expected': p6_vr_count,
                'actual': info['count'],
                'missing': list(missing_in_report)[:5] if missing_in_report else [],
                'extra': list(extra_in_report)[:5] if extra_in_report else []
            })

    details = {
        'p6_vr_count': p6_vr_count,
        'p6_vr_ids': p6_vr_ids[:10] if len(p6_vr_ids) > 10 else p6_vr_ids,
        'reports_checked': len(FINAL_REPORTS),
        'reports_found': len(FINAL_REPORTS) - len(missing_reports),
        'per_report_counts': {
            name: info['count'] for name, info in report_counts.items() if info['found']
        }
    }

    if missing_reports:
        details['missing_reports'] = missing_reports

    if discrepancies:
        details['discrepancies'] = discrepancies

    # Determine status
    if not p6_vr_ids:
        return ValidationResult(
            ValidationStatus.WARN,
            "No VR IDs found in P6 - skipping CP3 validation",
            details
        )

    if missing_reports and len(missing_reports) == len(FINAL_REPORTS):
        return ValidationResult(
            ValidationStatus.WARN,
            "No final reports found - skipping CP3 validation",
            details
        )

    if discrepancies:
        mismatch_reports = [d['report'] for d in discrepancies]
        return ValidationResult(
            ValidationStatus.FAIL,
            f"CP3 FAIL: VR count mismatch in {mismatch_reports}. P6 has {p6_vr_count} VRs.",
            details
        )

    if missing_reports:
        return ValidationResult(
            ValidationStatus.WARN,
            f"CP3 PARTIAL: {len(FINAL_REPORTS) - len(missing_reports)} reports match, "
            f"but missing: {missing_reports}",
            details
        )

    return ValidationResult(
        ValidationStatus.PASS,
        f"CP3 PASS: All {len(FINAL_REPORTS)} reports have {p6_vr_count} VRs matching P6",
        details
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
    # CP1: P5 → P6 threat count conservation
    results['cp1_count_conservation'] = validate_count_conservation(
        p5_total, consolidated, excluded
    )

    # CP2: VR threat_refs completeness
    results['cp2_vr_threat_refs'] = validate_vr_threat_refs(vr_mapping)

    # CP3: P6 → Reports VR count conservation (NEW)
    p6_vr_ids = extract_vr_ids_from_p6(p6_content)
    report_vr_counts = extract_report_vr_counts(report_path)
    results['cp3_report_conservation'] = validate_cp3_report_conservation(
        len(p6_vr_ids), p6_vr_ids, report_vr_counts
    )

    # ID format validations
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
    import argparse

    parser = argparse.ArgumentParser(
        description='Count Conservation Validation Script',
        epilog='''
Validates data integrity in STRIDE threat modeling workflow:
1. P5 → P6 threat count conservation
2. VR threat_refs completeness
3. ID format compliance

Examples:
    python validate_count_conservation.py ./Risk_Assessment_Report/
    python validate_count_conservation.py ./project/Risk_Assessment_Report/
''',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument(
        'report_dir',
        help='Path to the Risk_Assessment_Report directory containing phase documents'
    )

    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose output with detailed validation information'
    )

    args = parser.parse_args()

    if not os.path.isdir(args.report_dir):
        print(f"Error: {args.report_dir} is not a directory")
        sys.exit(1)

    results = run_validation(args.report_dir)
    exit_code = print_report(results)
    sys.exit(exit_code)


if __name__ == '__main__':
    main()
