# Code-First Deep Threat Modeling Workflow | Version 2.1.0 | https://github.com/fr33d3m0n/skill-threat-modeling | License: BSD-3-Clause | Welcome to cite but please retain all sources and declarations

#!/usr/bin/env python3
"""
STRIDE per Interaction Matrix Calculator.

Calculates applicable STRIDE threat categories based on DFD element types
following Microsoft Threat Modeling Tool methodology.

STRIDE per Interaction Matrix:
    Target Type          | Applicable Categories
    ---------------------|----------------------
    Process              | S, T, R, I, D, E (all)
    Data Store           | T, R, I, D
    Data Flow            | T, I, D
    External Interactor  | S, R (as source)

Usage:
    python stride_matrix.py --element process
    python stride_matrix.py --interaction process data_store
    python stride_matrix.py --generate-id S P1 001

Output: JSON format for integration with threat modeling workflow.
"""

import argparse
import json
import sys
from typing import List, Dict, Tuple


# STRIDE per Interaction Matrix
# Based on Microsoft Threat Modeling Tool methodology
STRIDE_MATRIX = {
    "process": ["S", "T", "R", "I", "D", "E"],
    "data_store": ["T", "R", "I", "D"],
    "data_flow": ["T", "I", "D"],
    "external_interactor": ["S", "R"],  # As source
}

# STRIDE category details
STRIDE_CATEGORIES = {
    "S": {
        "code": "S",
        "name": "Spoofing",
        "full_name": "Spoofing Identity",
        "security_property": "Authentication",
        "question": "Can an attacker pretend to be someone or something else?",
    },
    "T": {
        "code": "T",
        "name": "Tampering",
        "full_name": "Tampering with Data",
        "security_property": "Integrity",
        "question": "Can an attacker modify data in transit or at rest?",
    },
    "R": {
        "code": "R",
        "name": "Repudiation",
        "full_name": "Repudiation",
        "security_property": "Non-repudiation",
        "question": "Can an attacker deny performing an action?",
    },
    "I": {
        "code": "I",
        "name": "Information Disclosure",
        "full_name": "Information Disclosure",
        "security_property": "Confidentiality",
        "question": "Can an attacker access data they shouldn't?",
    },
    "D": {
        "code": "D",
        "name": "Denial of Service",
        "full_name": "Denial of Service",
        "security_property": "Availability",
        "question": "Can an attacker prevent legitimate users from accessing the system?",
    },
    "E": {
        "code": "E",
        "name": "Elevation of Privilege",
        "full_name": "Elevation of Privilege",
        "security_property": "Authorization",
        "question": "Can an attacker gain more privileges than intended?",
    },
}


def get_applicable_stride(element_type: str) -> Dict:
    """Get applicable STRIDE categories for an element type."""
    element = element_type.lower().replace("-", "_").replace(" ", "_")

    if element not in STRIDE_MATRIX:
        return {"error": f"Invalid element type: {element_type}"}

    codes = STRIDE_MATRIX[element]

    return {
        "element_type": element.upper(),
        "applicable_stride": codes,
        "categories": [
            {
                "code": code,
                "name": STRIDE_CATEGORIES[code]["name"],
                "security_property": STRIDE_CATEGORIES[code]["security_property"],
                "question": STRIDE_CATEGORIES[code]["question"],
            }
            for code in codes
        ],
        "count": len(codes),
    }


def analyze_interaction(source: str, target: str) -> Dict:
    """Analyze STRIDE threats for a source-target interaction."""
    source = source.lower().replace("-", "_").replace(" ", "_")
    target = target.lower().replace("-", "_").replace(" ", "_")

    if source not in STRIDE_MATRIX:
        return {"error": f"Invalid source type: {source}"}
    if target not in STRIDE_MATRIX:
        return {"error": f"Invalid target type: {target}"}

    # Target determines base threats
    target_threats = set(STRIDE_MATRIX[target])

    # External interactor as source adds S, R
    if source == "external_interactor":
        target_threats.update(["S", "R"])

    threats = sorted(target_threats, key=lambda x: "STRIDE".index(x))

    return {
        "source": source.upper(),
        "target": target.upper(),
        "applicable_stride": threats,
        "categories": [
            {
                "code": code,
                "name": STRIDE_CATEGORIES[code]["name"],
                "question": STRIDE_CATEGORIES[code]["question"],
            }
            for code in threats
        ],
        "count": len(threats),
    }


def generate_threat_id(stride_code: str, element_id: str, sequence: str) -> Dict:
    """Generate a threat ID in TMT format."""
    stride_code = stride_code.upper()

    if stride_code not in STRIDE_CATEGORIES:
        return {"error": f"Invalid STRIDE code: {stride_code}"}

    threat_id = f"T-{stride_code}-{element_id}-{sequence.zfill(3)}"

    return {
        "threat_id": threat_id,
        "stride_code": stride_code,
        "stride_name": STRIDE_CATEGORIES[stride_code]["name"],
        "element_id": element_id,
        "sequence": sequence,
    }


def show_matrix() -> Dict:
    """Display the full STRIDE per Interaction matrix."""
    return {
        "stride_matrix": {
            element.upper(): codes
            for element, codes in STRIDE_MATRIX.items()
        },
        "stride_categories": {
            code: {
                "name": info["name"],
                "security_property": info["security_property"],
            }
            for code, info in STRIDE_CATEGORIES.items()
        },
    }


def main():
    parser = argparse.ArgumentParser(
        description="STRIDE per Interaction matrix calculator for threat modeling",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # Get applicable STRIDE for an element type
    python stride_matrix.py --element process
    python stride_matrix.py --element data_store

    # Analyze a source-target interaction
    python stride_matrix.py --interaction external_interactor process

    # Generate a threat ID
    python stride_matrix.py --generate-id S P1 001

    # Show full STRIDE matrix
    python stride_matrix.py --show-matrix
        """
    )

    parser.add_argument(
        "--element", "-e",
        choices=["process", "data_store", "data_flow", "external_interactor"],
        help="Get applicable STRIDE for element type"
    )

    parser.add_argument(
        "--interaction", "-i",
        nargs=2,
        metavar=("SOURCE", "TARGET"),
        help="Analyze source-target interaction"
    )

    parser.add_argument(
        "--generate-id", "-g",
        nargs=3,
        metavar=("STRIDE", "ELEMENT", "SEQ"),
        help="Generate threat ID (e.g., S P1 001)"
    )

    parser.add_argument(
        "--show-matrix", "-m",
        action="store_true",
        help="Display full STRIDE matrix"
    )

    parser.add_argument(
        "--pretty", "-p",
        action="store_true",
        help="Pretty-print JSON output"
    )

    args = parser.parse_args()

    # Execute query
    result = None

    if args.element:
        result = get_applicable_stride(args.element)
    elif args.interaction:
        result = analyze_interaction(args.interaction[0], args.interaction[1])
    elif args.generate_id:
        result = generate_threat_id(*args.generate_id)
    elif args.show_matrix:
        result = show_matrix()
    else:
        parser.print_help()
        sys.exit(1)

    # Output JSON
    if args.pretty:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(json.dumps(result, ensure_ascii=False))


if __name__ == "__main__":
    main()
