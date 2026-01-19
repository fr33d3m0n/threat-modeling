#!/usr/bin/env python3
"""
Knowledge Base Query Tool for STRIDE Threat Modeling.

Provides CLI access to query CWE, CAPEC, ATT&CK, STRIDE, Cloud Services,
and LLM/AI threat mappings from the security knowledge base.

Usage:
    python query_kb.py --stride spoofing
    python query_kb.py --cwe CWE-89
    python query_kb.py --element process
    python query_kb.py --all-stride
    python query_kb.py --cloud aws --category compute
    python query_kb.py --llm LLM01
    python query_kb.py --all-llm
    python query_kb.py --ai-component llm_inference_service

Output: JSON format for easy integration with threat modeling workflow.
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Optional

import yaml

# Add parent directory to path for knowledge base import
sys.path.insert(0, str(Path(__file__).parent.parent))

from assets.knowledge import (
    SecurityKnowledgeBase,
    STRIDECategory,
    ElementType,
)


def query_stride_category(kb: SecurityKnowledgeBase, category: str) -> dict:
    """Query CWEs and CAPECs for a STRIDE category."""
    try:
        stride_cat = STRIDECategory(category.lower())
    except ValueError:
        return {"error": f"Invalid STRIDE category: {category}"}

    cwes = kb.get_cwes_for_stride(stride_cat)

    # Get STRIDE category info
    stride_data = kb._load_yaml("stride-library.yaml")
    stride_info = stride_data.get("stride_categories", {}).get(category.lower(), {})

    return {
        "category": category.upper(),
        "description": stride_info.get("description", ""),
        "security_property": stride_info.get("security_property", ""),
        "cwes": cwes,
        "threat_examples": stride_info.get("threat_examples", []),
        "typical_mitigations": stride_info.get("typical_mitigations", []),
    }


def query_cwe(kb: SecurityKnowledgeBase, cwe_id: str) -> dict:
    """Query details for a specific CWE."""
    cwe = kb.get_cwe_entry(cwe_id)
    if cwe is None:
        return {"error": f"CWE not found: {cwe_id}"}

    return {
        "id": cwe.id,
        "name": cwe.name,
        "description": cwe.description,
        "severity": cwe.severity,
        "stride_categories": cwe.stride_categories,
        "related_capec": cwe.related_capec,
        "mitigations": cwe.mitigations,
    }


def query_element_type(kb: SecurityKnowledgeBase, element: str) -> dict:
    """Query applicable STRIDE categories for an element type."""
    try:
        elem_type = ElementType(element.lower())
    except ValueError:
        return {"error": f"Invalid element type: {element}"}

    categories = kb.get_stride_for_element(elem_type)

    return {
        "element_type": element.upper(),
        "applicable_stride": [c.value for c in categories],
        "count": len(categories),
    }


def query_all_stride(kb: SecurityKnowledgeBase) -> dict:
    """Get all STRIDE categories with their mappings."""
    stride_data = kb._load_yaml("stride-library.yaml")
    categories = stride_data.get("stride_categories", {})

    result = {}
    for cat_name, cat_info in categories.items():
        result[cat_name.upper()] = {
            "code": cat_info.get("code", ""),
            "description": cat_info.get("description", ""),
            "security_property": cat_info.get("security_property", ""),
            "threat_examples": cat_info.get("threat_examples", [])[:3],  # Limit for brevity
        }

    return {"stride_categories": result}


# =============================================================================
# Cloud Services Query Functions
# =============================================================================

def load_cloud_services(kb_dir: Path) -> dict:
    """Load cloud services knowledge base."""
    cloud_file = kb_dir / "cloud-services.yaml"
    if not cloud_file.exists():
        return {}
    with open(cloud_file, 'r', encoding='utf-8') as f:
        return yaml.safe_load(f) or {}


def query_cloud_services(kb_dir: Path, provider: str, category: Optional[str] = None) -> dict:
    """Query cloud service threats for a provider and optional category."""
    cloud_data = load_cloud_services(kb_dir)
    if not cloud_data:
        return {"error": "Cloud services knowledge base not found"}

    provider = provider.lower()
    valid_providers = ["aws", "azure", "gcp", "alibaba", "tencent"]
    if provider not in valid_providers:
        return {"error": f"Invalid provider: {provider}. Valid: {valid_providers}"}

    # Get services for provider
    service_categories = cloud_data.get("service_categories", {})
    stride_by_category = cloud_data.get("stride_by_category", {})

    if category:
        category = category.lower()
        if category not in service_categories:
            return {"error": f"Invalid category: {category}. Valid: {list(service_categories.keys())}"}

        # Get specific category
        cat_services = service_categories.get(category, {}).get("services", {})
        cat_stride = stride_by_category.get(category, {})

        return {
            "provider": provider.upper(),
            "category": category,
            "services": cat_services.get(provider, []),
            "stride_threats": {
                stride_cat: {
                    "threats": [t for t in threats.get("threats", [])],
                }
                for stride_cat, threats in cat_stride.items()
            },
        }
    else:
        # Get all categories for provider
        all_services = {}
        for cat_name, cat_info in service_categories.items():
            services = cat_info.get("services", {}).get(provider, [])
            if services:
                all_services[cat_name] = services

        return {
            "provider": provider.upper(),
            "service_categories": all_services,
            "total_categories": len(all_services),
        }


def query_cloud_category_threats(kb_dir: Path, category: str) -> dict:
    """Query all threats for a cloud service category."""
    cloud_data = load_cloud_services(kb_dir)
    if not cloud_data:
        return {"error": "Cloud services knowledge base not found"}

    category = category.lower()
    stride_by_category = cloud_data.get("stride_by_category", {})

    if category not in stride_by_category:
        return {"error": f"Invalid category: {category}. Valid: {list(stride_by_category.keys())}"}

    cat_threats = stride_by_category.get(category, {})
    service_info = cloud_data.get("service_categories", {}).get(category, {})

    return {
        "category": category,
        "description": service_info.get("description", ""),
        "stride_threats": cat_threats,
    }


# =============================================================================
# LLM/AI Threats Query Functions
# =============================================================================

def load_llm_threats(kb_dir: Path) -> dict:
    """Load LLM threats knowledge base."""
    llm_file = kb_dir / "llm-threats.yaml"
    if not llm_file.exists():
        return {}
    with open(llm_file, 'r', encoding='utf-8') as f:
        return yaml.safe_load(f) or {}


def query_llm_threat(kb_dir: Path, llm_id: str) -> dict:
    """Query a specific OWASP LLM Top 10 threat."""
    llm_data = load_llm_threats(kb_dir)
    if not llm_data:
        return {"error": "LLM threats knowledge base not found"}

    llm_id = llm_id.upper()
    owasp_top10 = llm_data.get("owasp_llm_top10", {})

    if llm_id not in owasp_top10:
        valid_ids = list(owasp_top10.keys())
        return {"error": f"Invalid LLM ID: {llm_id}. Valid: {valid_ids}"}

    threat = owasp_top10[llm_id]
    return {
        "id": threat.get("id", llm_id),
        "name": threat.get("name", ""),
        "description": threat.get("description", ""),
        "stride_categories": threat.get("stride_categories", []),
        "attack_vectors": threat.get("attack_vectors", []),
        "impacts": threat.get("impacts", []),
        "mitigations": threat.get("mitigations", []),
        "cwes": threat.get("cwes", []),
        "capecs": threat.get("capecs", []),
        "atlas_techniques": threat.get("atlas_techniques", []),
        "severity": threat.get("severity", ""),
    }


def query_all_llm_threats(kb_dir: Path) -> dict:
    """Get all OWASP LLM Top 10 threats overview."""
    llm_data = load_llm_threats(kb_dir)
    if not llm_data:
        return {"error": "LLM threats knowledge base not found"}

    owasp_top10 = llm_data.get("owasp_llm_top10", {})

    result = {}
    for llm_id, threat in owasp_top10.items():
        result[llm_id] = {
            "name": threat.get("name", ""),
            "stride_categories": threat.get("stride_categories", []),
            "severity": threat.get("severity", ""),
            "attack_vectors": threat.get("attack_vectors", [])[:2],  # Limit for brevity
        }

    return {
        "owasp_llm_top10": result,
        "total": len(result),
    }


def query_ai_component(kb_dir: Path, component: str) -> dict:
    """Query threats for a specific AI component type."""
    llm_data = load_llm_threats(kb_dir)
    if not llm_data:
        return {"error": "LLM threats knowledge base not found"}

    component = component.lower()
    ai_components = llm_data.get("ai_components", {})

    if component not in ai_components:
        valid_components = list(ai_components.keys())
        return {"error": f"Invalid component: {component}. Valid: {valid_components}"}

    comp_info = ai_components[component]
    return {
        "component": component,
        "type": comp_info.get("type", ""),
        "description": comp_info.get("description", ""),
        "stride_threats": comp_info.get("stride_threats", {}),
    }


def query_ai_architecture(kb_dir: Path, pattern: str) -> dict:
    """Query threats for an AI architecture pattern."""
    llm_data = load_llm_threats(kb_dir)
    if not llm_data:
        return {"error": "LLM threats knowledge base not found"}

    pattern = pattern.lower()
    patterns = llm_data.get("architecture_patterns", {})

    if pattern not in patterns:
        valid_patterns = list(patterns.keys())
        return {"error": f"Invalid pattern: {pattern}. Valid: {valid_patterns}"}

    pattern_info = patterns[pattern]
    return {
        "pattern": pattern,
        "name": pattern_info.get("name", ""),
        "description": pattern_info.get("description", ""),
        "components": pattern_info.get("components", []),
        "trust_boundaries": pattern_info.get("trust_boundaries", []),
        "recommended_controls": pattern_info.get("recommended_controls", []),
    }


def main():
    parser = argparse.ArgumentParser(
        description="Query the security knowledge base for STRIDE threat modeling",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # Query a STRIDE category
    python query_kb.py --stride spoofing

    # Query a specific CWE
    python query_kb.py --cwe CWE-89

    # Query applicable STRIDE for element type
    python query_kb.py --element process

    # Get all STRIDE categories overview
    python query_kb.py --all-stride

    # Query cloud services (AWS, Azure, GCP, Alibaba, Tencent)
    python query_kb.py --cloud aws
    python query_kb.py --cloud aws --category compute

    # Query cloud service category threats
    python query_kb.py --cloud-category storage

    # Query OWASP LLM Top 10
    python query_kb.py --llm LLM01
    python query_kb.py --all-llm

    # Query AI component threats
    python query_kb.py --ai-component llm_inference_service
    python query_kb.py --ai-component rag_retrieval

    # Query AI architecture pattern threats
    python query_kb.py --ai-architecture rag_application
        """
    )

    # STRIDE arguments
    parser.add_argument(
        "--stride", "-s",
        choices=["spoofing", "tampering", "repudiation",
                 "information_disclosure", "denial_of_service",
                 "elevation_of_privilege"],
        help="Query by STRIDE category"
    )

    parser.add_argument(
        "--cwe", "-c",
        help="Query a specific CWE (e.g., CWE-89)"
    )

    parser.add_argument(
        "--element", "-e",
        choices=["process", "data_store", "data_flow", "external_interactor"],
        help="Query applicable STRIDE for element type"
    )

    parser.add_argument(
        "--all-stride", "-a",
        action="store_true",
        help="Get all STRIDE categories overview"
    )

    # Cloud arguments
    parser.add_argument(
        "--cloud",
        choices=["aws", "azure", "gcp", "alibaba", "tencent"],
        help="Query cloud provider services and threats"
    )

    parser.add_argument(
        "--category",
        choices=["compute", "storage", "database", "networking", "identity", "serverless"],
        help="Cloud service category (use with --cloud)"
    )

    parser.add_argument(
        "--cloud-category",
        choices=["compute", "storage", "database", "networking", "identity", "serverless"],
        help="Query all threats for a cloud service category"
    )

    # LLM/AI arguments
    parser.add_argument(
        "--llm",
        help="Query OWASP LLM Top 10 threat (e.g., LLM01)"
    )

    parser.add_argument(
        "--all-llm",
        action="store_true",
        help="Get all OWASP LLM Top 10 threats overview"
    )

    parser.add_argument(
        "--ai-component",
        choices=["llm_inference_service", "rag_retrieval", "vector_database",
                 "model_training_pipeline", "agent_tool_executor"],
        help="Query threats for an AI component type"
    )

    parser.add_argument(
        "--ai-architecture",
        choices=["basic_llm_api", "rag_application", "agent_system", "multi_model_pipeline"],
        help="Query threats for an AI architecture pattern"
    )

    # Output arguments
    parser.add_argument(
        "--pretty", "-p",
        action="store_true",
        help="Pretty-print JSON output"
    )

    args = parser.parse_args()

    # Initialize knowledge base
    kb_dir = Path(__file__).parent.parent / "assets" / "knowledge"
    kb = SecurityKnowledgeBase(kb_dir)

    # Execute query
    result = None

    # STRIDE queries
    if args.stride:
        result = query_stride_category(kb, args.stride)
    elif args.cwe:
        result = query_cwe(kb, args.cwe)
    elif args.element:
        result = query_element_type(kb, args.element)
    elif args.all_stride:
        result = query_all_stride(kb)
    # Cloud queries
    elif args.cloud:
        result = query_cloud_services(kb_dir, args.cloud, args.category)
    elif args.cloud_category:
        result = query_cloud_category_threats(kb_dir, args.cloud_category)
    # LLM/AI queries
    elif args.llm:
        result = query_llm_threat(kb_dir, args.llm)
    elif args.all_llm:
        result = query_all_llm_threats(kb_dir)
    elif args.ai_component:
        result = query_ai_component(kb_dir, args.ai_component)
    elif args.ai_architecture:
        result = query_ai_architecture(kb_dir, args.ai_architecture)
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
