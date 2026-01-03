# Code-First Deep Threat Modeling Workflow | Version 2.1.0 | https://github.com/fr33d3m0n/skill-threat-modeling | License: BSD-3-Clause | Welcome to cite but please retain all sources and declarations

"""
Security Knowledge Base Module
Provides access to CWE, CAPEC, ATT&CK, OWASP, and STRIDE mapping data.
"""

from pathlib import Path
from typing import Dict, List, Optional, Set, Any
from dataclasses import dataclass, field
from enum import Enum
import yaml
import logging
from functools import lru_cache

logger = logging.getLogger(__name__)


class STRIDECategory(Enum):
    """STRIDE threat categories."""
    SPOOFING = "spoofing"
    TAMPERING = "tampering"
    REPUDIATION = "repudiation"
    INFORMATION_DISCLOSURE = "information_disclosure"
    DENIAL_OF_SERVICE = "denial_of_service"
    ELEVATION_OF_PRIVILEGE = "elevation_of_privilege"


class ElementType(Enum):
    """DFD element types."""
    PROCESS = "process"
    DATA_STORE = "data_store"
    DATA_FLOW = "data_flow"
    EXTERNAL_INTERACTOR = "external_interactor"


@dataclass
class CWEReference:
    """CWE weakness reference."""
    id: str
    name: str
    description: str = ""
    severity: str = "medium"
    stride_categories: List[str] = field(default_factory=list)
    related_capec: List[str] = field(default_factory=list)
    mitigations: List[str] = field(default_factory=list)


@dataclass
class CAPECReference:
    """CAPEC attack pattern reference."""
    id: str
    name: str
    description: str = ""
    likelihood: str = ""
    severity: str = ""
    stride_categories: List[str] = field(default_factory=list)
    related_cwe: List[str] = field(default_factory=list)
    attack_mappings: List[Dict] = field(default_factory=list)
    mitigations: List[str] = field(default_factory=list)


@dataclass
class STRIDECategoryInfo:
    """STRIDE category information."""
    name: str
    code: str
    description: str
    security_property: str
    threat_examples: List[str] = field(default_factory=list)
    applicable_targets: List[str] = field(default_factory=list)
    typical_mitigations: List[str] = field(default_factory=list)
    primary_cwes: List[str] = field(default_factory=list)
    primary_capec: List[str] = field(default_factory=list)


@dataclass
class OWASPCategory:
    """OWASP Top 10 category reference."""
    id: str
    name: str
    description: str
    cwes: List[str] = field(default_factory=list)
    stride_categories: List[str] = field(default_factory=list)


@dataclass
class SecurityMapping:
    """Security framework mapping for a threat."""
    cwes: List[str] = field(default_factory=list)
    capecs: List[str] = field(default_factory=list)
    mitre_attack: List[str] = field(default_factory=list)
    owasp: List[str] = field(default_factory=list)


@dataclass
class KnowledgeBaseMetadata:
    """Metadata for knowledge base files."""
    version: str
    source: str = ""
    last_updated: str = ""
    description: str = ""


class SecurityKnowledgeBase:
    """
    Security Knowledge Base loader and accessor.

    Provides unified access to CWE, CAPEC, ATT&CK, OWASP, and STRIDE mapping data
    loaded from external YAML files.

    Example usage:
        kb = SecurityKnowledgeBase()

        # Get CWEs for a STRIDE category
        cwes = kb.get_cwes_for_stride(STRIDECategory.SPOOFING)

        # Get CAPEC patterns for a CWE
        capecs = kb.get_capecs_for_cwe("CWE-89")

        # Get STRIDE categories for an element type
        categories = kb.get_stride_for_element(ElementType.PROCESS)
    """

    def __init__(self, knowledge_dir: Optional[Path] = None):
        """
        Initialize the knowledge base.

        Args:
            knowledge_dir: Path to knowledge base directory.
                          Defaults to the 'knowledge' directory in the same location as this module.
        """
        if knowledge_dir is None:
            knowledge_dir = Path(__file__).parent

        self.knowledge_dir = Path(knowledge_dir)
        self._cache: Dict[str, dict] = {}
        self._metadata: Dict[str, KnowledgeBaseMetadata] = {}

        # Validate knowledge base on init
        self._validate_knowledge_base()

    def _validate_knowledge_base(self) -> None:
        """Validate that all required knowledge base files exist."""
        required_files = [
            "cwe-mappings.yaml",
            "capec-mappings.yaml",
            "stride-library.yaml",
            "comprehensive-mappings.yaml",
        ]

        missing_files = []
        for f in required_files:
            if not (self.knowledge_dir / f).exists():
                missing_files.append(f)

        if missing_files:
            logger.warning(f"Missing knowledge base files: {missing_files}")

    @lru_cache(maxsize=10)
    def _load_yaml(self, filename: str) -> dict:
        """
        Load a YAML file from the knowledge directory.

        Args:
            filename: Name of the YAML file to load

        Returns:
            Parsed YAML content as dictionary
        """
        path = self.knowledge_dir / filename

        if not path.exists():
            logger.error(f"Knowledge base file not found: {path}")
            return {}

        try:
            with open(path, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)

            # Extract and store metadata
            if 'metadata' in data:
                meta = data['metadata']
                self._metadata[filename] = KnowledgeBaseMetadata(
                    version=meta.get('version', 'unknown'),
                    source=meta.get('source', ''),
                    last_updated=meta.get('last_updated', ''),
                    description=meta.get('description', ''),
                )

            return data

        except yaml.YAMLError as e:
            logger.error(f"Error parsing YAML file {path}: {e}")
            return {}
        except Exception as e:
            logger.error(f"Error loading knowledge base file {path}: {e}")
            return {}

    # ==================== CWE Methods ====================

    def get_cwe_data(self) -> dict:
        """Get full CWE knowledge base data."""
        return self._load_yaml("cwe-mappings.yaml")

    def get_cwe_top_25(self) -> Dict[str, dict]:
        """
        Get CWE Top 25 2025 entries.

        Returns:
            Dictionary mapping CWE IDs to their details
        """
        data = self.get_cwe_data()
        return data.get("cwe_top_25_2025", {})

    def get_cwe_entry(self, cwe_id: str) -> Optional[CWEReference]:
        """
        Get a specific CWE entry.

        Args:
            cwe_id: CWE identifier (e.g., "CWE-89")

        Returns:
            CWEReference if found, None otherwise
        """
        # Normalize CWE ID
        if not cwe_id.startswith("CWE-"):
            cwe_id = f"CWE-{cwe_id}"

        data = self.get_cwe_data()
        top_25 = data.get("cwe_top_25_2025", {})

        if cwe_id in top_25:
            entry = top_25[cwe_id]
            return CWEReference(
                id=cwe_id,
                name=entry.get("name", ""),
                description=entry.get("description", ""),
                severity="high",  # Top 25 are high severity
                stride_categories=entry.get("stride_categories", []),
                related_capec=entry.get("related_capec", []),
                mitigations=entry.get("mitigations", []),
            )

        return None

    def get_cwes_for_stride(
        self,
        category: STRIDECategory,
        severity_filter: Optional[str] = None
    ) -> List[str]:
        """
        Get CWE IDs applicable to a STRIDE category.

        Args:
            category: STRIDE category
            severity_filter: Optional filter by severity ('high', 'medium', 'low')

        Returns:
            List of CWE IDs
        """
        data = self.get_cwe_data()
        stride_mappings = data.get("stride_mappings", {})
        category_mappings = stride_mappings.get(category.value, [])

        if severity_filter:
            return [
                m["id"] for m in category_mappings
                if m.get("severity", "medium") == severity_filter
            ]

        return [m["id"] for m in category_mappings]

    def get_cwes_for_owasp(self, owasp_id: str) -> List[str]:
        """
        Get CWEs mapped to an OWASP Top 10 category.

        Args:
            owasp_id: OWASP category ID (e.g., "A01:2025")

        Returns:
            List of CWE IDs
        """
        data = self.get_cwe_data()
        owasp_mapping = data.get("owasp_top_10_2025_mapping", {})

        if owasp_id in owasp_mapping:
            return owasp_mapping[owasp_id].get("cwes", [])

        return []

    def get_owasp_categories(self) -> Dict[str, OWASPCategory]:
        """
        Get all OWASP Top 10 2025 categories.

        Returns:
            Dictionary mapping OWASP IDs to OWASPCategory objects
        """
        data = self.get_cwe_data()
        owasp_mapping = data.get("owasp_top_10_2025_mapping", {})

        result = {}
        for owasp_id, owasp_data in owasp_mapping.items():
            result[owasp_id] = OWASPCategory(
                id=owasp_id,
                name=owasp_data.get("name", ""),
                description=owasp_data.get("description", ""),
                cwes=owasp_data.get("cwes", []),
                stride_categories=owasp_data.get("stride", []),
            )

        return result

    # ==================== CAPEC Methods ====================

    def get_capec_data(self) -> dict:
        """Get full CAPEC knowledge base data."""
        return self._load_yaml("capec-mappings.yaml")

    def get_capec_entry(self, capec_id: str) -> Optional[CAPECReference]:
        """
        Get a specific CAPEC entry.

        Args:
            capec_id: CAPEC identifier (e.g., "CAPEC-89")

        Returns:
            CAPECReference if found, None otherwise
        """
        # Normalize CAPEC ID
        if not capec_id.startswith("CAPEC-"):
            capec_id = f"CAPEC-{capec_id}"

        data = self.get_capec_data()
        patterns = data.get("attack_patterns", {})

        if capec_id in patterns:
            entry = patterns[capec_id]
            return CAPECReference(
                id=capec_id,
                name=entry.get("name", ""),
                description=entry.get("description", ""),
                likelihood=entry.get("likelihood", ""),
                severity=entry.get("severity", ""),
                stride_categories=entry.get("stride_categories", []),
                related_cwe=entry.get("related_cwe", []),
                attack_mappings=entry.get("attack_mappings", []),
                mitigations=entry.get("mitigations", []),
            )

        return None

    def get_capecs_for_stride(
        self,
        category: STRIDECategory,
        severity_filter: Optional[str] = None
    ) -> List[str]:
        """
        Get CAPEC IDs applicable to a STRIDE category.

        Args:
            category: STRIDE category
            severity_filter: Optional filter by severity ('high', 'medium', 'low')

        Returns:
            List of CAPEC IDs
        """
        data = self.get_capec_data()
        stride_mappings = data.get("stride_mappings", {})
        category_mappings = stride_mappings.get(category.value, [])

        if severity_filter:
            return [
                m["id"] for m in category_mappings
                if m.get("severity", "medium") == severity_filter
            ]

        return [m["id"] for m in category_mappings]

    def get_capecs_for_cwe(self, cwe_id: str) -> List[str]:
        """
        Get CAPEC patterns that exploit a specific CWE.

        Args:
            cwe_id: CWE identifier

        Returns:
            List of CAPEC IDs
        """
        data = self._load_yaml("comprehensive-mappings.yaml")
        cwe_to_capec = data.get("cwe_to_capec", {})

        # Normalize CWE ID
        if not cwe_id.startswith("CWE-"):
            cwe_id = f"CWE-{cwe_id}"

        return cwe_to_capec.get(cwe_id, [])

    def get_attack_techniques_for_capec(self, capec_id: str) -> List[Dict]:
        """
        Get MITRE ATT&CK techniques mapped to a CAPEC pattern.

        Args:
            capec_id: CAPEC identifier

        Returns:
            List of ATT&CK technique mappings
        """
        entry = self.get_capec_entry(capec_id)
        if entry:
            return entry.attack_mappings
        return []

    # ==================== STRIDE Methods ====================

    def get_stride_data(self) -> dict:
        """Get full STRIDE library data."""
        return self._load_yaml("stride-library.yaml")

    def get_stride_category_info(self, category: STRIDECategory) -> Optional[STRIDECategoryInfo]:
        """
        Get detailed information about a STRIDE category.

        Args:
            category: STRIDE category

        Returns:
            STRIDECategoryInfo if found, None otherwise
        """
        data = self.get_stride_data()
        categories = data.get("stride_categories", {})

        if category.value in categories:
            cat_data = categories[category.value]
            return STRIDECategoryInfo(
                name=cat_data.get("name", ""),
                code=cat_data.get("code", ""),
                description=cat_data.get("description", ""),
                security_property=cat_data.get("security_property", ""),
                threat_examples=cat_data.get("threat_examples", []),
                applicable_targets=cat_data.get("applicable_targets", []),
                typical_mitigations=cat_data.get("typical_mitigations", []),
                primary_cwes=cat_data.get("primary_cwes", []),
                primary_capec=cat_data.get("primary_capec", []),
            )

        return None

    def get_stride_for_element(self, element_type: ElementType) -> List[STRIDECategory]:
        """
        Get applicable STRIDE categories for a DFD element type.

        This implements the STRIDE per Interaction matrix.

        Args:
            element_type: Type of DFD element

        Returns:
            List of applicable STRIDE categories
        """
        data = self.get_stride_data()
        stride_per_element = data.get("stride_per_element", {})

        category_names = stride_per_element.get(element_type.value, [])
        return [STRIDECategory(name) for name in category_names]

    def get_generation_filters(self, category: STRIDECategory) -> Dict[str, Any]:
        """
        Get generation filters for a STRIDE category.

        These filters determine when threats should be generated based on
        element attributes (TMT-compatible).

        Args:
            category: STRIDE category

        Returns:
            Dictionary with 'include' and 'exclude' filter conditions
        """
        data = self.get_stride_data()
        filters = data.get("generation_filters", {})
        return filters.get(category.value, {"include": [], "exclude": []})

    # ==================== Security Mapping Methods ====================

    def get_security_mapping(self, category: STRIDECategory) -> SecurityMapping:
        """
        Get complete security framework mapping for a STRIDE category.

        Args:
            category: STRIDE category

        Returns:
            SecurityMapping with CWEs, CAPECs, ATT&CK techniques, and OWASP categories
        """
        cwes = self.get_cwes_for_stride(category)
        capecs = self.get_capecs_for_stride(category)

        # Collect ATT&CK techniques from CAPEC mappings
        attack_techniques = set()
        for capec_id in capecs[:10]:  # Limit to avoid too many lookups
            entry = self.get_capec_entry(capec_id)
            if entry and entry.attack_mappings:
                for mapping in entry.attack_mappings:
                    tech_id = mapping.get('technique_id', '')
                    if tech_id:
                        attack_techniques.add(tech_id)

        # Find relevant OWASP categories
        owasp_cats = []
        owasp_mapping = self.get_owasp_categories()
        for owasp_id, owasp_cat in owasp_mapping.items():
            if category.value in owasp_cat.stride_categories or "all" in owasp_cat.stride_categories:
                owasp_cats.append(owasp_id)

        return SecurityMapping(
            cwes=cwes[:50],  # Limit to top 50
            capecs=capecs[:30],  # Limit to top 30
            mitre_attack=sorted(list(attack_techniques))[:20],
            owasp=owasp_cats,
        )

    # ==================== Utility Methods ====================

    def get_metadata(self, filename: str) -> Optional[KnowledgeBaseMetadata]:
        """
        Get metadata for a specific knowledge base file.

        Args:
            filename: Name of the knowledge base file

        Returns:
            KnowledgeBaseMetadata if available
        """
        # Ensure file is loaded
        self._load_yaml(filename)
        return self._metadata.get(filename)

    def get_all_metadata(self) -> Dict[str, KnowledgeBaseMetadata]:
        """
        Get metadata for all knowledge base files.

        Returns:
            Dictionary mapping filenames to their metadata
        """
        # Load all files to populate metadata
        self._load_yaml("cwe-mappings.yaml")
        self._load_yaml("capec-mappings.yaml")
        self._load_yaml("stride-library.yaml")
        self._load_yaml("comprehensive-mappings.yaml")

        return self._metadata.copy()

    def validate_knowledge_base(self) -> Dict[str, bool]:
        """
        Validate all knowledge base files are present and valid.

        Returns:
            Dictionary mapping filenames to their validity status
        """
        required_files = [
            "cwe-mappings.yaml",
            "capec-mappings.yaml",
            "stride-library.yaml",
            "comprehensive-mappings.yaml",
        ]

        results = {}
        for filename in required_files:
            path = self.knowledge_dir / filename
            if path.exists():
                try:
                    data = self._load_yaml(filename)
                    results[filename] = bool(data)
                except Exception:
                    results[filename] = False
            else:
                results[filename] = False

        return results

    def get_statistics(self) -> Dict[str, int]:
        """
        Get statistics about the knowledge base.

        Returns:
            Dictionary with counts of various entries
        """
        cwe_data = self.get_cwe_data()
        capec_data = self.get_capec_data()

        return {
            "cwe_top_25_count": len(cwe_data.get("cwe_top_25_2025", {})),
            "owasp_categories_count": len(cwe_data.get("owasp_top_10_2025_mapping", {})),
            "capec_patterns_count": len(capec_data.get("attack_patterns", {})),
            "attack_techniques_count": len(capec_data.get("attack_mappings", {})),
            "stride_categories_count": 6,  # Fixed
        }

    def clear_cache(self) -> None:
        """Clear the internal cache."""
        self._cache.clear()
        self._load_yaml.cache_clear()

    # ==================== Security Controls Methods ====================

    def get_controls_mapping(self) -> dict:
        """Get STRIDE to security controls mapping data."""
        return self._load_yaml("stride-controls-mapping.yaml")

    def get_controls_for_stride(self, category: STRIDECategory) -> Dict[str, Any]:
        """
        Get security controls applicable to a STRIDE category.

        Args:
            category: STRIDE category

        Returns:
            Dictionary with primary_controls, secondary_controls, and mitigation_patterns
        """
        data = self.get_controls_mapping()
        mappings = data.get("stride_to_controls", {})
        return mappings.get(category.value, {})

    def get_mitigation_patterns(self, category: STRIDECategory) -> List[Dict]:
        """
        Get mitigation patterns for a STRIDE category.

        Args:
            category: STRIDE category

        Returns:
            List of mitigation pattern dictionaries with name, description, reference
        """
        controls = self.get_controls_for_stride(category)
        return controls.get("mitigation_patterns", [])

    def get_security_control_file(self, control_name: str) -> Optional[str]:
        """
        Get the content of a security control file.

        Args:
            control_name: Name of the control file (e.g., "codeguard-0-authentication-mfa.md")

        Returns:
            File content as string, or None if not found
        """
        control_path = self.knowledge_dir / "security-controls" / control_name
        if control_path.exists():
            try:
                with open(control_path, 'r', encoding='utf-8') as f:
                    return f.read()
            except Exception as e:
                logger.error(f"Error reading control file {control_path}: {e}")
        return None

    def get_language_specific_controls(self, language: str) -> List[str]:
        """
        Get security control files applicable to a programming language.

        Args:
            language: Programming language (e.g., "python", "javascript")

        Returns:
            List of control file names
        """
        data = self.get_controls_mapping()
        language_rules = data.get("language_rules", {})
        return language_rules.get(language.lower(), [])

    def get_always_apply_rules(self) -> List[Dict]:
        """
        Get security rules that should always be applied.

        Returns:
            List of rule dictionaries with rule filename and description
        """
        data = self.get_controls_mapping()
        return data.get("always_apply_rules", [])

    # ==================== SQLite Integration Methods ====================

    def _get_sqlite_connection(self):
        """Get SQLite connection if database exists."""
        import sqlite3
        # V2 database with unified schema
        sqlite_path = self.knowledge_dir / "security_kb_v2.sqlite"
        if not sqlite_path.exists():
            return None
        return sqlite3.connect(str(sqlite_path))

    def get_cwe_full_data(self, cwe_id: str) -> Optional[Dict]:
        """
        Get complete CWE data from SQLite database.

        Args:
            cwe_id: CWE identifier (e.g., "CWE-89")

        Returns:
            Dictionary with full CWE data including hierarchy, mitigations, CAPEC links
        """
        conn = self._get_sqlite_connection()
        if not conn:
            return None

        try:
            cursor = conn.cursor()
            if not cwe_id.startswith("CWE-"):
                cwe_id = f"CWE-{cwe_id}"

            # Get basic info
            cursor.execute(
                "SELECT id, name, description, abstraction, status FROM cwe WHERE id = ?",
                (cwe_id,)
            )
            row = cursor.fetchone()
            if not row:
                return None

            result = {
                "id": row[0],
                "name": row[1],
                "description": row[2],
                "abstraction": row[3],
                "status": row[4],
                "source": "sqlite",
            }

            # Get STRIDE mappings
            cursor.execute(
                "SELECT stride_category FROM stride_cwe WHERE cwe_id = ?",
                (cwe_id,)
            )
            result["stride_categories"] = [r[0] for r in cursor.fetchall()]

            # Get CAPEC mappings
            cursor.execute(
                "SELECT DISTINCT capec_id FROM capec_cwe WHERE cwe_id = ?",
                (cwe_id,)
            )
            result["related_capec"] = [r[0] for r in cursor.fetchall()]

            # Get hierarchy
            cursor.execute(
                "SELECT parent_id FROM cwe_hierarchy WHERE child_id = ?",
                (cwe_id,)
            )
            result["parents"] = [r[0] for r in cursor.fetchall()]

            cursor.execute(
                "SELECT child_id FROM cwe_hierarchy WHERE parent_id = ?",
                (cwe_id,)
            )
            result["children"] = [r[0] for r in cursor.fetchall()]

            # Get OWASP mappings (V2: JOIN with owasp_top10)
            cursor.execute("""
                SELECT oc.owasp_id, ot.name, ot.year
                FROM owasp_cwe oc
                JOIN owasp_top10 ot ON oc.owasp_id = ot.id AND oc.year = ot.year
                WHERE oc.cwe_id = ?
            """, (cwe_id,))
            result["owasp_categories"] = [
                {"id": r[0], "name": r[1], "year": r[2]} for r in cursor.fetchall()
            ]

            # Get mitigations (V2: cwe_mitigation table with strategy)
            cursor.execute("""
                SELECT phase, strategy, description, effectiveness
                FROM cwe_mitigation WHERE cwe_id = ?
            """, (cwe_id,))
            result["mitigations"] = [
                {"phase": r[0], "strategy": r[1], "description": r[2], "effectiveness": r[3]}
                for r in cursor.fetchall()
            ]

            return result
        finally:
            conn.close()

    def get_all_cwes_for_stride(self, category: STRIDECategory) -> List[str]:
        """
        Get all CWE IDs for a STRIDE category from SQLite (more complete than YAML).

        Args:
            category: STRIDE category

        Returns:
            List of all CWE IDs (not just curated top entries)
        """
        conn = self._get_sqlite_connection()
        if not conn:
            return self.get_cwes_for_stride(category)  # Fallback to YAML

        try:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT cwe_id FROM stride_cwe WHERE stride_category = ?",
                (category.value.replace("_", " ").title(),)
            )
            return [r[0] for r in cursor.fetchall()]
        finally:
            conn.close()

    def get_capec_attack_techniques(self, capec_id: str) -> List[Dict]:
        """
        Get MITRE ATT&CK techniques for a CAPEC from SQLite.

        Args:
            capec_id: CAPEC identifier

        Returns:
            List of ATT&CK technique mappings
        """
        conn = self._get_sqlite_connection()
        if not conn:
            return self.get_attack_techniques_for_capec(capec_id)

        try:
            cursor = conn.cursor()
            if not capec_id.startswith("CAPEC-"):
                capec_id = f"CAPEC-{capec_id}"

            cursor.execute(
                "SELECT attack_id, attack_name FROM capec_attack WHERE capec_id = ?",
                (capec_id,)
            )
            return [
                {"technique_id": r[0], "technique_name": r[1]}
                for r in cursor.fetchall()
            ]
        finally:
            conn.close()

    def check_kev_status(self, cve_id: str) -> Dict:
        """
        Check if a CVE is in CISA KEV (Known Exploited Vulnerabilities).

        Args:
            cve_id: CVE identifier (e.g., "CVE-2021-44228")

        Returns:
            Dictionary with KEV status and details if found
        """
        conn = self._get_sqlite_connection()
        if not conn:
            return {"is_known_exploited": False, "cve_id": cve_id, "error": "SQLite not available"}

        try:
            cursor = conn.cursor()
            cursor.execute(
                """SELECT cve_id, vendor, product, vuln_name, date_added,
                          due_date, ransomware_use, notes
                   FROM kev WHERE cve_id = ?""",
                (cve_id.upper(),)
            )
            row = cursor.fetchone()

            if row:
                return {
                    "is_known_exploited": True,
                    "cve_id": row[0],
                    "vendor": row[1],
                    "product": row[2],
                    "vulnerability_name": row[3],
                    "date_added": row[4],
                    "due_date": row[5],
                    "known_ransomware": row[6],
                    "notes": row[7],
                }
            else:
                return {"is_known_exploited": False, "cve_id": cve_id}
        finally:
            conn.close()

    def get_enhanced_statistics(self) -> Dict[str, int]:
        """
        Get enhanced statistics including SQLite database counts.

        Returns:
            Dictionary with counts from both YAML and SQLite sources
        """
        stats = self.get_statistics()

        conn = self._get_sqlite_connection()
        if conn:
            try:
                cursor = conn.cursor()
                # V2 schema tables
                for table in ['cwe', 'cwe_mitigation', 'capec', 'capec_attack',
                              'attack_technique', 'attack_mitigation', 'owasp_top10',
                              'owasp_cwe', 'stride_cwe']:
                    try:
                        cursor.execute(f'SELECT COUNT(*) FROM {table}')
                        stats[f"sqlite_{table}_count"] = cursor.fetchone()[0]
                    except Exception:
                        stats[f"sqlite_{table}_count"] = 0
            finally:
                conn.close()

        return stats


# Convenience function for getting a singleton instance
_kb_instance: Optional[SecurityKnowledgeBase] = None


def get_knowledge_base(knowledge_dir: Optional[Path] = None) -> SecurityKnowledgeBase:
    """
    Get or create a SecurityKnowledgeBase instance.

    Args:
        knowledge_dir: Optional path to knowledge base directory

    Returns:
        SecurityKnowledgeBase instance
    """
    global _kb_instance

    if _kb_instance is None or knowledge_dir is not None:
        _kb_instance = SecurityKnowledgeBase(knowledge_dir)

    return _kb_instance


__all__ = [
    'SecurityKnowledgeBase',
    'get_knowledge_base',
    'STRIDECategory',
    'ElementType',
    'CWEReference',
    'CAPECReference',
    'STRIDECategoryInfo',
    'OWASPCategory',
    'SecurityMapping',
    'KnowledgeBaseMetadata',
]
