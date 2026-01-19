#!/usr/bin/env python3
"""
Knowledge Base Builder - Complete Extraction and Build System

Extracts data from:
- CWE XML v4.19
- CAPEC XML v3.9
- ATT&CK STIX + XLSX v18.1
- OWASP Top 10 2025
- STRIDE mappings

Builds unified SQLite database with:
- Core entity tables
- Relationship mappings
- FTS5 full-text search indexes
- Integrity verification
"""

import json
import re
import sqlite3
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

# Try to import pandas for XLSX support
try:
    import pandas as pd
    HAS_PANDAS = True
except ImportError:
    HAS_PANDAS = False
    print("Warning: pandas not available, XLSX processing will be skipped")

# Paths
LIBRARY_DIR = Path(__file__).parent.parent.parent / "Library"
KNOWLEDGE_DIR = Path(__file__).parent.parent / "assets" / "knowledge"
DB_PATH = KNOWLEDGE_DIR / "security_kb_v2.sqlite"

# Namespaces
CWE_NS = {'cwe': 'http://cwe.mitre.org/cwe-7'}
CAPEC_NS = {'capec': 'http://capec.mitre.org/capec-3'}


@dataclass
class BuildStats:
    """Track build statistics"""
    cwe_count: int = 0
    cwe_mitigation_count: int = 0
    cwe_hierarchy_count: int = 0
    capec_count: int = 0
    capec_cwe_count: int = 0
    attack_technique_count: int = 0
    attack_mitigation_count: int = 0
    capec_attack_count: int = 0
    attack_tech_mitigation_count: int = 0
    owasp_count: int = 0
    owasp_cwe_count: int = 0
    stride_cwe_count: int = 0
    errors: List[str] = None

    def __post_init__(self):
        if self.errors is None:
            self.errors = []

    def to_dict(self) -> Dict:
        return {
            'cwe': self.cwe_count,
            'cwe_mitigations': self.cwe_mitigation_count,
            'cwe_hierarchy': self.cwe_hierarchy_count,
            'capec': self.capec_count,
            'capec_cwe': self.capec_cwe_count,
            'attack_techniques': self.attack_technique_count,
            'attack_mitigations': self.attack_mitigation_count,
            'capec_attack': self.capec_attack_count,
            'attack_tech_mitigation': self.attack_tech_mitigation_count,
            'owasp_categories': self.owasp_count,
            'owasp_cwe': self.owasp_cwe_count,
            'stride_cwe': self.stride_cwe_count,
            'errors': len(self.errors)
        }


class KnowledgeBaseBuilder:
    """Build unified security knowledge base from raw data sources."""

    def __init__(self, db_path: Path = DB_PATH):
        self.db_path = db_path
        self.conn: Optional[sqlite3.Connection] = None
        self.stats = BuildStats()

    def build(self) -> BuildStats:
        """Execute full build pipeline."""
        print("=" * 60)
        print("Knowledge Base Builder v2.0")
        print("=" * 60)
        print(f"Database: {self.db_path}")
        print(f"Library:  {LIBRARY_DIR}")
        print()

        try:
            # Create database
            self._create_database()

            # Extract and load data (order matters for foreign keys)
            print("\n[Phase 1] Extracting STRIDE categories...")
            self._load_stride_categories()

            print("\n[Phase 2] Extracting CWE data...")
            self._extract_cwe()

            print("\n[Phase 3] Extracting CAPEC data...")
            self._extract_capec()

            print("\n[Phase 4] Extracting ATT&CK data...")
            self._extract_attack()

            print("\n[Phase 5] Extracting OWASP data...")
            self._extract_owasp()

            print("\n[Phase 6] Building STRIDE→CWE mappings...")
            self._build_stride_mappings()

            print("\n[Phase 7] Building FTS indexes...")
            self._build_fts_indexes()

            print("\n[Phase 8] Verifying integrity...")
            self._verify_integrity()

            self.conn.commit()

        except Exception as e:
            self.stats.errors.append(f"Fatal error: {e}")
            raise
        finally:
            if self.conn:
                self.conn.close()

        self._print_summary()
        return self.stats

    def _create_database(self):
        """Create database with optimized schema."""
        # Remove existing database
        if self.db_path.exists():
            self.db_path.unlink()

        self.conn = sqlite3.connect(str(self.db_path))
        self.conn.execute("PRAGMA foreign_keys = OFF")  # Defer FK checks
        self.conn.execute("PRAGMA journal_mode = WAL")
        self.conn.execute("PRAGMA synchronous = NORMAL")

        cursor = self.conn.cursor()

        # Core entity tables
        cursor.executescript("""
            -- STRIDE categories
            CREATE TABLE stride_category (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                security_property TEXT NOT NULL,
                description TEXT
            );

            -- CWE weaknesses
            CREATE TABLE cwe (
                id TEXT PRIMARY KEY,
                cwe_num INTEGER NOT NULL,
                name TEXT NOT NULL,
                abstraction TEXT,
                status TEXT,
                description TEXT,
                extended_description TEXT,
                likelihood_of_exploit TEXT,
                embedding_text TEXT
            );

            -- CWE hierarchy
            CREATE TABLE cwe_hierarchy (
                child_id TEXT NOT NULL,
                parent_id TEXT NOT NULL,
                nature TEXT,
                ordinal TEXT,
                PRIMARY KEY (child_id, parent_id)
            );

            -- CWE mitigations
            CREATE TABLE cwe_mitigation (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cwe_id TEXT NOT NULL,
                phase TEXT,
                strategy TEXT,
                description TEXT NOT NULL,
                effectiveness TEXT
            );

            -- CAPEC attack patterns
            CREATE TABLE capec (
                id TEXT PRIMARY KEY,
                capec_num INTEGER NOT NULL,
                name TEXT NOT NULL,
                abstraction TEXT,
                status TEXT,
                description TEXT,
                severity TEXT,
                likelihood_of_attack TEXT,
                prerequisites TEXT,
                skills_required TEXT,
                resources_required TEXT,
                embedding_text TEXT
            );

            -- CAPEC → CWE mappings
            CREATE TABLE capec_cwe (
                capec_id TEXT NOT NULL,
                cwe_id TEXT NOT NULL,
                nature TEXT,
                PRIMARY KEY (capec_id, cwe_id)
            );

            -- ATT&CK techniques
            CREATE TABLE attack_technique (
                id TEXT PRIMARY KEY,
                stix_id TEXT UNIQUE,
                name TEXT NOT NULL,
                description TEXT,
                tactics TEXT,
                platforms TEXT,
                detection TEXT,
                is_subtechnique INTEGER DEFAULT 0,
                parent_technique TEXT,
                version TEXT,
                embedding_text TEXT
            );

            -- ATT&CK mitigations
            CREATE TABLE attack_mitigation (
                id TEXT PRIMARY KEY,
                stix_id TEXT UNIQUE,
                name TEXT NOT NULL,
                description TEXT
            );

            -- CAPEC → ATT&CK mappings
            CREATE TABLE capec_attack (
                capec_id TEXT NOT NULL,
                attack_id TEXT NOT NULL,
                source TEXT,
                PRIMARY KEY (capec_id, attack_id)
            );

            -- ATT&CK technique → mitigation
            CREATE TABLE attack_tech_mitigation (
                technique_id TEXT NOT NULL,
                mitigation_id TEXT NOT NULL,
                description TEXT,
                PRIMARY KEY (technique_id, mitigation_id)
            );

            -- OWASP Top 10
            CREATE TABLE owasp_top10 (
                id TEXT PRIMARY KEY,
                year INTEGER NOT NULL,
                name TEXT NOT NULL,
                description TEXT,
                cwe_count INTEGER
            );

            -- OWASP → CWE mappings
            CREATE TABLE owasp_cwe (
                owasp_id TEXT NOT NULL,
                cwe_id TEXT NOT NULL,
                year INTEGER NOT NULL,
                PRIMARY KEY (owasp_id, cwe_id, year)
            );

            -- STRIDE → CWE mappings
            CREATE TABLE stride_cwe (
                stride_category TEXT NOT NULL,
                cwe_id TEXT NOT NULL,
                relevance_score REAL DEFAULT 1.0,
                source TEXT,
                notes TEXT,
                PRIMARY KEY (stride_category, cwe_id)
            );

            -- Indexes
            CREATE INDEX idx_cwe_num ON cwe(cwe_num);
            CREATE INDEX idx_cwe_abstraction ON cwe(abstraction);
            CREATE INDEX idx_capec_num ON capec(capec_num);
            CREATE INDEX idx_capec_severity ON capec(severity);
            CREATE INDEX idx_attack_tactics ON attack_technique(tactics);
            CREATE INDEX idx_attack_parent ON attack_technique(parent_technique);
            CREATE INDEX idx_capec_cwe_cwe ON capec_cwe(cwe_id);
            CREATE INDEX idx_stride_cwe_cwe ON stride_cwe(cwe_id);
            CREATE INDEX idx_owasp_cwe_cwe ON owasp_cwe(cwe_id);
        """)

        print("  ✓ Database schema created")

    def _load_stride_categories(self):
        """Load STRIDE category definitions."""
        categories = [
            ('S', 'Spoofing', 'Authentication',
             'Pretending to be something or someone other than yourself'),
            ('T', 'Tampering', 'Integrity',
             'Modifying something on disk, network, memory, or elsewhere'),
            ('R', 'Repudiation', 'Non-repudiation',
             'Claiming to have not performed an action'),
            ('I', 'Information Disclosure', 'Confidentiality',
             'Exposing information to someone not authorized to see it'),
            ('D', 'Denial of Service', 'Availability',
             'Absorbing resources needed to provide service'),
            ('E', 'Elevation of Privilege', 'Authorization',
             'Allowing someone to do something they are not authorized to do'),
        ]

        cursor = self.conn.cursor()
        cursor.executemany(
            "INSERT INTO stride_category (id, name, security_property, description) VALUES (?, ?, ?, ?)",
            categories
        )
        print(f"  ✓ Loaded 6 STRIDE categories")

    def _extract_cwe(self):
        """Extract CWE data from XML."""
        cwe_path = LIBRARY_DIR / "CWE" / "cwec_v4.19.xml"
        if not cwe_path.exists():
            self.stats.errors.append(f"CWE file not found: {cwe_path}")
            return

        tree = ET.parse(str(cwe_path))
        root = tree.getroot()

        cursor = self.conn.cursor()

        # Extract weaknesses
        weaknesses = root.findall('.//cwe:Weakness', CWE_NS)

        for w in weaknesses:
            cwe_id = f"CWE-{w.get('ID')}"
            cwe_num = int(w.get('ID'))
            name = w.get('Name', '')
            abstraction = w.get('Abstraction', '')
            status = w.get('Status', '')

            # Get description
            desc_elem = w.find('cwe:Description', CWE_NS)
            description = desc_elem.text if desc_elem is not None else ''

            ext_desc_elem = w.find('cwe:Extended_Description', CWE_NS)
            ext_description = self._get_text_content(ext_desc_elem) if ext_desc_elem is not None else ''

            # Get likelihood
            likelihood_elem = w.find('cwe:Likelihood_Of_Exploit', CWE_NS)
            likelihood = likelihood_elem.text if likelihood_elem is not None else ''

            # Build embedding text
            embedding_text = f"{name}. {description}"

            cursor.execute("""
                INSERT OR REPLACE INTO cwe
                (id, cwe_num, name, abstraction, status, description,
                 extended_description, likelihood_of_exploit, embedding_text)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (cwe_id, cwe_num, name, abstraction, status, description,
                  ext_description, likelihood, embedding_text))
            self.stats.cwe_count += 1

            # Extract hierarchy relationships
            related = w.findall('.//cwe:Related_Weakness', CWE_NS)
            for rel in related:
                nature = rel.get('Nature', '')
                target_id = f"CWE-{rel.get('CWE_ID')}"
                ordinal = rel.get('Ordinal', '')

                if nature in ('ChildOf', 'ParentOf', 'MemberOf', 'HasMember'):
                    if nature == 'ChildOf':
                        cursor.execute("""
                            INSERT OR IGNORE INTO cwe_hierarchy (child_id, parent_id, nature, ordinal)
                            VALUES (?, ?, ?, ?)
                        """, (cwe_id, target_id, nature, ordinal))
                    elif nature == 'ParentOf':
                        cursor.execute("""
                            INSERT OR IGNORE INTO cwe_hierarchy (child_id, parent_id, nature, ordinal)
                            VALUES (?, ?, ?, ?)
                        """, (target_id, cwe_id, 'ChildOf', ordinal))
                    self.stats.cwe_hierarchy_count += 1

            # Extract mitigations
            mitigations = w.findall('.//cwe:Mitigation', CWE_NS)
            for mit in mitigations:
                phase_elem = mit.find('cwe:Phase', CWE_NS)
                phase = phase_elem.text if phase_elem is not None else ''

                strategy_elem = mit.find('cwe:Strategy', CWE_NS)
                strategy = strategy_elem.text if strategy_elem is not None else ''

                desc_elem = mit.find('cwe:Description', CWE_NS)
                mit_desc = self._get_text_content(desc_elem) if desc_elem is not None else ''

                eff_elem = mit.find('cwe:Effectiveness', CWE_NS)
                effectiveness = eff_elem.text if eff_elem is not None else ''

                if mit_desc:
                    cursor.execute("""
                        INSERT INTO cwe_mitigation (cwe_id, phase, strategy, description, effectiveness)
                        VALUES (?, ?, ?, ?, ?)
                    """, (cwe_id, phase, strategy, mit_desc, effectiveness))
                    self.stats.cwe_mitigation_count += 1

        print(f"  ✓ Extracted {self.stats.cwe_count} CWE weaknesses")
        print(f"  ✓ Extracted {self.stats.cwe_hierarchy_count} hierarchy relations")
        print(f"  ✓ Extracted {self.stats.cwe_mitigation_count} mitigations")

    def _extract_capec(self):
        """Extract CAPEC data from XML."""
        capec_path = LIBRARY_DIR / "CAPEC" / "capec_v3.9.xml"
        if not capec_path.exists():
            self.stats.errors.append(f"CAPEC file not found: {capec_path}")
            return

        tree = ET.parse(str(capec_path))
        root = tree.getroot()

        cursor = self.conn.cursor()

        # Extract attack patterns
        patterns = root.findall('.//capec:Attack_Pattern', CAPEC_NS)

        for ap in patterns:
            capec_id = f"CAPEC-{ap.get('ID')}"
            capec_num = int(ap.get('ID'))
            name = ap.get('Name', '')
            abstraction = ap.get('Abstraction', '')
            status = ap.get('Status', '')

            # Get description
            desc_elem = ap.find('capec:Description', CAPEC_NS)
            description = self._get_text_content(desc_elem) if desc_elem is not None else ''

            # Get severity
            severity_elem = ap.find('capec:Typical_Severity', CAPEC_NS)
            severity = severity_elem.text if severity_elem is not None else ''

            # Get likelihood
            likelihood_elem = ap.find('capec:Likelihood_Of_Attack', CAPEC_NS)
            likelihood = likelihood_elem.text if likelihood_elem is not None else ''

            # Get prerequisites
            prereqs = []
            for prereq in ap.findall('.//capec:Prerequisite', CAPEC_NS):
                prereqs.append(prereq.text or '')
            prerequisites = '; '.join(prereqs)

            # Get skills required
            skills = []
            for skill in ap.findall('.//capec:Skill', CAPEC_NS):
                level = skill.get('Level', '')
                skill_text = skill.text or ''
                skills.append(f"[{level}] {skill_text}")
            skills_required = '; '.join(skills)

            # Get resources required
            resources = []
            for res in ap.findall('.//capec:Resource', CAPEC_NS):
                resources.append(res.text or '')
            resources_required = '; '.join(resources)

            # Build embedding text
            embedding_text = f"{name}. {description}. Prerequisites: {prerequisites}. Severity: {severity}"

            cursor.execute("""
                INSERT OR REPLACE INTO capec
                (id, capec_num, name, abstraction, status, description, severity,
                 likelihood_of_attack, prerequisites, skills_required, resources_required, embedding_text)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (capec_id, capec_num, name, abstraction, status, description, severity,
                  likelihood, prerequisites, skills_required, resources_required, embedding_text))
            self.stats.capec_count += 1

            # Extract CWE mappings
            related_weaknesses = ap.findall('.//capec:Related_Weakness', CAPEC_NS)
            for rw in related_weaknesses:
                cwe_id = f"CWE-{rw.get('CWE_ID')}"
                nature = rw.get('Nature', '')

                cursor.execute("""
                    INSERT OR IGNORE INTO capec_cwe (capec_id, cwe_id, nature)
                    VALUES (?, ?, ?)
                """, (capec_id, cwe_id, nature))
                self.stats.capec_cwe_count += 1

        print(f"  ✓ Extracted {self.stats.capec_count} CAPEC patterns")
        print(f"  ✓ Extracted {self.stats.capec_cwe_count} CAPEC→CWE mappings")

    def _extract_attack(self):
        """Extract ATT&CK data from STIX and XLSX."""
        stix_path = LIBRARY_DIR / "ATTACK" / "attack-stix-data" / "enterprise-attack" / "enterprise-attack.json"

        if not stix_path.exists():
            self.stats.errors.append(f"ATT&CK STIX file not found: {stix_path}")
            return

        with open(stix_path) as f:
            stix_data = json.load(f)

        cursor = self.conn.cursor()
        objects = stix_data.get('objects', [])

        # Index objects by STIX ID for relationship processing
        stix_index: Dict[str, Any] = {}
        for obj in objects:
            stix_id = obj.get('id')
            if stix_id:
                stix_index[stix_id] = obj

        # Extract techniques (attack-pattern)
        techniques = [obj for obj in objects if obj.get('type') == 'attack-pattern']

        for tech in techniques:
            stix_id = tech.get('id')
            name = tech.get('name', '')
            description = tech.get('description', '')

            # Get external ID (T1234)
            tech_id = None
            capec_refs = []
            for ref in tech.get('external_references', []):
                if ref.get('source_name') == 'mitre-attack':
                    tech_id = ref.get('external_id')
                elif ref.get('source_name') == 'capec':
                    capec_refs.append(ref.get('external_id'))

            if not tech_id:
                continue

            # Check if sub-technique
            is_sub = '.' in tech_id if tech_id else False
            parent = tech_id.split('.')[0] if is_sub and tech_id else None

            # Get tactics (kill chain phases)
            tactics = []
            for phase in tech.get('kill_chain_phases', []):
                if phase.get('kill_chain_name') == 'mitre-attack':
                    tactics.append(phase.get('phase_name'))

            # Get platforms
            platforms = tech.get('x_mitre_platforms', [])

            # Get detection
            detection = tech.get('x_mitre_detection', '')

            # Build embedding text
            embedding_text = f"{name}. {description}. Tactics: {', '.join(tactics)}. Detection: {detection}"

            cursor.execute("""
                INSERT OR REPLACE INTO attack_technique
                (id, stix_id, name, description, tactics, platforms, detection,
                 is_subtechnique, parent_technique, version, embedding_text)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (tech_id, stix_id, name, description, json.dumps(tactics),
                  json.dumps(platforms), detection, 1 if is_sub else 0,
                  parent, tech.get('x_mitre_version', ''), embedding_text))
            self.stats.attack_technique_count += 1

            # Add CAPEC mappings
            for capec_ref in capec_refs:
                cursor.execute("""
                    INSERT OR IGNORE INTO capec_attack (capec_id, attack_id, source)
                    VALUES (?, ?, ?)
                """, (capec_ref, tech_id, 'stix'))
                self.stats.capec_attack_count += 1

        # Extract mitigations (course-of-action)
        mitigations = [obj for obj in objects if obj.get('type') == 'course-of-action']

        for mit in mitigations:
            stix_id = mit.get('id')
            name = mit.get('name', '')
            description = mit.get('description', '')

            # Get external ID (M1234)
            mit_id = None
            for ref in mit.get('external_references', []):
                if ref.get('source_name') == 'mitre-attack':
                    mit_id = ref.get('external_id')
                    break

            if not mit_id:
                continue

            cursor.execute("""
                INSERT OR REPLACE INTO attack_mitigation
                (id, stix_id, name, description)
                VALUES (?, ?, ?, ?)
            """, (mit_id, stix_id, name, description))
            self.stats.attack_mitigation_count += 1

        # Extract relationships (technique→mitigation)
        relationships = [obj for obj in objects if obj.get('type') == 'relationship']

        for rel in relationships:
            rel_type = rel.get('relationship_type')
            if rel_type != 'mitigates':
                continue

            source_ref = rel.get('source_ref')
            target_ref = rel.get('target_ref')

            source_obj = stix_index.get(source_ref)
            target_obj = stix_index.get(target_ref)

            if not source_obj or not target_obj:
                continue

            # Get IDs
            mit_id = None
            tech_id = None

            for ref in source_obj.get('external_references', []):
                if ref.get('source_name') == 'mitre-attack':
                    mit_id = ref.get('external_id')
                    break

            for ref in target_obj.get('external_references', []):
                if ref.get('source_name') == 'mitre-attack':
                    tech_id = ref.get('external_id')
                    break

            if mit_id and tech_id:
                rel_desc = rel.get('description', '')
                cursor.execute("""
                    INSERT OR IGNORE INTO attack_tech_mitigation
                    (technique_id, mitigation_id, description)
                    VALUES (?, ?, ?)
                """, (tech_id, mit_id, rel_desc))
                self.stats.attack_tech_mitigation_count += 1

        print(f"  ✓ Extracted {self.stats.attack_technique_count} ATT&CK techniques")
        print(f"  ✓ Extracted {self.stats.attack_mitigation_count} ATT&CK mitigations")
        print(f"  ✓ Extracted {self.stats.capec_attack_count} CAPEC→ATT&CK mappings")
        print(f"  ✓ Extracted {self.stats.attack_tech_mitigation_count} technique→mitigation relations")

    def _extract_owasp(self):
        """Extract OWASP Top 10 2025 mappings."""
        owasp_path = LIBRARY_DIR / "OWASP" / "OWASP_2025_CWE_MAPPING.md"

        if not owasp_path.exists():
            self.stats.errors.append(f"OWASP file not found: {owasp_path}")
            return

        cursor = self.conn.cursor()

        # OWASP 2025 categories
        categories = {
            'A01': ('Broken Access Control', 40),
            'A02': ('Security Misconfiguration', 16),
            'A03': ('Software Supply Chain Failures', 5),
            'A04': ('Cryptographic Failures', 32),
            'A05': ('Injection', 37),
            'A06': ('Insecure Design', 39),
            'A07': ('Authentication Failures', 36),
            'A08': ('Software or Data Integrity Failures', 14),
            'A09': ('Security Logging & Alerting Failures', 5),
            'A10': ('Mishandling of Exceptional Conditions', 24),
        }

        # Load existing JSON mapping for CWE details
        json_path = KNOWLEDGE_DIR / "owasp_cwe_mapping.json"
        if json_path.exists():
            with open(json_path) as f:
                json_mapping = json.load(f)
        else:
            json_mapping = {}

        for cat_id, (name, cwe_count) in categories.items():
            cursor.execute("""
                INSERT OR REPLACE INTO owasp_top10 (id, year, name, description, cwe_count)
                VALUES (?, ?, ?, ?, ?)
            """, (cat_id, 2025, name, '', cwe_count))
            self.stats.owasp_count += 1

            # Load CWE mappings from JSON
            if cat_id in json_mapping:
                cwes = json_mapping[cat_id].get('cwes', [])
                for cwe_id in cwes:
                    cursor.execute("""
                        INSERT OR IGNORE INTO owasp_cwe (owasp_id, cwe_id, year)
                        VALUES (?, ?, ?)
                    """, (cat_id, cwe_id, 2025))
                    self.stats.owasp_cwe_count += 1

        print(f"  ✓ Loaded {self.stats.owasp_count} OWASP categories")
        print(f"  ✓ Loaded {self.stats.owasp_cwe_count} OWASP→CWE mappings")

    def _build_stride_mappings(self):
        """Build STRIDE→CWE mappings based on CWE characteristics."""
        cursor = self.conn.cursor()

        # STRIDE category name to ID mapping
        stride_name_to_id = {
            'Spoofing': 'S',
            'Tampering': 'T',
            'Repudiation': 'R',
            'Information Disclosure': 'I',
            'Denial of Service': 'D',
            'Elevation of Privilege': 'E',
        }

        # Load existing stride_cwe_mapping.json if available
        json_path = KNOWLEDGE_DIR / "stride_cwe_mapping.json"
        if json_path.exists():
            with open(json_path) as f:
                existing_mappings = json.load(f)

            for stride_name, data in existing_mappings.items():
                stride_cat = stride_name_to_id.get(stride_name, stride_name)

                # Handle nested structure with primary_cwes and related_cwes
                if isinstance(data, dict):
                    cwes = []
                    # Extract from primary_cwes (list of objects with 'id')
                    for cwe_obj in data.get('primary_cwes', []):
                        if isinstance(cwe_obj, dict) and 'id' in cwe_obj:
                            cwes.append((cwe_obj['id'], 1.0))  # High relevance
                    # Extract from related_cwes
                    for cwe_obj in data.get('related_cwes', []):
                        if isinstance(cwe_obj, dict) and 'id' in cwe_obj:
                            cwes.append((cwe_obj['id'], 0.7))  # Lower relevance
                else:
                    # Simple list of CWE IDs
                    cwes = [(cwe_id, 1.0) for cwe_id in data]

                for cwe_id, score in cwes:
                    cursor.execute("""
                        INSERT OR IGNORE INTO stride_cwe (stride_category, cwe_id, source, relevance_score)
                        VALUES (?, ?, ?, ?)
                    """, (stride_cat, cwe_id, 'json', score))
                    self.stats.stride_cwe_count += 1

        # Add additional mappings based on CWE characteristics
        # This is a simplified heuristic - production would use ML classification
        stride_keywords = {
            'S': ['authentication', 'identity', 'credential', 'spoofing', 'impersonat'],
            'T': ['integrity', 'tampering', 'modification', 'unauthorized change', 'injection'],
            'R': ['audit', 'logging', 'repudiation', 'accountability', 'non-repudiation'],
            'I': ['disclosure', 'exposure', 'leak', 'confidential', 'sensitive data'],
            'D': ['denial', 'availability', 'resource', 'exhaustion', 'crash'],
            'E': ['privilege', 'authorization', 'access control', 'escalation', 'bypass'],
        }

        cursor.execute("SELECT id, name, description FROM cwe")
        cwes = cursor.fetchall()

        for cwe_id, name, description in cwes:
            text = f"{name} {description or ''}".lower()

            for stride_cat, keywords in stride_keywords.items():
                for keyword in keywords:
                    if keyword in text:
                        cursor.execute("""
                            INSERT OR IGNORE INTO stride_cwe (stride_category, cwe_id, source, relevance_score)
                            VALUES (?, ?, ?, ?)
                        """, (stride_cat, cwe_id, 'inferred', 0.7))
                        self.stats.stride_cwe_count += 1
                        break

        print(f"  ✓ Built {self.stats.stride_cwe_count} STRIDE→CWE mappings")

    def _build_fts_indexes(self):
        """Build FTS5 full-text search indexes."""
        cursor = self.conn.cursor()

        # CWE FTS
        cursor.execute("""
            CREATE VIRTUAL TABLE IF NOT EXISTS cwe_fts USING fts5(
                id, name, description,
                content=cwe,
                content_rowid=rowid
            )
        """)
        cursor.execute("INSERT INTO cwe_fts(cwe_fts) VALUES('rebuild')")

        # CAPEC FTS
        cursor.execute("""
            CREATE VIRTUAL TABLE IF NOT EXISTS capec_fts USING fts5(
                id, name, description,
                content=capec,
                content_rowid=rowid
            )
        """)
        cursor.execute("INSERT INTO capec_fts(capec_fts) VALUES('rebuild')")

        # ATT&CK FTS
        cursor.execute("""
            CREATE VIRTUAL TABLE IF NOT EXISTS attack_fts USING fts5(
                id, name, description, detection,
                content=attack_technique,
                content_rowid=rowid
            )
        """)
        cursor.execute("INSERT INTO attack_fts(attack_fts) VALUES('rebuild')")

        print("  ✓ Built FTS5 indexes for CWE, CAPEC, ATT&CK")

    def _verify_integrity(self):
        """Verify database integrity and fix orphan references."""
        cursor = self.conn.cursor()
        issues = []
        fixed = 0

        # Define known deprecated/category CWEs that are referenced but not in main list
        deprecated_cwes = {
            'CWE-16': ('Configuration', 'Category'),
            'CWE-264': ('Permissions, Privileges, and Access Controls', 'Category'),
            'CWE-275': ('Permission Issues', 'Category'),
            'CWE-320': ('Key Management Errors', 'Category'),
            'CWE-1035': ('OWASP Top Ten 2017 Category A9 - Using Components with Known Vulnerabilities', 'Category'),
        }

        # Add missing CWEs as stubs
        for cwe_id, (name, abstraction) in deprecated_cwes.items():
            cwe_num = int(cwe_id.split('-')[1])
            cursor.execute("""
                INSERT OR IGNORE INTO cwe (id, cwe_num, name, abstraction, status, description)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (cwe_id, cwe_num, name, abstraction, 'Deprecated',
                  f'Category/Deprecated CWE. See official MITRE CWE database for details.'))
            if cursor.rowcount > 0:
                fixed += 1

        if fixed > 0:
            print(f"  ✓ Added {fixed} deprecated/category CWE stubs")

        # Check for orphan CAPEC→CWE references
        cursor.execute("""
            SELECT capec_id, cwe_id FROM capec_cwe
            WHERE cwe_id NOT IN (SELECT id FROM cwe)
        """)
        orphans = cursor.fetchall()
        if orphans:
            issues.append(f"CAPEC→CWE: {len(orphans)} orphan CWE references")

        # Check for orphan OWASP→CWE references
        cursor.execute("""
            SELECT owasp_id, cwe_id FROM owasp_cwe
            WHERE cwe_id NOT IN (SELECT id FROM cwe)
        """)
        orphans = cursor.fetchall()
        if orphans:
            issues.append(f"OWASP→CWE: {len(orphans)} orphan CWE references")

        # Check for orphan STRIDE→CWE references
        cursor.execute("""
            SELECT stride_category, cwe_id FROM stride_cwe
            WHERE cwe_id NOT IN (SELECT id FROM cwe)
        """)
        orphans = cursor.fetchall()
        if orphans:
            # Delete invalid STRIDE→CWE mappings
            cursor.execute("""
                DELETE FROM stride_cwe
                WHERE cwe_id NOT IN (SELECT id FROM cwe)
            """)
            print(f"  ✓ Removed {len(orphans)} invalid STRIDE→CWE mappings")

        if issues:
            for issue in issues:
                print(f"  ⚠️  {issue}")
                self.stats.errors.append(issue)
        else:
            print("  ✓ All referential integrity checks passed")

    def _get_text_content(self, elem) -> str:
        """Extract all text content from an XML element including children."""
        if elem is None:
            return ''

        texts = []
        if elem.text:
            texts.append(elem.text.strip())

        for child in elem:
            if child.text:
                texts.append(child.text.strip())
            if child.tail:
                texts.append(child.tail.strip())

        return ' '.join(texts)

    def _print_summary(self):
        """Print build summary."""
        print()
        print("=" * 60)
        print("Build Summary")
        print("=" * 60)

        stats = self.stats.to_dict()
        for key, value in stats.items():
            if key != 'errors':
                print(f"  {key}: {value}")

        print()
        if self.stats.errors:
            print(f"  ⚠️  {len(self.stats.errors)} issues encountered:")
            for err in self.stats.errors[:5]:
                print(f"      - {err}")
        else:
            print("  ✓ Build completed successfully with no errors")

        print()
        print(f"Database saved to: {self.db_path}")
        print(f"Database size: {self.db_path.stat().st_size / 1024 / 1024:.2f} MB")


def main():
    """Main entry point."""
    builder = KnowledgeBaseBuilder()
    stats = builder.build()

    # Return exit code based on errors
    return 1 if stats.errors else 0


if __name__ == "__main__":
    exit(main())
