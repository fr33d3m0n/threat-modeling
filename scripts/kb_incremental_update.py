#!/usr/bin/env python3
"""
Knowledge Base Incremental Update Module

Implements efficient incremental updates for the security knowledge base:
- Source version tracking with file checksums
- Change detection to skip unchanged sources
- Upsert logic for atomicity and idempotency
- Rollback support on errors

Supported sources:
- CWE XML (Common Weakness Enumeration)
- CAPEC XML (Common Attack Pattern Enumeration)
- ATT&CK STIX (MITRE ATT&CK Framework)
- OWASP Top 10 (manual definition)

Usage:
    python kb_incremental_update.py --check      # Check for updates
    python kb_incremental_update.py --update     # Run incremental update
    python kb_incremental_update.py --force      # Force full update
    python kb_incremental_update.py --status     # Show current status
"""

import argparse
import hashlib
import json
import sqlite3
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Any

# ============================================================================
# Configuration
# ============================================================================

SCRIPT_DIR = Path(__file__).parent
THREAT_MODELING_DIR = SCRIPT_DIR.parent
LIBRARY_DIR = Path("/home/elly/STRIDE/Library")
KNOWLEDGE_DIR = THREAT_MODELING_DIR / "assets" / "knowledge"
KB_SQLITE_PATH = KNOWLEDGE_DIR / "security_kb.sqlite"

# Source file paths
SOURCES = {
    'cwe': {
        'path': LIBRARY_DIR / "CWE" / "cwec_v4.19.xml",
        'type': 'xml',
        'version_attr': None,  # Extract from filename or content
    },
    'capec': {
        'path': LIBRARY_DIR / "CAPEC" / "capec_v3.9.xml",
        'type': 'xml',
        'version_attr': None,
    },
    'attack_stix': {
        'path': LIBRARY_DIR / "ATTACK" / "attack-stix-data" / "enterprise-attack",
        'type': 'stix_dir',
        'version_attr': None,
    },
}

# XML namespaces
CWE_NS = {'cwe': 'http://cwe.mitre.org/cwe-7'}
CAPEC_NS = {'capec': 'http://capec.mitre.org/capec-3'}


# ============================================================================
# Data Classes
# ============================================================================

@dataclass
class SourceVersion:
    """Track version information for a data source."""
    source_name: str
    file_path: str
    version: str
    checksum: str
    record_count: int
    last_updated: str

    @classmethod
    def from_row(cls, row: tuple) -> 'SourceVersion':
        return cls(
            source_name=row[0],
            file_path=row[1],
            version=row[2],
            checksum=row[3],
            record_count=row[4],
            last_updated=row[5]
        )


@dataclass
class UpdateResult:
    """Result of an incremental update operation."""
    source_name: str
    status: str  # 'unchanged', 'updated', 'error', 'skipped'
    records_added: int = 0
    records_updated: int = 0
    records_deleted: int = 0
    old_version: Optional[str] = None
    new_version: Optional[str] = None
    old_checksum: Optional[str] = None
    new_checksum: Optional[str] = None
    error_message: Optional[str] = None
    duration_seconds: float = 0.0


@dataclass
class UpdateStats:
    """Aggregate statistics for update operation."""
    start_time: datetime = field(default_factory=datetime.now)
    end_time: Optional[datetime] = None
    sources_checked: int = 0
    sources_updated: int = 0
    sources_unchanged: int = 0
    sources_error: int = 0
    results: List[UpdateResult] = field(default_factory=list)

    def add_result(self, result: UpdateResult):
        self.results.append(result)
        if result.status == 'updated':
            self.sources_updated += 1
        elif result.status == 'unchanged':
            self.sources_unchanged += 1
        elif result.status == 'error':
            self.sources_error += 1
        self.sources_checked += 1

    def finalize(self):
        self.end_time = datetime.now()

    @property
    def duration(self) -> float:
        if self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return 0.0


# ============================================================================
# Utility Functions
# ============================================================================

def calculate_file_checksum(file_path: Path) -> str:
    """Calculate MD5 checksum of a file."""
    hasher = hashlib.md5()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            hasher.update(chunk)
    return hasher.hexdigest()


def calculate_directory_checksum(dir_path: Path, pattern: str = "*.json") -> str:
    """Calculate combined checksum of files in a directory."""
    hasher = hashlib.md5()
    files = sorted(dir_path.glob(pattern))
    for f in files:
        hasher.update(f.name.encode())
        hasher.update(str(f.stat().st_mtime).encode())
    return hasher.hexdigest()


def extract_version_from_filename(path: Path) -> str:
    """
    Extract version from filename.

    Supports formats:
    - 'cwec_v4.19.xml' -> '4.19'
    - 'capec_v3.9.xml' -> '3.9'
    - 'enterprise-attack-18.1.json' -> '18.1'
    """
    name = path.stem
    # Format: something_vX.Y
    if '_v' in name:
        return name.split('_v')[1]
    # Format: something-X.Y (ATT&CK STIX)
    if '-' in name:
        parts = name.split('-')
        # Last part should be version (e.g., '18.1')
        for part in reversed(parts):
            if part.replace('.', '').isdigit():
                return part
    return 'unknown'


def get_latest_stix_file(stix_dir: Path) -> Optional[Path]:
    """Find the latest enterprise-attack STIX bundle file."""
    stix_files = list(stix_dir.glob("enterprise-attack-*.json"))
    if not stix_files:
        return None

    def get_version(f: Path) -> tuple:
        name = f.stem
        version_str = name.replace('enterprise-attack-', '')
        try:
            parts = version_str.split('.')
            return tuple(int(p) for p in parts)
        except ValueError:
            return (0,)

    stix_files.sort(key=get_version, reverse=True)
    return stix_files[0] if stix_files else None


# ============================================================================
# Database Operations
# ============================================================================

class IncrementalUpdater:
    """Manages incremental updates to the knowledge base."""

    def __init__(self, db_path: Path = KB_SQLITE_PATH):
        self.db_path = db_path
        self.conn: Optional[sqlite3.Connection] = None

    def connect(self):
        """Establish database connection."""
        if not self.db_path.exists():
            raise FileNotFoundError(f"Database not found: {self.db_path}")
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row
        self._ensure_source_version_table()

    def close(self):
        """Close database connection."""
        if self.conn:
            self.conn.close()
            self.conn = None

    def _ensure_source_version_table(self):
        """Create source_version table if it doesn't exist."""
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS source_version (
                source_name TEXT PRIMARY KEY,
                file_path TEXT,
                version TEXT,
                checksum TEXT,
                record_count INTEGER,
                last_updated TEXT
            )
        """)
        self.conn.commit()

    def get_source_version(self, source_name: str) -> Optional[SourceVersion]:
        """Get stored version info for a source."""
        cursor = self.conn.execute(
            "SELECT * FROM source_version WHERE source_name = ?",
            (source_name,)
        )
        row = cursor.fetchone()
        return SourceVersion.from_row(tuple(row)) if row else None

    def update_source_version(self, version: SourceVersion):
        """Update or insert source version info."""
        self.conn.execute("""
            INSERT OR REPLACE INTO source_version
            (source_name, file_path, version, checksum, record_count, last_updated)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            version.source_name,
            version.file_path,
            version.version,
            version.checksum,
            version.record_count,
            version.last_updated
        ))
        self.conn.commit()

    def check_for_updates(self) -> Dict[str, Dict[str, Any]]:
        """Check all sources for available updates."""
        results = {}

        for source_name, config in SOURCES.items():
            path = config['path']
            current_version = self.get_source_version(source_name)

            if config['type'] == 'xml':
                if not path.exists():
                    results[source_name] = {
                        'status': 'missing',
                        'path': str(path)
                    }
                    continue

                new_checksum = calculate_file_checksum(path)
                new_version = extract_version_from_filename(path)

            elif config['type'] == 'stix_dir':
                if not path.exists():
                    results[source_name] = {
                        'status': 'missing',
                        'path': str(path)
                    }
                    continue

                latest_file = get_latest_stix_file(path)
                if not latest_file:
                    results[source_name] = {
                        'status': 'missing',
                        'path': str(path)
                    }
                    continue

                new_checksum = calculate_file_checksum(latest_file)
                new_version = extract_version_from_filename(latest_file)
            else:
                continue

            if current_version is None:
                results[source_name] = {
                    'status': 'new',
                    'new_version': new_version,
                    'new_checksum': new_checksum
                }
            elif current_version.checksum != new_checksum:
                results[source_name] = {
                    'status': 'changed',
                    'old_version': current_version.version,
                    'new_version': new_version,
                    'old_checksum': current_version.checksum,
                    'new_checksum': new_checksum
                }
            else:
                results[source_name] = {
                    'status': 'unchanged',
                    'version': current_version.version,
                    'last_updated': current_version.last_updated
                }

        return results

    def run_incremental_update(self, force: bool = False) -> UpdateStats:
        """Run incremental update for all sources."""
        stats = UpdateStats()

        for source_name, config in SOURCES.items():
            result = self._update_source(source_name, config, force)
            stats.add_result(result)

        stats.finalize()
        return stats

    def _update_source(self, source_name: str, config: Dict, force: bool) -> UpdateResult:
        """Update a single source."""
        start_time = datetime.now()
        path = config['path']

        # Check if source exists
        if not path.exists():
            return UpdateResult(
                source_name=source_name,
                status='error',
                error_message=f"Source path not found: {path}",
                duration_seconds=(datetime.now() - start_time).total_seconds()
            )

        # Calculate new checksum
        if config['type'] == 'xml':
            new_checksum = calculate_file_checksum(path)
            new_version = extract_version_from_filename(path)
            source_path = str(path)
        elif config['type'] == 'stix_dir':
            latest_file = get_latest_stix_file(path)
            if not latest_file:
                return UpdateResult(
                    source_name=source_name,
                    status='error',
                    error_message=f"No STIX files found in: {path}",
                    duration_seconds=(datetime.now() - start_time).total_seconds()
                )
            new_checksum = calculate_file_checksum(latest_file)
            new_version = extract_version_from_filename(latest_file)
            source_path = str(latest_file)
        else:
            return UpdateResult(
                source_name=source_name,
                status='skipped',
                error_message=f"Unsupported source type: {config['type']}",
                duration_seconds=(datetime.now() - start_time).total_seconds()
            )

        # Check if update is needed
        current_version = self.get_source_version(source_name)

        if not force and current_version and current_version.checksum == new_checksum:
            return UpdateResult(
                source_name=source_name,
                status='unchanged',
                old_version=current_version.version,
                new_version=new_version,
                old_checksum=current_version.checksum,
                new_checksum=new_checksum,
                duration_seconds=(datetime.now() - start_time).total_seconds()
            )

        # Run appropriate update
        try:
            if source_name == 'cwe':
                records_added, records_updated = self._update_cwe(path)
            elif source_name == 'capec':
                records_added, records_updated = self._update_capec(path)
            elif source_name == 'attack_stix':
                records_added, records_updated = self._update_attack_stix(Path(source_path))
            else:
                return UpdateResult(
                    source_name=source_name,
                    status='skipped',
                    error_message=f"No update handler for: {source_name}",
                    duration_seconds=(datetime.now() - start_time).total_seconds()
                )

            # Update source version
            record_count = records_added + records_updated
            self.update_source_version(SourceVersion(
                source_name=source_name,
                file_path=source_path,
                version=new_version,
                checksum=new_checksum,
                record_count=record_count,
                last_updated=datetime.now().isoformat()
            ))

            return UpdateResult(
                source_name=source_name,
                status='updated',
                records_added=records_added,
                records_updated=records_updated,
                old_version=current_version.version if current_version else None,
                new_version=new_version,
                old_checksum=current_version.checksum if current_version else None,
                new_checksum=new_checksum,
                duration_seconds=(datetime.now() - start_time).total_seconds()
            )

        except Exception as e:
            self.conn.rollback()
            return UpdateResult(
                source_name=source_name,
                status='error',
                error_message=str(e),
                duration_seconds=(datetime.now() - start_time).total_seconds()
            )

    def _update_cwe(self, xml_path: Path) -> Tuple[int, int]:
        """Update CWE data from XML."""
        tree = ET.parse(xml_path)
        root = tree.getroot()

        added = 0
        updated = 0

        # Parse weaknesses
        weaknesses = root.findall('.//cwe:Weakness', CWE_NS)

        for weakness in weaknesses:
            cwe_num = weakness.get('ID')
            cwe_id = f"CWE-{cwe_num}"
            name = weakness.get('Name', '')
            abstraction = weakness.get('Abstraction', '')
            status = weakness.get('Status', '')

            # Get descriptions
            desc_elem = weakness.find('.//cwe:Description', CWE_NS)
            description = self._extract_text(desc_elem) if desc_elem is not None else ''

            ext_desc_elem = weakness.find('.//cwe:Extended_Description', CWE_NS)
            extended_description = self._extract_text(ext_desc_elem) if ext_desc_elem is not None else ''

            # Get likelihood
            likelihood = weakness.findtext('.//cwe:Likelihood_Of_Exploit', '', CWE_NS)

            # Build embedding text
            embedding_text = f"{cwe_id} {name} {description}"

            # Check if exists
            cursor = self.conn.execute("SELECT id FROM cwe WHERE id = ?", (cwe_id,))
            exists = cursor.fetchone() is not None

            self.conn.execute("""
                INSERT OR REPLACE INTO cwe
                (id, cwe_num, name, abstraction, status, description,
                 extended_description, likelihood_of_exploit, embedding_text)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (cwe_id, int(cwe_num), name, abstraction, status, description,
                  extended_description, likelihood, embedding_text))

            if exists:
                updated += 1
            else:
                added += 1

        self.conn.commit()
        return added, updated

    def _update_capec(self, xml_path: Path) -> Tuple[int, int]:
        """Update CAPEC data from XML."""
        tree = ET.parse(xml_path)
        root = tree.getroot()

        added = 0
        updated = 0

        # Parse attack patterns
        patterns = root.findall('.//capec:Attack_Pattern', CAPEC_NS)

        for pattern in patterns:
            capec_num = pattern.get('ID')
            capec_id = f"CAPEC-{capec_num}"
            name = pattern.get('Name', '')
            abstraction = pattern.get('Abstraction', '')
            status = pattern.get('Status', '')

            # Get description
            desc_elem = pattern.find('.//capec:Description', CAPEC_NS)
            description = self._extract_text(desc_elem) if desc_elem is not None else ''

            # Get severity and likelihood
            severity = pattern.findtext('.//capec:Typical_Severity', '', CAPEC_NS)
            likelihood = pattern.findtext('.//capec:Likelihood_Of_Attack', '', CAPEC_NS)

            # Get prerequisites
            prereq_elem = pattern.find('.//capec:Prerequisites', CAPEC_NS)
            prerequisites = self._extract_text(prereq_elem) if prereq_elem is not None else ''

            # Get skills required
            skills_elem = pattern.find('.//capec:Skills_Required', CAPEC_NS)
            skills_required = self._extract_text(skills_elem) if skills_elem is not None else ''

            # Get resources required
            resources_elem = pattern.find('.//capec:Resources_Required', CAPEC_NS)
            resources_required = self._extract_text(resources_elem) if resources_elem is not None else ''

            # Build embedding text
            embedding_text = f"{capec_id} {name} {description}"

            # Check if exists
            cursor = self.conn.execute("SELECT id FROM capec WHERE id = ?", (capec_id,))
            exists = cursor.fetchone() is not None

            self.conn.execute("""
                INSERT OR REPLACE INTO capec
                (id, capec_num, name, abstraction, status, description, severity,
                 likelihood_of_attack, prerequisites, skills_required, resources_required,
                 embedding_text)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (capec_id, int(capec_num), name, abstraction, status, description,
                  severity, likelihood, prerequisites, skills_required, resources_required,
                  embedding_text))

            if exists:
                updated += 1
            else:
                added += 1

        self.conn.commit()
        return added, updated

    def _update_attack_stix(self, stix_path: Path) -> Tuple[int, int]:
        """Update ATT&CK data from STIX bundle."""
        with open(stix_path, 'r') as f:
            bundle = json.load(f)

        added = 0
        updated = 0

        for obj in bundle.get('objects', []):
            if obj.get('type') != 'attack-pattern':
                continue

            # Get technique ID
            technique_id = None
            for ref in obj.get('external_references', []):
                if ref.get('source_name') == 'mitre-attack':
                    technique_id = ref.get('external_id')
                    break

            if not technique_id:
                continue

            name = obj.get('name', '')
            description = obj.get('description', '')

            # Get tactics from kill chain phases
            tactics = []
            for phase in obj.get('kill_chain_phases', []):
                if phase.get('kill_chain_name') == 'mitre-attack':
                    tactics.append(phase.get('phase_name', ''))
            tactics_str = ','.join(tactics)

            # Get platforms
            platforms = obj.get('x_mitre_platforms', [])
            platforms_str = ','.join(platforms) if platforms else ''

            # Check if exists
            cursor = self.conn.execute(
                "SELECT id FROM attack_technique WHERE id = ?",
                (technique_id,)
            )
            exists = cursor.fetchone() is not None

            self.conn.execute("""
                INSERT OR REPLACE INTO attack_technique
                (id, name, description, tactics, platforms)
                VALUES (?, ?, ?, ?, ?)
            """, (technique_id, name, description, tactics_str, platforms_str))

            if exists:
                updated += 1
            else:
                added += 1

        self.conn.commit()
        return added, updated

    def _extract_text(self, elem) -> str:
        """Extract text content from XML element, handling nested elements."""
        if elem is None:
            return ''
        text_parts = []
        if elem.text:
            text_parts.append(elem.text.strip())
        for child in elem:
            if child.text:
                text_parts.append(child.text.strip())
            if child.tail:
                text_parts.append(child.tail.strip())
        return ' '.join(text_parts)

    def get_status(self) -> Dict[str, Any]:
        """Get current status of all sources."""
        status = {
            'database': str(self.db_path),
            'sources': {}
        }

        for source_name in SOURCES.keys():
            version = self.get_source_version(source_name)
            if version:
                status['sources'][source_name] = {
                    'version': version.version,
                    'checksum': version.checksum[:8] + '...',
                    'record_count': version.record_count,
                    'last_updated': version.last_updated
                }
            else:
                status['sources'][source_name] = {
                    'status': 'never_updated'
                }

        return status


# ============================================================================
# CLI Interface
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description='Knowledge Base Incremental Update Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # Check for available updates
    python kb_incremental_update.py --check

    # Run incremental update (only changed sources)
    python kb_incremental_update.py --update

    # Force full update of all sources
    python kb_incremental_update.py --force

    # Show current version status
    python kb_incremental_update.py --status
        """
    )

    parser.add_argument('--check', action='store_true',
                        help='Check for available updates')
    parser.add_argument('--update', action='store_true',
                        help='Run incremental update')
    parser.add_argument('--force', action='store_true',
                        help='Force update all sources')
    parser.add_argument('--status', action='store_true',
                        help='Show current source versions')
    parser.add_argument('--db', type=Path, default=KB_SQLITE_PATH,
                        help='Database path')

    args = parser.parse_args()

    if not any([args.check, args.update, args.force, args.status]):
        parser.print_help()
        return

    updater = IncrementalUpdater(args.db)

    try:
        updater.connect()

        if args.status:
            print("\n" + "=" * 60)
            print("KNOWLEDGE BASE SOURCE STATUS")
            print("=" * 60)
            status = updater.get_status()
            print(f"Database: {status['database']}")
            print()
            for source, info in status['sources'].items():
                print(f"[{source}]")
                for k, v in info.items():
                    print(f"  {k}: {v}")
                print()

        if args.check:
            print("\n" + "=" * 60)
            print("CHECKING FOR UPDATES")
            print("=" * 60)
            updates = updater.check_for_updates()
            for source, info in updates.items():
                status = info.get('status', 'unknown')
                if status == 'changed':
                    print(f"[{source}] UPDATE AVAILABLE")
                    print(f"  Old version: {info.get('old_version')}")
                    print(f"  New version: {info.get('new_version')}")
                elif status == 'new':
                    print(f"[{source}] NEW SOURCE")
                    print(f"  Version: {info.get('new_version')}")
                elif status == 'unchanged':
                    print(f"[{source}] Up to date ({info.get('version')})")
                elif status == 'missing':
                    print(f"[{source}] MISSING: {info.get('path')}")
                print()

        if args.update or args.force:
            print("\n" + "=" * 60)
            print("RUNNING INCREMENTAL UPDATE" + (" (FORCED)" if args.force else ""))
            print("=" * 60)

            stats = updater.run_incremental_update(force=args.force)

            for result in stats.results:
                status_icon = {
                    'updated': '✓',
                    'unchanged': '○',
                    'error': '✗',
                    'skipped': '-'
                }.get(result.status, '?')

                print(f"[{status_icon}] {result.source_name}: {result.status}")

                if result.status == 'updated':
                    print(f"    Added: {result.records_added}, Updated: {result.records_updated}")
                    if result.old_version:
                        print(f"    Version: {result.old_version} → {result.new_version}")
                elif result.status == 'error':
                    print(f"    Error: {result.error_message}")

            print()
            print(f"Summary: {stats.sources_updated} updated, "
                  f"{stats.sources_unchanged} unchanged, "
                  f"{stats.sources_error} errors "
                  f"({stats.duration:.1f}s)")

    finally:
        updater.close()


if __name__ == '__main__':
    main()
