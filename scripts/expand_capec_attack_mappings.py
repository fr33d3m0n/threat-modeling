#!/usr/bin/env python3
"""
CAPEC→ATT&CK Mapping Expansion Module

Extracts comprehensive CAPEC→ATT&CK mappings from:
1. CAPEC XML Taxonomy_Mappings (primary source - 272+ records)
2. ATT&CK STIX external_references (secondary source - 36+ records)

This module addresses the gap where only 36 mappings were previously extracted.

Usage:
    python expand_capec_attack_mappings.py --extract     # Extract to JSON
    python expand_capec_attack_mappings.py --import-db   # Import to SQLite
    python expand_capec_attack_mappings.py --stats       # Show statistics
    python expand_capec_attack_mappings.py --verify      # Verify mappings
"""

import argparse
import json
import re
import sqlite3
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

# ============================================================================
# Configuration
# ============================================================================

# Path configuration
SCRIPT_DIR = Path(__file__).parent
THREAT_MODELING_DIR = SCRIPT_DIR.parent
LIBRARY_DIR = Path("/home/elly/STRIDE/Library")

# Data sources
CAPEC_XML_PATH = LIBRARY_DIR / "CAPEC" / "capec_v3.9.xml"
ATTACK_STIX_PATH = LIBRARY_DIR / "ATTACK" / "attack-stix-data" / "enterprise-attack"
KB_SQLITE_PATH = THREAT_MODELING_DIR / "assets" / "knowledge" / "security_kb.sqlite"

# XML namespace
CAPEC_NS = {'capec': 'http://capec.mitre.org/capec-3'}


# ============================================================================
# Data Classes
# ============================================================================

@dataclass
class CAPECATTACKMapping:
    """Represents a single CAPEC→ATT&CK mapping."""
    capec_id: str
    attack_id: str
    attack_name: str
    source: str  # 'capec_xml' or 'attack_stix'
    capec_name: Optional[str] = None

    def __hash__(self):
        return hash((self.capec_id, self.attack_id))

    def __eq__(self, other):
        if not isinstance(other, CAPECATTACKMapping):
            return False
        return self.capec_id == other.capec_id and self.attack_id == other.attack_id


@dataclass
class ExtractionStats:
    """Statistics for extraction process."""
    capec_xml_mappings: int = 0
    attack_stix_mappings: int = 0
    total_unique_mappings: int = 0
    unique_capec_ids: int = 0
    unique_attack_ids: int = 0
    duplicate_count: int = 0
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            'capec_xml_mappings': self.capec_xml_mappings,
            'attack_stix_mappings': self.attack_stix_mappings,
            'total_unique_mappings': self.total_unique_mappings,
            'unique_capec_ids': self.unique_capec_ids,
            'unique_attack_ids': self.unique_attack_ids,
            'duplicate_count': self.duplicate_count,
            'errors': self.errors,
            'extraction_time': datetime.now().isoformat()
        }


# ============================================================================
# Extraction Functions
# ============================================================================

def normalize_attack_id(entry_id: str) -> str:
    """
    Normalize ATT&CK Entry_ID to standard format.

    Examples:
        "1574.010" -> "T1574.010"
        "1110" -> "T1110"
        "T1574" -> "T1574"
    """
    entry_id = entry_id.strip()

    # Already has T prefix
    if entry_id.upper().startswith('T'):
        return entry_id.upper()

    # Handle sub-technique format (1574.010)
    if '.' in entry_id:
        parts = entry_id.split('.')
        return f"T{parts[0]}.{parts[1].zfill(3)}"

    # Simple technique ID
    return f"T{entry_id}"


def normalize_capec_id(capec_id: str) -> str:
    """
    Normalize CAPEC ID to standard format.

    Examples:
        "114" -> "CAPEC-114"
        "CAPEC-114" -> "CAPEC-114"
    """
    capec_id = capec_id.strip()

    if capec_id.upper().startswith('CAPEC-'):
        return capec_id.upper()

    return f"CAPEC-{capec_id}"


def extract_from_capec_xml(capec_path: Path) -> Tuple[List[CAPECATTACKMapping], List[str]]:
    """
    Extract CAPEC→ATT&CK mappings from CAPEC XML.

    Parses Taxonomy_Mapping elements with Taxonomy_Name="ATTACK".

    Returns:
        Tuple of (mappings list, errors list)
    """
    mappings = []
    errors = []

    if not capec_path.exists():
        errors.append(f"CAPEC XML not found: {capec_path}")
        return mappings, errors

    try:
        tree = ET.parse(capec_path)
        root = tree.getroot()
    except ET.ParseError as e:
        errors.append(f"Failed to parse CAPEC XML: {e}")
        return mappings, errors

    # Find all Attack_Pattern elements
    patterns = root.findall('.//capec:Attack_Pattern', CAPEC_NS)

    for pattern in patterns:
        capec_num = pattern.get('ID')
        capec_name = pattern.get('Name')

        if not capec_num:
            continue

        capec_id = normalize_capec_id(capec_num)

        # Find all ATT&CK taxonomy mappings within this pattern
        attack_mappings = pattern.findall(
            './/capec:Taxonomy_Mapping[@Taxonomy_Name="ATTACK"]',
            CAPEC_NS
        )

        for mapping in attack_mappings:
            entry_id_elem = mapping.find('capec:Entry_ID', CAPEC_NS)
            entry_name_elem = mapping.find('capec:Entry_Name', CAPEC_NS)

            if entry_id_elem is None or entry_id_elem.text is None:
                continue

            entry_id = entry_id_elem.text.strip()
            entry_name = entry_name_elem.text.strip() if entry_name_elem is not None and entry_name_elem.text else ""

            try:
                attack_id = normalize_attack_id(entry_id)
                mappings.append(CAPECATTACKMapping(
                    capec_id=capec_id,
                    attack_id=attack_id,
                    attack_name=entry_name,
                    source='capec_xml',
                    capec_name=capec_name
                ))
            except Exception as e:
                errors.append(f"Failed to normalize ATT&CK ID '{entry_id}': {e}")

    return mappings, errors


def is_valid_capec_id(capec_id: str) -> bool:
    """
    Validate CAPEC ID has proper format with numeric component.

    Old ATT&CK STIX files (v7.0-7.2) contain malformed IDs like
    "CAPEC-capec" or "CAPEC-CAPEC" which should be filtered out.
    """
    if not capec_id:
        return False
    # Must contain at least one digit
    return any(c.isdigit() for c in capec_id)


def get_latest_stix_file(stix_dir: Path) -> Optional[Path]:
    """
    Find the latest enterprise-attack STIX bundle file.

    Returns the file with highest version number to avoid
    processing outdated data with known data quality issues.
    """
    stix_files = list(stix_dir.glob("enterprise-attack-*.json"))
    if not stix_files:
        return None

    # Sort by version number (extract from filename)
    def get_version(f: Path) -> tuple:
        name = f.stem  # enterprise-attack-10.0
        version_str = name.replace('enterprise-attack-', '')
        try:
            parts = version_str.split('.')
            return tuple(int(p) for p in parts)
        except ValueError:
            return (0,)

    stix_files.sort(key=get_version, reverse=True)
    return stix_files[0] if stix_files else None


def extract_from_attack_stix(stix_dir: Path) -> Tuple[List[CAPECATTACKMapping], List[str]]:
    """
    Extract CAPEC→ATT&CK mappings from ATT&CK STIX data.

    Parses external_references with source_name="capec".
    Only processes the latest STIX bundle to avoid duplicate
    and malformed data from older versions.

    Returns:
        Tuple of (mappings list, errors list)
    """
    mappings = []
    errors = []

    # Use only the latest STIX file
    stix_file = get_latest_stix_file(stix_dir)

    if not stix_file:
        errors.append(f"No enterprise-attack STIX files found in: {stix_dir}")
        return mappings, errors

    try:
        with open(stix_file, 'r', encoding='utf-8') as f:
            bundle = json.load(f)
    except json.JSONDecodeError as e:
        errors.append(f"Failed to parse {stix_file}: {e}")
        return mappings, errors

    objects = bundle.get('objects', [])

    for obj in objects:
        if obj.get('type') != 'attack-pattern':
            continue

        # Get ATT&CK technique ID
        attack_id = None
        attack_name = obj.get('name', '')

        for ref in obj.get('external_references', []):
            if ref.get('source_name') == 'mitre-attack':
                attack_id = ref.get('external_id')
                break

        if not attack_id:
            continue

        # Find CAPEC references
        for ref in obj.get('external_references', []):
            if ref.get('source_name') == 'capec':
                capec_id = ref.get('external_id')
                # Validate CAPEC ID format
                if capec_id and is_valid_capec_id(capec_id):
                    mappings.append(CAPECATTACKMapping(
                        capec_id=normalize_capec_id(capec_id),
                        attack_id=attack_id,
                        attack_name=attack_name,
                        source='attack_stix'
                    ))
                elif capec_id:
                    errors.append(f"Invalid CAPEC ID '{capec_id}' for {attack_id}")

    return mappings, errors


def merge_mappings(
    capec_mappings: List[CAPECATTACKMapping],
    stix_mappings: List[CAPECATTACKMapping]
) -> Tuple[List[CAPECATTACKMapping], int]:
    """
    Merge mappings from both sources, removing duplicates.

    Priority: CAPEC XML > ATT&CK STIX (for source attribution)

    Returns:
        Tuple of (unique mappings list, duplicate count)
    """
    seen: Set[Tuple[str, str]] = set()
    unique_mappings = []
    duplicate_count = 0

    # Process CAPEC XML first (higher priority)
    for mapping in capec_mappings:
        key = (mapping.capec_id, mapping.attack_id)
        if key not in seen:
            seen.add(key)
            unique_mappings.append(mapping)

    # Process STIX mappings (add only if not seen)
    for mapping in stix_mappings:
        key = (mapping.capec_id, mapping.attack_id)
        if key not in seen:
            seen.add(key)
            unique_mappings.append(mapping)
        else:
            duplicate_count += 1

    return unique_mappings, duplicate_count


# ============================================================================
# Database Operations
# ============================================================================

def import_to_database(mappings: List[CAPECATTACKMapping], db_path: Path, dry_run: bool = False) -> Dict:
    """
    Import mappings to SQLite database.

    Args:
        mappings: List of mappings to import
        db_path: Path to SQLite database
        dry_run: If True, don't commit changes

    Returns:
        Import statistics dictionary
    """
    result = {
        'inserted': 0,
        'updated': 0,
        'skipped': 0,
        'errors': []
    }

    if not db_path.exists():
        result['errors'].append(f"Database not found: {db_path}")
        return result

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    try:
        # Check current count
        cursor.execute("SELECT COUNT(*) FROM capec_attack")
        before_count = cursor.fetchone()[0]

        for mapping in mappings:
            try:
                cursor.execute("""
                    INSERT INTO capec_attack (capec_id, attack_id, source)
                    VALUES (?, ?, ?)
                    ON CONFLICT(capec_id, attack_id) DO UPDATE SET source = excluded.source
                """, (mapping.capec_id, mapping.attack_id, mapping.source))

                if cursor.rowcount > 0:
                    result['inserted'] += 1
                else:
                    result['skipped'] += 1

            except sqlite3.Error as e:
                result['errors'].append(f"Failed to insert {mapping.capec_id}->{mapping.attack_id}: {e}")

        if not dry_run:
            conn.commit()

            # Verify final count
            cursor.execute("SELECT COUNT(*) FROM capec_attack")
            after_count = cursor.fetchone()[0]
            result['before_count'] = before_count
            result['after_count'] = after_count
        else:
            result['dry_run'] = True
            conn.rollback()

    except sqlite3.Error as e:
        result['errors'].append(f"Database error: {e}")
        conn.rollback()
    finally:
        conn.close()

    return result


def verify_mappings(db_path: Path) -> Dict:
    """
    Verify CAPEC→ATT&CK mappings in database.

    Checks for:
    - Orphan CAPEC IDs (not in capec table)
    - Orphan ATT&CK IDs (not in attack_technique table)
    - Mapping statistics

    Returns:
        Verification results dictionary
    """
    result = {
        'total_mappings': 0,
        'valid_mappings': 0,
        'orphan_capec': [],
        'orphan_attack': [],
        'source_breakdown': {},
        'top_capec_mapped': [],
        'top_attack_mapped': []
    }

    if not db_path.exists():
        result['error'] = f"Database not found: {db_path}"
        return result

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    try:
        # Total count
        cursor.execute("SELECT COUNT(*) FROM capec_attack")
        result['total_mappings'] = cursor.fetchone()[0]

        # Source breakdown
        cursor.execute("""
            SELECT source, COUNT(*) as cnt
            FROM capec_attack
            GROUP BY source
        """)
        result['source_breakdown'] = dict(cursor.fetchall())

        # Check for orphan CAPEC IDs
        cursor.execute("""
            SELECT DISTINCT ca.capec_id
            FROM capec_attack ca
            LEFT JOIN capec c ON ca.capec_id = c.id
            WHERE c.id IS NULL
        """)
        result['orphan_capec'] = [row[0] for row in cursor.fetchall()]

        # Check for orphan ATT&CK IDs
        cursor.execute("""
            SELECT DISTINCT ca.attack_id
            FROM capec_attack ca
            LEFT JOIN attack_technique at ON ca.attack_id = at.id
            WHERE at.id IS NULL
        """)
        result['orphan_attack'] = [row[0] for row in cursor.fetchall()]

        # Valid mappings (both sides exist)
        cursor.execute("""
            SELECT COUNT(*)
            FROM capec_attack ca
            JOIN capec c ON ca.capec_id = c.id
            JOIN attack_technique at ON ca.attack_id = at.id
        """)
        result['valid_mappings'] = cursor.fetchone()[0]

        # Top CAPEC patterns with most ATT&CK mappings
        cursor.execute("""
            SELECT capec_id, COUNT(*) as cnt
            FROM capec_attack
            GROUP BY capec_id
            ORDER BY cnt DESC
            LIMIT 10
        """)
        result['top_capec_mapped'] = cursor.fetchall()

        # Top ATT&CK techniques with most CAPEC mappings
        cursor.execute("""
            SELECT attack_id, COUNT(*) as cnt
            FROM capec_attack
            GROUP BY attack_id
            ORDER BY cnt DESC
            LIMIT 10
        """)
        result['top_attack_mapped'] = cursor.fetchall()

        # Unique counts
        cursor.execute("SELECT COUNT(DISTINCT capec_id) FROM capec_attack")
        result['unique_capec'] = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(DISTINCT attack_id) FROM capec_attack")
        result['unique_attack'] = cursor.fetchone()[0]

    except sqlite3.Error as e:
        result['error'] = str(e)
    finally:
        conn.close()

    return result


# ============================================================================
# CLI Functions
# ============================================================================

def run_extraction(output_path: Optional[Path] = None) -> Tuple[List[CAPECATTACKMapping], ExtractionStats]:
    """
    Run full extraction from all sources.

    Returns:
        Tuple of (mappings list, extraction stats)
    """
    stats = ExtractionStats()

    print("[Phase 1] Extracting from CAPEC XML...")
    capec_mappings, capec_errors = extract_from_capec_xml(CAPEC_XML_PATH)
    stats.capec_xml_mappings = len(capec_mappings)
    stats.errors.extend(capec_errors)
    print(f"  ✓ Extracted {len(capec_mappings)} mappings from CAPEC XML")

    print("[Phase 2] Extracting from ATT&CK STIX...")
    stix_mappings, stix_errors = extract_from_attack_stix(ATTACK_STIX_PATH)
    stats.attack_stix_mappings = len(stix_mappings)
    stats.errors.extend(stix_errors)
    print(f"  ✓ Extracted {len(stix_mappings)} mappings from ATT&CK STIX")

    print("[Phase 3] Merging and deduplicating...")
    unique_mappings, duplicates = merge_mappings(capec_mappings, stix_mappings)
    stats.total_unique_mappings = len(unique_mappings)
    stats.duplicate_count = duplicates
    print(f"  ✓ Total unique mappings: {len(unique_mappings)}")
    print(f"  ✓ Duplicates removed: {duplicates}")

    # Calculate unique IDs
    stats.unique_capec_ids = len(set(m.capec_id for m in unique_mappings))
    stats.unique_attack_ids = len(set(m.attack_id for m in unique_mappings))

    # Optionally save to JSON
    if output_path:
        output_data = {
            'stats': stats.to_dict(),
            'mappings': [
                {
                    'capec_id': m.capec_id,
                    'attack_id': m.attack_id,
                    'attack_name': m.attack_name,
                    'source': m.source,
                    'capec_name': m.capec_name
                }
                for m in unique_mappings
            ]
        }
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(output_data, f, indent=2, ensure_ascii=False)
        print(f"\n✓ Saved to {output_path}")

    return unique_mappings, stats


def main():
    parser = argparse.ArgumentParser(
        description='CAPEC→ATT&CK Mapping Expansion Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # Extract mappings and save to JSON
    python expand_capec_attack_mappings.py --extract -o mappings.json

    # Import to database
    python expand_capec_attack_mappings.py --import-db

    # Dry run (test without committing)
    python expand_capec_attack_mappings.py --import-db --dry-run

    # Verify current database mappings
    python expand_capec_attack_mappings.py --verify

    # Show statistics
    python expand_capec_attack_mappings.py --stats
        """
    )

    parser.add_argument('--extract', action='store_true',
                        help='Extract mappings from sources')
    parser.add_argument('--import-db', action='store_true',
                        help='Import mappings to SQLite database')
    parser.add_argument('--verify', action='store_true',
                        help='Verify database mappings')
    parser.add_argument('--stats', action='store_true',
                        help='Show extraction statistics')
    parser.add_argument('--dry-run', action='store_true',
                        help='Test import without committing')
    parser.add_argument('-o', '--output', type=Path,
                        help='Output JSON file path')
    parser.add_argument('--db', type=Path, default=KB_SQLITE_PATH,
                        help='SQLite database path')
    parser.add_argument('--pretty', '-p', action='store_true',
                        help='Pretty print output')

    args = parser.parse_args()

    if not any([args.extract, args.import_db, args.verify, args.stats]):
        parser.print_help()
        return

    if args.extract or args.import_db or args.stats:
        mappings, stats = run_extraction(args.output if args.extract else None)

        if args.stats:
            print("\n" + "="*60)
            print("EXTRACTION STATISTICS")
            print("="*60)
            print(f"CAPEC XML mappings:     {stats.capec_xml_mappings}")
            print(f"ATT&CK STIX mappings:   {stats.attack_stix_mappings}")
            print(f"Total unique mappings:  {stats.total_unique_mappings}")
            print(f"Unique CAPEC IDs:       {stats.unique_capec_ids}")
            print(f"Unique ATT&CK IDs:      {stats.unique_attack_ids}")
            print(f"Duplicates removed:     {stats.duplicate_count}")
            if stats.errors:
                print(f"Errors: {len(stats.errors)}")

        if args.import_db:
            print("\n[Phase 4] Importing to database...")
            result = import_to_database(mappings, args.db, args.dry_run)

            if args.dry_run:
                print("  [DRY RUN - no changes committed]")

            print(f"  ✓ Inserted: {result['inserted']}")
            print(f"  ✓ Skipped:  {result['skipped']}")

            if 'before_count' in result:
                print(f"  ✓ Before: {result['before_count']} → After: {result['after_count']}")

            if result['errors']:
                print(f"  ⚠ Errors: {len(result['errors'])}")

    if args.verify:
        print("\n" + "="*60)
        print("DATABASE VERIFICATION")
        print("="*60)
        result = verify_mappings(args.db)

        if args.pretty:
            print(json.dumps(result, indent=2, ensure_ascii=False))
        else:
            print(f"Total mappings:    {result['total_mappings']}")
            print(f"Valid mappings:    {result['valid_mappings']}")
            print(f"Unique CAPEC:      {result.get('unique_capec', 'N/A')}")
            print(f"Unique ATT&CK:     {result.get('unique_attack', 'N/A')}")
            print(f"Orphan CAPEC:      {len(result['orphan_capec'])}")
            print(f"Orphan ATT&CK:     {len(result['orphan_attack'])}")
            print(f"\nSource breakdown:")
            for source, count in result['source_breakdown'].items():
                print(f"  {source}: {count}")

            if result['orphan_attack']:
                print(f"\n⚠ Orphan ATT&CK IDs (first 10):")
                for attack_id in result['orphan_attack'][:10]:
                    print(f"  - {attack_id}")


if __name__ == '__main__':
    main()
