#!/usr/bin/env python3
"""
CVE Index Builder for STRIDE Threat Modeling.

Builds and maintains a SQLite index of CVE data from cvelistV5 repository.
Supports incremental updates based on file modification times.

Usage:
    # Full build (first time)
    python build_cve_index.py --full

    # Incremental update (daily updates)
    python build_cve_index.py --incremental

    # Check statistics
    python build_cve_index.py --stats

Data source: https://github.com/CVEProject/cvelistV5
"""

import argparse
import json
import logging
import os
import sqlite3
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, List, Any, Iterator

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Paths
SCRIPT_DIR = Path(__file__).parent
PROJECT_DIR = SCRIPT_DIR.parent
KNOWLEDGE_DIR = PROJECT_DIR / "assets" / "knowledge"
LIBRARY_DIR = Path.home() / "STRIDE" / "Library"
CVE_DIR = LIBRARY_DIR / "CVE" / "cvelistV5" / "cves"
DB_PATH = KNOWLEDGE_DIR / "security_kb_v2.sqlite"


@dataclass
class CVERecord:
    """Extracted CVE record data."""
    cve_id: str
    state: str
    date_published: Optional[str]
    date_updated: Optional[str]
    description: str
    cvss_version: Optional[str]
    cvss_score: Optional[float]
    cvss_severity: Optional[str]
    cvss_vector: Optional[str]
    cwes: List[str]
    vendors: List[str]
    products: List[str]
    source_file: str


class CVEIndexBuilder:
    """
    Builds and maintains CVE index in SQLite database.

    Features:
    - Incremental updates based on file timestamps
    - Parallel file processing for performance
    - FTS5 full-text search index
    - CWE linkage for threat chain queries
    """

    def __init__(self, db_path: Path = DB_PATH, cve_dir: Path = CVE_DIR):
        self.db_path = db_path
        self.cve_dir = cve_dir
        self.conn = None

    def connect(self) -> sqlite3.Connection:
        """Create database connection."""
        self.conn = sqlite3.connect(str(self.db_path))
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self.conn.execute("PRAGMA cache_size=-64000")  # 64MB cache
        return self.conn

    def close(self):
        """Close database connection."""
        if self.conn:
            self.conn.close()
            self.conn = None

    def create_schema(self):
        """Create CVE tables and indexes."""
        cursor = self.conn.cursor()

        # Main CVE table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS cve (
                id TEXT PRIMARY KEY,
                state TEXT NOT NULL,
                date_published TEXT,
                date_updated TEXT,
                description TEXT,
                cvss_version TEXT,
                cvss_score REAL,
                cvss_severity TEXT,
                cvss_vector TEXT,
                vendors TEXT,  -- JSON array
                products TEXT,  -- JSON array
                source_file TEXT,
                indexed_at TEXT NOT NULL
            )
        """)

        # CVE to CWE mapping table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS cve_cwe (
                cve_id TEXT NOT NULL,
                cwe_id TEXT NOT NULL,
                PRIMARY KEY (cve_id, cwe_id)
            )
        """)

        # Indexes for common queries
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_cve_state ON cve(state)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_cve_date_published ON cve(date_published)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_cve_date_updated ON cve(date_updated)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_cve_cvss_score ON cve(cvss_score)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_cve_cvss_severity ON cve(cvss_severity)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_cve_cwe_cwe ON cve_cwe(cwe_id)")

        # FTS5 full-text search index
        cursor.execute("""
            CREATE VIRTUAL TABLE IF NOT EXISTS cve_fts USING fts5(
                id,
                description,
                vendors,
                products,
                content='cve',
                content_rowid='rowid',
                tokenize='porter unicode61'
            )
        """)

        # Triggers to keep FTS in sync
        cursor.execute("""
            CREATE TRIGGER IF NOT EXISTS cve_ai AFTER INSERT ON cve BEGIN
                INSERT INTO cve_fts(rowid, id, description, vendors, products)
                VALUES (NEW.rowid, NEW.id, NEW.description, NEW.vendors, NEW.products);
            END
        """)
        cursor.execute("""
            CREATE TRIGGER IF NOT EXISTS cve_ad AFTER DELETE ON cve BEGIN
                INSERT INTO cve_fts(cve_fts, rowid, id, description, vendors, products)
                VALUES ('delete', OLD.rowid, OLD.id, OLD.description, OLD.vendors, OLD.products);
            END
        """)
        cursor.execute("""
            CREATE TRIGGER IF NOT EXISTS cve_au AFTER UPDATE ON cve BEGIN
                INSERT INTO cve_fts(cve_fts, rowid, id, description, vendors, products)
                VALUES ('delete', OLD.rowid, OLD.id, OLD.description, OLD.vendors, OLD.products);
                INSERT INTO cve_fts(rowid, id, description, vendors, products)
                VALUES (NEW.rowid, NEW.id, NEW.description, NEW.vendors, NEW.products);
            END
        """)

        # Index metadata table for incremental updates
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS cve_index_meta (
                key TEXT PRIMARY KEY,
                value TEXT
            )
        """)

        self.conn.commit()
        logger.info("CVE schema created/verified")

    def get_last_index_time(self) -> Optional[datetime]:
        """Get timestamp of last index build."""
        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT value FROM cve_index_meta WHERE key = 'last_index_time'"
        )
        row = cursor.fetchone()
        if row:
            return datetime.fromisoformat(row[0])
        return None

    def set_last_index_time(self, dt: datetime):
        """Set timestamp of last index build."""
        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO cve_index_meta (key, value)
            VALUES ('last_index_time', ?)
        """, (dt.isoformat(),))
        self.conn.commit()

    def iter_cve_files(self, since: Optional[datetime] = None) -> Iterator[Path]:
        """
        Iterate over CVE JSON files.

        Args:
            since: Only yield files modified after this time (for incremental)
        """
        if not self.cve_dir.exists():
            logger.error(f"CVE directory not found: {self.cve_dir}")
            return

        for year_dir in sorted(self.cve_dir.iterdir()):
            if not year_dir.is_dir() or not year_dir.name.isdigit():
                continue

            for sub_dir in year_dir.iterdir():
                if not sub_dir.is_dir():
                    continue

                for json_file in sub_dir.glob("CVE-*.json"):
                    if since:
                        mtime = datetime.fromtimestamp(json_file.stat().st_mtime)
                        if mtime <= since:
                            continue
                    yield json_file

    def parse_cve_file(self, file_path: Path) -> Optional[CVERecord]:
        """
        Parse a CVE JSON file and extract relevant fields.

        Args:
            file_path: Path to CVE JSON file

        Returns:
            CVERecord or None if parsing fails
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)

            # Extract metadata
            metadata = data.get('cveMetadata', {})
            cve_id = metadata.get('cveId', '')
            if not cve_id:
                return None

            state = metadata.get('state', 'UNKNOWN')
            date_published = metadata.get('datePublished')
            date_updated = metadata.get('dateUpdated')

            # Extract from CNA container
            cna = data.get('containers', {}).get('cna', {})

            # Description (prefer English)
            description = ""
            for desc in cna.get('descriptions', []):
                if desc.get('lang', '').startswith('en'):
                    description = desc.get('value', '')
                    break
            if not description and cna.get('descriptions'):
                description = cna['descriptions'][0].get('value', '')

            # CVSS metrics
            cvss_version = None
            cvss_score = None
            cvss_severity = None
            cvss_vector = None

            for metric in cna.get('metrics', []):
                # Try CVSS 3.1, 3.0, then 2.0
                for ver in ['cvssV3_1', 'cvssV3_0', 'cvssV2_0']:
                    if ver in metric:
                        cvss_data = metric[ver]
                        cvss_version = ver.replace('_', '.')
                        cvss_score = cvss_data.get('baseScore')
                        cvss_severity = cvss_data.get('baseSeverity')
                        cvss_vector = cvss_data.get('vectorString')
                        break
                if cvss_score:
                    break

            # CWE IDs
            cwes = []
            for problem_type in cna.get('problemTypes', []):
                for desc in problem_type.get('descriptions', []):
                    cwe_id = desc.get('cweId', '')
                    if cwe_id and cwe_id.startswith('CWE-'):
                        cwes.append(cwe_id)

            # Vendors and products
            vendors = set()
            products = set()
            for affected in cna.get('affected', []):
                vendor = affected.get('vendor', '')
                product = affected.get('product', '')
                if vendor:
                    vendors.add(vendor)
                if product:
                    products.add(product)

            return CVERecord(
                cve_id=cve_id,
                state=state,
                date_published=date_published,
                date_updated=date_updated,
                description=description[:10000],  # Limit length
                cvss_version=cvss_version,
                cvss_score=cvss_score,
                cvss_severity=cvss_severity,
                cvss_vector=cvss_vector,
                cwes=list(set(cwes)),
                vendors=list(vendors),
                products=list(products),
                source_file=str(file_path.relative_to(self.cve_dir))
            )

        except json.JSONDecodeError as e:
            logger.warning(f"JSON parse error in {file_path}: {e}")
            return None
        except Exception as e:
            logger.warning(f"Error parsing {file_path}: {e}")
            return None

    def insert_cve(self, record: CVERecord):
        """Insert or update a CVE record."""
        cursor = self.conn.cursor()
        now = datetime.now().isoformat()

        # Upsert CVE record
        cursor.execute("""
            INSERT OR REPLACE INTO cve (
                id, state, date_published, date_updated,
                description, cvss_version, cvss_score, cvss_severity, cvss_vector,
                vendors, products, source_file, indexed_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            record.cve_id,
            record.state,
            record.date_published,
            record.date_updated,
            record.description,
            record.cvss_version,
            record.cvss_score,
            record.cvss_severity,
            record.cvss_vector,
            json.dumps(record.vendors),
            json.dumps(record.products),
            record.source_file,
            now
        ))

        # Update CWE mappings
        cursor.execute("DELETE FROM cve_cwe WHERE cve_id = ?", (record.cve_id,))
        for cwe_id in record.cwes:
            cursor.execute(
                "INSERT OR IGNORE INTO cve_cwe (cve_id, cwe_id) VALUES (?, ?)",
                (record.cve_id, cwe_id)
            )

    def build_full(self, workers: int = 8, batch_size: int = 1000):
        """
        Build complete CVE index from scratch.

        Args:
            workers: Number of parallel file readers
            batch_size: Commit after this many records
        """
        logger.info("Starting full CVE index build...")
        start_time = datetime.now()

        self.create_schema()

        # Clear existing data
        cursor = self.conn.cursor()
        cursor.execute("DELETE FROM cve")
        cursor.execute("DELETE FROM cve_cwe")
        cursor.execute("DELETE FROM cve_fts")
        self.conn.commit()

        # Collect all files
        files = list(self.iter_cve_files())
        total_files = len(files)
        logger.info(f"Found {total_files:,} CVE files to process")

        # Process files in parallel
        processed = 0
        errors = 0
        batch = []

        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {executor.submit(self.parse_cve_file, f): f for f in files}

            for future in as_completed(futures):
                try:
                    record = future.result()
                    if record:
                        batch.append(record)

                        if len(batch) >= batch_size:
                            for r in batch:
                                self.insert_cve(r)
                            self.conn.commit()
                            processed += len(batch)
                            batch = []

                            if processed % 10000 == 0:
                                elapsed = (datetime.now() - start_time).total_seconds()
                                rate = processed / elapsed if elapsed > 0 else 0
                                logger.info(
                                    f"Processed {processed:,}/{total_files:,} "
                                    f"({100*processed/total_files:.1f}%) - "
                                    f"{rate:.0f} records/sec"
                                )
                    else:
                        errors += 1
                except Exception as e:
                    errors += 1
                    logger.warning(f"Processing error: {e}")

        # Final batch
        if batch:
            for r in batch:
                self.insert_cve(r)
            self.conn.commit()
            processed += len(batch)

        # Update metadata
        self.set_last_index_time(start_time)

        elapsed = (datetime.now() - start_time).total_seconds()
        logger.info(
            f"Full build complete: {processed:,} records in {elapsed:.1f}s "
            f"({errors} errors)"
        )

        return processed, errors

    def build_incremental(self, workers: int = 4):
        """
        Update index with only changed files since last build.
        """
        last_time = self.get_last_index_time()
        if not last_time:
            logger.warning("No previous build found, running full build")
            return self.build_full(workers)

        logger.info(f"Starting incremental update (since {last_time})")
        start_time = datetime.now()

        # Find changed files
        files = list(self.iter_cve_files(since=last_time))
        if not files:
            logger.info("No new or modified CVE files found")
            return 0, 0

        logger.info(f"Found {len(files):,} modified CVE files")

        # Process files
        processed = 0
        errors = 0

        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {executor.submit(self.parse_cve_file, f): f for f in files}

            for future in as_completed(futures):
                try:
                    record = future.result()
                    if record:
                        self.insert_cve(record)
                        processed += 1

                        if processed % 100 == 0:
                            self.conn.commit()
                    else:
                        errors += 1
                except Exception as e:
                    errors += 1
                    logger.warning(f"Processing error: {e}")

        self.conn.commit()
        self.set_last_index_time(start_time)

        elapsed = (datetime.now() - start_time).total_seconds()
        logger.info(
            f"Incremental update complete: {processed:,} records in {elapsed:.1f}s "
            f"({errors} errors)"
        )

        return processed, errors

    def get_statistics(self) -> Dict[str, Any]:
        """Get index statistics."""
        cursor = self.conn.cursor()
        stats = {}

        # Total CVEs
        cursor.execute("SELECT COUNT(*) FROM cve")
        stats['total_cves'] = cursor.fetchone()[0]

        # By state
        cursor.execute("""
            SELECT state, COUNT(*) FROM cve GROUP BY state ORDER BY COUNT(*) DESC
        """)
        stats['by_state'] = {row[0]: row[1] for row in cursor.fetchall()}

        # By severity
        cursor.execute("""
            SELECT cvss_severity, COUNT(*) FROM cve
            WHERE cvss_severity IS NOT NULL
            GROUP BY cvss_severity ORDER BY COUNT(*) DESC
        """)
        stats['by_severity'] = {row[0]: row[1] for row in cursor.fetchall()}

        # By year
        cursor.execute("""
            SELECT substr(id, 5, 4) as year, COUNT(*) FROM cve
            GROUP BY year ORDER BY year DESC LIMIT 10
        """)
        stats['by_year'] = {row[0]: row[1] for row in cursor.fetchall()}

        # CWE mappings
        cursor.execute("SELECT COUNT(DISTINCT cve_id) FROM cve_cwe")
        stats['cves_with_cwe'] = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(DISTINCT cwe_id) FROM cve_cwe")
        stats['unique_cwes'] = cursor.fetchone()[0]

        # Top CWEs
        cursor.execute("""
            SELECT cwe_id, COUNT(*) as cnt FROM cve_cwe
            GROUP BY cwe_id ORDER BY cnt DESC LIMIT 10
        """)
        stats['top_cwes'] = {row[0]: row[1] for row in cursor.fetchall()}

        # Index metadata
        cursor.execute("SELECT * FROM cve_index_meta")
        stats['metadata'] = {row[0]: row[1] for row in cursor.fetchall()}

        return stats


def main():
    parser = argparse.ArgumentParser(
        description="Build CVE index for STRIDE threat modeling"
    )
    parser.add_argument(
        '--full', action='store_true',
        help="Build complete index from scratch"
    )
    parser.add_argument(
        '--incremental', action='store_true',
        help="Update index with changed files only"
    )
    parser.add_argument(
        '--stats', action='store_true',
        help="Show index statistics"
    )
    parser.add_argument(
        '--workers', type=int, default=8,
        help="Number of parallel workers (default: 8)"
    )
    parser.add_argument(
        '--cve-dir', type=str,
        help="Path to CVE data directory"
    )

    args = parser.parse_args()

    # Validate
    if not any([args.full, args.incremental, args.stats]):
        parser.print_help()
        sys.exit(1)

    cve_dir = Path(args.cve_dir) if args.cve_dir else CVE_DIR

    builder = CVEIndexBuilder(DB_PATH, cve_dir)

    try:
        builder.connect()

        if args.stats:
            stats = builder.get_statistics()
            print(json.dumps(stats, indent=2))
        elif args.full:
            builder.build_full(workers=args.workers)
            stats = builder.get_statistics()
            print(f"\nIndex statistics:")
            print(f"  Total CVEs: {stats['total_cves']:,}")
            print(f"  CVEs with CWE: {stats['cves_with_cwe']:,}")
            print(f"  Unique CWEs: {stats['unique_cwes']}")
        elif args.incremental:
            processed, errors = builder.build_incremental(workers=args.workers)
            if processed > 0:
                stats = builder.get_statistics()
                print(f"Updated {processed:,} records ({errors} errors)")
                print(f"Total CVEs in index: {stats['total_cves']:,}")
    finally:
        builder.close()


if __name__ == "__main__":
    main()
