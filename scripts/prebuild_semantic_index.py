#!/usr/bin/env python3
"""
Semantic Search Index Pre-builder.

Pre-computes embeddings from knowledge base tables (CWE, CAPEC, ATT&CK, etc.)
and saves them for fast loading at startup.

Performance: ~30s cold start → ~100ms with pre-built index

Usage:
  python prebuild_semantic_index.py build      # Build index
  python prebuild_semantic_index.py check      # Check if index is fresh
  python prebuild_semantic_index.py stats      # Show statistics
  python prebuild_semantic_index.py test-search "SQL injection"  # Test search
"""

import hashlib
import json
import sqlite3
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import numpy as np

# Paths
SCRIPT_DIR = Path(__file__).parent
KNOWLEDGE_DIR = SCRIPT_DIR.parent / "assets" / "knowledge"
KB_SQLITE_PATH = KNOWLEDGE_DIR / "security_kb_v2.sqlite"
INDEX_DIR = KNOWLEDGE_DIR / "semantic_index"


# Table configurations for embedding extraction
TABLE_CONFIGS = {
    "cwe": {
        "query": """
            SELECT id, name,
                   COALESCE(embedding_text, description, name) as text
            FROM cwe
            WHERE status != 'Deprecated'
        """,
        "id_col": 0,
        "name_col": 1,
        "text_col": 2,
    },
    "capec": {
        "query": """
            SELECT id, name,
                   COALESCE(embedding_text, description, name) as text
            FROM capec
            WHERE status != 'Deprecated'
        """,
        "id_col": 0,
        "name_col": 1,
        "text_col": 2,
    },
    "attack": {
        "query": """
            SELECT id, name,
                   COALESCE(embedding_text, description, name) as text
            FROM attack_technique
        """,
        "id_col": 0,
        "name_col": 1,
        "text_col": 2,
    },
    "stride": {
        "query": """
            SELECT id, name,
                   name || ': ' || security_property || '. ' || COALESCE(description, '') as text
            FROM stride_category
        """,
        "id_col": 0,
        "name_col": 1,
        "text_col": 2,
    },
    "owasp": {
        "query": """
            SELECT id, name, description as text
            FROM owasp_top10
        """,
        "id_col": 0,
        "name_col": 1,
        "text_col": 2,
    },
}


@dataclass
class IndexMetadata:
    """Metadata for the pre-built index."""
    created_at: str = ""
    embedding_count: int = 0
    embedding_dim: int = 384  # all-MiniLM-L6-v2 dimension
    model_name: str = "all-MiniLM-L6-v2"
    source_db_checksum: str = ""
    type_counts: Dict[str, int] = field(default_factory=dict)
    build_time_seconds: float = 0.0
    version: str = "1.0"

    def to_dict(self) -> dict:
        return {
            "created_at": self.created_at,
            "embedding_count": self.embedding_count,
            "embedding_dim": self.embedding_dim,
            "model_name": self.model_name,
            "source_db_checksum": self.source_db_checksum,
            "type_counts": self.type_counts,
            "build_time_seconds": self.build_time_seconds,
            "version": self.version,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "IndexMetadata":
        return cls(
            created_at=data.get("created_at", ""),
            embedding_count=data.get("embedding_count", 0),
            embedding_dim=data.get("embedding_dim", 384),
            model_name=data.get("model_name", "all-MiniLM-L6-v2"),
            source_db_checksum=data.get("source_db_checksum", ""),
            type_counts=data.get("type_counts", {}),
            build_time_seconds=data.get("build_time_seconds", 0.0),
            version=data.get("version", "1.0"),
        )


@dataclass
class EmbeddingRecord:
    """Single embedding record."""
    id: str
    type: str
    name: str
    text: str
    embedding: Optional[np.ndarray] = None


class SemanticIndexBuilder:
    """Builds semantic search index from knowledge base tables."""

    def __init__(self, db_path: Path = KB_SQLITE_PATH):
        self.db_path = db_path
        self.conn: Optional[sqlite3.Connection] = None
        self.model = None

    def connect(self) -> None:
        """Connect to database."""
        if not self.db_path.exists():
            raise FileNotFoundError(f"Database not found: {self.db_path}")
        self.conn = sqlite3.connect(self.db_path)

    def close(self) -> None:
        """Close database connection."""
        if self.conn:
            self.conn.close()
            self.conn = None

    def _load_model(self):
        """Lazy load sentence-transformers model."""
        if self.model is None:
            try:
                from sentence_transformers import SentenceTransformer
                print("Loading sentence-transformers model...")
                self.model = SentenceTransformer('all-MiniLM-L6-v2')
            except ImportError:
                raise ImportError(
                    "sentence-transformers not installed. "
                    "Install with: pip install sentence-transformers"
                )
        return self.model

    def calculate_db_checksum(self) -> str:
        """Calculate checksum of database for change detection."""
        checksums = []
        for table_name, config in TABLE_CONFIGS.items():
            try:
                cursor = self.conn.execute(
                    f"SELECT COUNT(*) FROM ({config['query']})"
                )
                count = cursor.fetchone()[0]
                checksums.append(f"{table_name}:{count}")
            except sqlite3.OperationalError:
                checksums.append(f"{table_name}:0")

        data = "|".join(checksums).encode('utf-8')
        return hashlib.md5(data).hexdigest()

    def load_records_from_table(
        self,
        table_name: str,
        config: dict
    ) -> List[EmbeddingRecord]:
        """Load records from a single table."""
        records = []
        try:
            cursor = self.conn.execute(config["query"])
            for row in cursor.fetchall():
                id_ = row[config["id_col"]]
                name = row[config["name_col"]] or ""
                text = row[config["text_col"]] or name

                # Skip empty texts
                if not text.strip():
                    continue

                records.append(EmbeddingRecord(
                    id=str(id_),
                    type=table_name,
                    name=name,
                    text=text
                ))
        except sqlite3.OperationalError as e:
            print(f"Warning: Could not load {table_name}: {e}")

        return records

    def load_all_records(self) -> Tuple[List[EmbeddingRecord], Dict[str, int]]:
        """Load records from all configured tables."""
        all_records = []
        type_counts = {}

        for table_name, config in TABLE_CONFIGS.items():
            records = self.load_records_from_table(table_name, config)
            all_records.extend(records)
            type_counts[table_name] = len(records)
            print(f"  Loaded {len(records)} records from {table_name}")

        return all_records, type_counts

    def compute_embeddings(
        self,
        records: List[EmbeddingRecord],
        batch_size: int = 64
    ) -> np.ndarray:
        """Compute embeddings for all records."""
        model = self._load_model()
        texts = [r.text for r in records]

        print(f"Computing embeddings for {len(texts)} texts...")

        # Compute in batches with progress
        all_embeddings = []
        for i in range(0, len(texts), batch_size):
            batch = texts[i:i + batch_size]
            embeddings = model.encode(batch, show_progress_bar=False)
            all_embeddings.append(embeddings)

            progress = min(i + batch_size, len(texts))
            print(f"  Progress: {progress}/{len(texts)} ({100*progress/len(texts):.0f}%)")

        return np.vstack(all_embeddings)

    def build_index(self, output_dir: Path = INDEX_DIR) -> IndexMetadata:
        """Build semantic index and save to files."""
        start_time = time.time()

        # Ensure output directory exists
        output_dir.mkdir(parents=True, exist_ok=True)

        # Load all records
        print(f"Loading records from {self.db_path}...")
        records, type_counts = self.load_all_records()

        if not records:
            raise ValueError("No records found in database")

        total_records = len(records)
        print(f"\nTotal records: {total_records}")

        # Compute embeddings
        embeddings_matrix = self.compute_embeddings(records)
        embedding_dim = embeddings_matrix.shape[1]

        # Normalize embeddings for cosine similarity
        norms = np.linalg.norm(embeddings_matrix, axis=1, keepdims=True)
        embeddings_matrix = embeddings_matrix / norms

        # Prepare string arrays
        ids = [r.id for r in records]
        types = [r.type for r in records]
        names = [r.name for r in records]
        texts = [r.text for r in records]

        # Save embeddings matrix (already normalized)
        embeddings_file = output_dir / "embeddings.npz"
        np.savez_compressed(
            embeddings_file,
            embeddings=embeddings_matrix.astype(np.float32)
        )
        print(f"\nSaved embeddings to {embeddings_file}")

        # Save string data as JSON
        strings_file = output_dir / "strings.json"
        with open(strings_file, 'w', encoding='utf-8') as f:
            json.dump({
                "ids": ids,
                "types": types,
                "names": names,
                "texts": texts
            }, f, ensure_ascii=False, indent=None)
        print(f"Saved string data to {strings_file}")

        # Create metadata
        build_time = time.time() - start_time
        metadata = IndexMetadata(
            created_at=datetime.now().isoformat(),
            embedding_count=total_records,
            embedding_dim=embedding_dim,
            model_name="all-MiniLM-L6-v2",
            source_db_checksum=self.calculate_db_checksum(),
            type_counts=type_counts,
            build_time_seconds=round(build_time, 2)
        )

        # Save metadata
        metadata_file = output_dir / "metadata.json"
        with open(metadata_file, 'w', encoding='utf-8') as f:
            json.dump(metadata.to_dict(), f, indent=2, ensure_ascii=False)
        print(f"Saved metadata to {metadata_file}")

        # Print summary
        print(f"\n{'='*50}")
        print(f"Index build complete in {build_time:.2f}s")
        print(f"  Total embeddings: {total_records}")
        print(f"  Embedding dimension: {embedding_dim}")
        print(f"  By type:")
        for type_name, count in sorted(type_counts.items(), key=lambda x: -x[1]):
            print(f"    {type_name}: {count}")

        # File sizes
        emb_size = embeddings_file.stat().st_size / 1024 / 1024
        str_size = strings_file.stat().st_size / 1024 / 1024
        print(f"  File sizes:")
        print(f"    embeddings.npz: {emb_size:.2f} MB")
        print(f"    strings.json: {str_size:.2f} MB")

        return metadata


class SemanticIndexLoader:
    """Fast loader for pre-built semantic index."""

    def __init__(self, index_dir: Path = INDEX_DIR):
        self.index_dir = index_dir
        self.embeddings: Optional[np.ndarray] = None
        self.ids: List[str] = []
        self.types: List[str] = []
        self.names: List[str] = []
        self.texts: List[str] = []
        self.metadata: Optional[IndexMetadata] = None
        self._loaded = False

    def is_available(self) -> bool:
        """Check if pre-built index exists."""
        return (
            (self.index_dir / "embeddings.npz").exists() and
            (self.index_dir / "strings.json").exists() and
            (self.index_dir / "metadata.json").exists()
        )

    def load(self) -> bool:
        """Load pre-built index. Returns True if successful."""
        if self._loaded:
            return True

        if not self.is_available():
            return False

        start_time = time.time()

        try:
            # Load embeddings matrix
            data = np.load(self.index_dir / "embeddings.npz")
            self.embeddings = data["embeddings"]

            # Load string data
            with open(self.index_dir / "strings.json", 'r', encoding='utf-8') as f:
                strings = json.load(f)
                self.ids = strings["ids"]
                self.types = strings["types"]
                self.names = strings["names"]
                self.texts = strings["texts"]

            # Load metadata
            with open(self.index_dir / "metadata.json", 'r', encoding='utf-8') as f:
                self.metadata = IndexMetadata.from_dict(json.load(f))

            self._loaded = True
            load_time = time.time() - start_time
            print(f"Loaded semantic index in {load_time*1000:.1f}ms "
                  f"({len(self.ids)} embeddings)")
            return True

        except Exception as e:
            print(f"Failed to load semantic index: {e}")
            return False

    def search(
        self,
        query_embedding: np.ndarray,
        top_k: int = 10,
        type_filter: Optional[str] = None
    ) -> List[Tuple[str, str, str, str, float]]:
        """
        Search for similar items.

        Args:
            query_embedding: Query vector (384 dimensions)
            top_k: Number of results to return
            type_filter: Optional type filter (e.g., 'cwe', 'attack')

        Returns:
            List of (id, type, name, text, similarity_score) tuples
        """
        if not self._loaded:
            raise RuntimeError("Index not loaded. Call load() first.")

        # Normalize query
        query_norm = query_embedding / np.linalg.norm(query_embedding)

        # Apply type filter if specified
        if type_filter:
            mask = np.array([t == type_filter for t in self.types])
            filtered_embeddings = self.embeddings[mask]
            filtered_indices = np.where(mask)[0]
        else:
            filtered_embeddings = self.embeddings
            filtered_indices = np.arange(len(self.embeddings))

        if len(filtered_embeddings) == 0:
            return []

        # Compute cosine similarities (embeddings are already normalized)
        similarities = np.dot(filtered_embeddings, query_norm)

        # Get top-k indices
        if len(similarities) <= top_k:
            top_indices = np.argsort(similarities)[::-1]
        else:
            top_indices = np.argpartition(similarities, -top_k)[-top_k:]
            top_indices = top_indices[np.argsort(similarities[top_indices])[::-1]]

        results = []
        for idx in top_indices:
            original_idx = filtered_indices[idx]
            results.append((
                self.ids[original_idx],
                self.types[original_idx],
                self.names[original_idx],
                self.texts[original_idx],
                float(similarities[idx])
            ))

        return results

    def get_by_id(self, item_id: str) -> Optional[Tuple[str, str, str, np.ndarray]]:
        """Get item by ID. Returns (type, name, text, embedding) or None."""
        if not self._loaded:
            raise RuntimeError("Index not loaded. Call load() first.")

        try:
            idx = self.ids.index(item_id)
            return (
                self.types[idx],
                self.names[idx],
                self.texts[idx],
                self.embeddings[idx]
            )
        except ValueError:
            return None

    def get_type_counts(self) -> Dict[str, int]:
        """Get count of embeddings by type."""
        if not self._loaded:
            return {}

        counts = {}
        for t in self.types:
            counts[t] = counts.get(t, 0) + 1
        return counts


def check_index_freshness(
    db_path: Path = KB_SQLITE_PATH,
    index_dir: Path = INDEX_DIR
) -> dict:
    """
    Check if pre-built index is up-to-date with database.

    Returns dict with:
        - is_fresh: bool - True if index matches database
        - reason: str - Explanation
        - db_checksum: str - Current database checksum
        - index_checksum: str - Stored index checksum
    """
    result = {
        "is_fresh": False,
        "reason": "",
        "db_checksum": "",
        "index_checksum": ""
    }

    # Check if index exists
    metadata_file = index_dir / "metadata.json"
    if not metadata_file.exists():
        result["reason"] = "Index does not exist"
        return result

    # Load metadata
    with open(metadata_file, 'r') as f:
        metadata = IndexMetadata.from_dict(json.load(f))
    result["index_checksum"] = metadata.source_db_checksum

    # Calculate current database checksum
    if not db_path.exists():
        result["reason"] = "Database not found"
        return result

    builder = SemanticIndexBuilder(db_path)
    builder.connect()
    try:
        current_checksum = builder.calculate_db_checksum()
        result["db_checksum"] = current_checksum

        if current_checksum == metadata.source_db_checksum:
            result["is_fresh"] = True
            result["reason"] = "Index is up-to-date"
        else:
            result["reason"] = "Database has changed since index was built"
    finally:
        builder.close()

    return result


def main():
    """CLI entry point."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Semantic Search Index Pre-builder",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Build index
  python prebuild_semantic_index.py build

  # Check if index is fresh
  python prebuild_semantic_index.py check

  # Show index statistics
  python prebuild_semantic_index.py stats

  # Test search
  python prebuild_semantic_index.py test-search "SQL injection vulnerability"
"""
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Build command
    build_parser = subparsers.add_parser("build", help="Build semantic index")
    build_parser.add_argument(
        "--db", type=Path, default=KB_SQLITE_PATH,
        help="Path to SQLite database"
    )
    build_parser.add_argument(
        "--output", type=Path, default=INDEX_DIR,
        help="Output directory for index files"
    )
    build_parser.add_argument(
        "--force", action="store_true",
        help="Force rebuild even if index is fresh"
    )

    # Check command
    check_parser = subparsers.add_parser("check", help="Check index freshness")
    check_parser.add_argument(
        "--db", type=Path, default=KB_SQLITE_PATH,
        help="Path to SQLite database"
    )

    # Stats command
    subparsers.add_parser("stats", help="Show index statistics")

    # Test search command
    test_parser = subparsers.add_parser("test-search", help="Test semantic search")
    test_parser.add_argument("query", help="Search query")
    test_parser.add_argument(
        "--top-k", type=int, default=5,
        help="Number of results (default: 5)"
    )
    test_parser.add_argument(
        "--type", dest="type_filter",
        help="Filter by type (e.g., cwe, attack, capec)"
    )

    args = parser.parse_args()

    if args.command == "build":
        # Check freshness first
        if not args.force:
            freshness = check_index_freshness(args.db, args.output)
            if freshness["is_fresh"]:
                print("Index is already up-to-date. Use --force to rebuild.")
                return

        builder = SemanticIndexBuilder(args.db)
        builder.connect()
        try:
            metadata = builder.build_index(args.output)
            print("\nBuild successful!")
        finally:
            builder.close()

    elif args.command == "check":
        freshness = check_index_freshness(args.db)
        print(f"Index status: {'FRESH' if freshness['is_fresh'] else 'STALE'}")
        print(f"Reason: {freshness['reason']}")
        if freshness['db_checksum']:
            print(f"Database checksum: {freshness['db_checksum']}")
        if freshness['index_checksum']:
            print(f"Index checksum: {freshness['index_checksum']}")

    elif args.command == "stats":
        loader = SemanticIndexLoader()
        if not loader.is_available():
            print("No pre-built index found. Run 'build' first.")
            return

        loader.load()
        print(f"\nSemantic Index Statistics")
        print(f"{'='*50}")
        print(f"Created: {loader.metadata.created_at}")
        print(f"Total embeddings: {loader.metadata.embedding_count}")
        print(f"Embedding dimension: {loader.metadata.embedding_dim}")
        print(f"Model: {loader.metadata.model_name}")
        print(f"Build time: {loader.metadata.build_time_seconds}s")
        print(f"\nBy type:")
        for type_name, count in sorted(loader.metadata.type_counts.items(),
                                       key=lambda x: -x[1]):
            print(f"  {type_name}: {count}")

        # File sizes
        emb_file = loader.index_dir / "embeddings.npz"
        str_file = loader.index_dir / "strings.json"
        if emb_file.exists():
            print(f"\nFile sizes:")
            print(f"  embeddings.npz: {emb_file.stat().st_size / 1024 / 1024:.2f} MB")
            print(f"  strings.json: {str_file.stat().st_size / 1024 / 1024:.2f} MB")

    elif args.command == "test-search":
        # Need sentence-transformers for encoding query
        try:
            from sentence_transformers import SentenceTransformer
        except ImportError:
            print("Error: sentence-transformers not installed")
            print("Install with: pip install sentence-transformers")
            return

        loader = SemanticIndexLoader()
        if not loader.load():
            print("Failed to load index. Run 'build' first.")
            return

        print(f"Encoding query: {args.query}")
        model = SentenceTransformer("all-MiniLM-L6-v2")
        query_embedding = model.encode(args.query)

        print(f"\nSearching (top {args.top_k}" +
              (f", type={args.type_filter}" if args.type_filter else "") + ")...")

        results = loader.search(
            query_embedding,
            top_k=args.top_k,
            type_filter=args.type_filter
        )

        print(f"\nResults ({len(results)}):")
        for i, (id_, type_, name, text, score) in enumerate(results, 1):
            print(f"\n{i}. [{type_}] {id_}: {name}")
            print(f"   Score: {score:.4f}")
            # Truncate text for display
            display_text = text[:150] + "..." if len(text) > 150 else text
            print(f"   {display_text}")

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
