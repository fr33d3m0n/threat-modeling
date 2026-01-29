#!/usr/bin/env python3
"""
File Listing Utility for STRIDE Threat Modeling.

Provides structured file listing for Claude to understand project structure
during Phase 1 (Project Understanding).

Usage:
    python list_files.py /path/to/project
    python list_files.py /path/to/project --extensions py,js,ts
    python list_files.py /path/to/project --max-depth 3
    python list_files.py /path/to/project --categorize
    python list_files.py /path/to/project --doc-analysis

Output: JSON format for easy integration with threat modeling workflow.
"""

import argparse
import fnmatch
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Set


# Common patterns to exclude
DEFAULT_EXCLUDES = {
    # Version control
    ".git", ".svn", ".hg",
    # Dependencies
    "node_modules", "vendor", "venv", ".venv", "env", ".env",
    "__pycache__", ".pytest_cache", ".mypy_cache",
    # Build outputs
    "dist", "build", "out", "target", ".next", ".nuxt",
    # IDE
    ".idea", ".vscode", ".vs",
    # Misc
    ".DS_Store", "Thumbs.db", "*.pyc", "*.pyo",
}

# Documentation categories for Phase 1.1 Doc-Guided Discovery
DOC_CATEGORIES = {
    "readme": {
        "patterns": ["README*", "readme*"],
        "extensions": [".md", ".rst", ".txt", ""],
        "priority": 1,
    },
    "architecture": {
        "patterns": ["ARCHITECTURE*", "architecture*", "DESIGN*", "design*"],
        "extensions": [".md", ".rst", ".txt"],
        "priority": 2,
    },
    "api_docs": {
        "patterns": ["api*", "API*", "swagger*", "openapi*"],
        "extensions": [".md", ".yaml", ".yml", ".json"],
        "priority": 3,
    },
    "docs_directory": {
        "patterns": ["docs", "doc", "documentation"],
        "is_directory": True,
        "priority": 4,
    },
    "contributing": {
        "patterns": ["CONTRIBUTING*", "contributing*"],
        "extensions": [".md", ".rst", ".txt", ""],
        "priority": 5,
    },
    "changelog": {
        "patterns": ["CHANGELOG*", "changelog*", "HISTORY*", "history*", "NEWS*"],
        "extensions": [".md", ".rst", ".txt", ""],
        "priority": 6,
    },
}

# File categories for project understanding
FILE_CATEGORIES = {
    "entry_points": {
        "patterns": ["main.py", "app.py", "index.js", "index.ts", "main.go", "Main.java"],
        "description": "Application entry points",
    },
    "api_routes": {
        "patterns": ["routes", "api", "endpoints", "handlers", "controllers"],
        "extensions": [".py", ".js", ".ts", ".go", ".java"],
        "description": "API route definitions",
    },
    "config": {
        "patterns": ["config", "settings", ".env", "*.yaml", "*.yml", "*.toml", "*.json"],
        "description": "Configuration files",
    },
    "models": {
        "patterns": ["models", "schemas", "entities", "types"],
        "description": "Data models and schemas",
    },
    "auth": {
        "patterns": ["auth", "authentication", "authorization", "security", "jwt", "oauth"],
        "description": "Authentication/Authorization",
    },
    "database": {
        "patterns": ["db", "database", "migrations", "repositories", "dal"],
        "description": "Database layer",
    },
    "tests": {
        "patterns": ["test", "tests", "spec", "__tests__", "*_test.py", "*_test.go"],
        "description": "Test files",
    },
    "deploy": {
        "patterns": ["deploy", "k8s", "kubernetes", "docker", "terraform", "pulumi", "cdk"],
        "extensions": [".yaml", ".yml", ".tf", ".hcl"],
        "description": "Deployment configuration",
    },
    "docs": {
        "patterns": ["docs", "documentation", "*.md", "*.rst"],
        "description": "Documentation",
    },
}


def should_exclude(path: Path, excludes: Set[str]) -> bool:
    """Check if path should be excluded."""
    name = path.name
    for exclude in excludes:
        if exclude.startswith("*"):
            if name.endswith(exclude[1:]):
                return True
        elif name == exclude:
            return True
    return False


def get_file_info(path: Path, root: Path) -> Dict:
    """Get file information."""
    rel_path = path.relative_to(root)
    stat = path.stat()

    return {
        "path": str(rel_path),
        "name": path.name,
        "extension": path.suffix.lower() if path.suffix else None,
        "size": stat.st_size,
        "is_hidden": path.name.startswith("."),
    }


def list_files(
    root: Path,
    extensions: Optional[Set[str]] = None,
    max_depth: Optional[int] = None,
    excludes: Optional[Set[str]] = None,
) -> Dict:
    """List files in directory with metadata."""
    if excludes is None:
        excludes = DEFAULT_EXCLUDES

    files = []
    directories = []
    total_size = 0
    extension_counts: Dict[str, int] = {}

    def walk(current: Path, depth: int):
        nonlocal total_size

        if max_depth is not None and depth > max_depth:
            return

        try:
            entries = sorted(current.iterdir(), key=lambda x: (not x.is_dir(), x.name.lower()))
        except PermissionError:
            return

        for entry in entries:
            if should_exclude(entry, excludes):
                continue

            if entry.is_dir():
                rel_path = entry.relative_to(root)
                directories.append(str(rel_path))
                walk(entry, depth + 1)
            elif entry.is_file():
                ext = entry.suffix.lower() if entry.suffix else "(no extension)"

                # Filter by extension if specified
                if extensions and ext.lstrip(".") not in extensions and ext not in extensions:
                    continue

                file_info = get_file_info(entry, root)
                files.append(file_info)
                total_size += file_info["size"]
                extension_counts[ext] = extension_counts.get(ext, 0) + 1

    walk(root, 0)

    return {
        "root": str(root.absolute()),
        "total_files": len(files),
        "total_directories": len(directories),
        "total_size_bytes": total_size,
        "extension_summary": dict(sorted(extension_counts.items(), key=lambda x: -x[1])),
        "directories": directories,
        "files": files,
    }


def categorize_files(files: List[Dict]) -> Dict:
    """Categorize files by their likely purpose."""
    categorized = {cat: [] for cat in FILE_CATEGORIES}
    categorized["other"] = []

    for file_info in files:
        path = file_info["path"].lower()
        name = file_info["name"].lower()
        ext = file_info["extension"] or ""

        matched = False
        for cat_name, cat_config in FILE_CATEGORIES.items():
            patterns = cat_config.get("patterns", [])
            cat_extensions = cat_config.get("extensions", [])

            for pattern in patterns:
                if pattern.startswith("*"):
                    if name.endswith(pattern[1:]):
                        categorized[cat_name].append(file_info["path"])
                        matched = True
                        break
                elif pattern in path.split(os.sep) or pattern == name:
                    if not cat_extensions or ext in cat_extensions:
                        categorized[cat_name].append(file_info["path"])
                        matched = True
                        break
            if matched:
                break

        if not matched:
            categorized["other"].append(file_info["path"])

    # Remove empty categories and add counts
    result = {}
    for cat_name, files_list in categorized.items():
        if files_list:
            result[cat_name] = {
                "count": len(files_list),
                "description": FILE_CATEGORIES.get(cat_name, {}).get("description", "Other files"),
                "files": files_list[:20],  # Limit for readability
                "truncated": len(files_list) > 20,
            }

    return result


def detect_project_type(result: Dict) -> Dict:
    """Detect project type from file patterns."""
    extensions = result.get("extension_summary", {})
    files = [f["name"].lower() for f in result.get("files", [])]

    indicators = {
        "python": {
            "extensions": [".py"],
            "files": ["setup.py", "pyproject.toml", "requirements.txt", "Pipfile"],
        },
        "javascript": {
            "extensions": [".js", ".jsx"],
            "files": ["package.json", "webpack.config.js"],
        },
        "typescript": {
            "extensions": [".ts", ".tsx"],
            "files": ["tsconfig.json", "package.json"],
        },
        "go": {
            "extensions": [".go"],
            "files": ["go.mod", "go.sum"],
        },
        "java": {
            "extensions": [".java"],
            "files": ["pom.xml", "build.gradle"],
        },
        "rust": {
            "extensions": [".rs"],
            "files": ["Cargo.toml"],
        },
        "docker": {
            "files": ["Dockerfile", "docker-compose.yml", "docker-compose.yaml"],
        },
        "kubernetes": {
            "files": ["k8s", "kubernetes", "helm"],
        },
        "terraform": {
            "extensions": [".tf", ".hcl"],
            "files": ["main.tf", "terraform.tfvars"],
        },
    }

    detected = []
    for proj_type, config in indicators.items():
        score = 0

        # Check extensions
        for ext in config.get("extensions", []):
            if ext in extensions:
                score += extensions[ext]

        # Check specific files
        for fname in config.get("files", []):
            if fname.lower() in files:
                score += 10

        if score > 0:
            detected.append({"type": proj_type, "confidence_score": score})

    return {
        "detected_types": sorted(detected, key=lambda x: -x["confidence_score"]),
        "primary_type": detected[0]["type"] if detected else "unknown",
    }


def match_doc_pattern(name: str, pattern: str) -> bool:
    """Match a filename against a documentation pattern using glob-style matching."""
    # Handle patterns with wildcards
    if "*" in pattern:
        return fnmatch.fnmatch(name, pattern) or fnmatch.fnmatch(name.lower(), pattern.lower())
    # Exact match (case-insensitive)
    return name.lower() == pattern.lower()


def classify_documentation(
    project_root: Path,
    files: List[Dict],
    directories: List[str],
) -> Dict[str, Any]:
    """
    Classify documentation files by category and build prioritized list.

    Args:
        project_root: Root path of the project
        files: List of file info dicts from list_files()
        directories: List of directory paths

    Returns:
        Dict containing categorized documentation files
    """
    categorized: Dict[str, List[Dict]] = {cat: [] for cat in DOC_CATEGORIES}
    all_doc_files: List[Dict] = []

    # First, identify docs directories
    docs_dirs: Set[str] = set()
    for dir_path in directories:
        dir_name = Path(dir_path).name.lower()
        for pattern in DOC_CATEGORIES["docs_directory"]["patterns"]:
            if dir_name == pattern.lower():
                docs_dirs.add(dir_path)
                categorized["docs_directory"].append({
                    "path": dir_path + "/",
                    "category": "docs_directory",
                    "is_directory": True,
                })
                break

    # Classify each file
    for file_info in files:
        file_path = file_info["path"]
        file_name = file_info["name"]
        file_ext = file_info.get("extension", "") or ""
        file_size = file_info.get("size", 0)

        # Check if file is in a docs directory
        in_docs_dir = any(file_path.startswith(docs_dir + os.sep) or file_path.startswith(docs_dir + "/")
                         for docs_dir in docs_dirs)

        matched_category = None
        match_priority = 999

        # Check against each category
        for cat_name, cat_config in DOC_CATEGORIES.items():
            if cat_config.get("is_directory"):
                continue

            patterns = cat_config.get("patterns", [])
            allowed_extensions = cat_config.get("extensions", [".md", ".rst", ".txt", ""])
            priority = cat_config.get("priority", 99)

            # Check extension compatibility
            ext_match = file_ext.lower() in [e.lower() for e in allowed_extensions]
            if not ext_match and file_ext != "":
                continue

            # Check pattern match
            for pattern in patterns:
                if match_doc_pattern(file_name, pattern):
                    if priority < match_priority:
                        matched_category = cat_name
                        match_priority = priority
                    break

        # If matched or in docs directory with doc extension
        if matched_category:
            doc_entry = {
                "path": file_path,
                "name": file_name,
                "category": matched_category,
                "size": file_size,
                "in_docs_dir": in_docs_dir,
                "priority": match_priority,
            }
            categorized[matched_category].append(doc_entry)
            all_doc_files.append(doc_entry)
        elif in_docs_dir and file_ext.lower() in [".md", ".rst", ".txt"]:
            # Files in docs directory that don't match specific patterns
            doc_entry = {
                "path": file_path,
                "name": file_name,
                "category": "docs_directory",
                "size": file_size,
                "in_docs_dir": True,
                "priority": DOC_CATEGORIES["docs_directory"]["priority"],
            }
            all_doc_files.append(doc_entry)

    # Build simplified output for each category
    doc_files_by_category: Dict[str, List[str]] = {}
    for cat_name, entries in categorized.items():
        if entries:
            doc_files_by_category[cat_name] = [e["path"] for e in entries]

    # Sort all docs by priority then by size (larger = more content = higher priority)
    all_doc_files.sort(key=lambda x: (x["priority"], -x["size"]))

    # Build priority order list
    doc_priority_order = [
        {"path": doc["path"], "category": doc["category"], "size": doc["size"]}
        for doc in all_doc_files
    ]

    return {
        "files": doc_files_by_category,
        "doc_priority_order": doc_priority_order,
        "docs_directories": list(docs_dirs),
    }


def calculate_doc_quality_score(
    project_root: Path,
    doc_classification: Dict[str, Any],
    files: List[Dict],
) -> Dict[str, Any]:
    """
    Calculate documentation quality score.

    Scoring:
    - base_score (0-40):
      - has_readme: 20
      - has_architecture_doc: 10
      - has_api_doc: 10

    - depth_score (0-30):
      - readme_size_>_5kb: 10
      - has_docs_directory: 10
      - docs_file_count_>_5: 10

    - completeness_score (0-30):
      - has_contributing: 5
      - has_changelog: 5
      - has_openapi_spec: 10
      - has_code_comments_ratio_>_10%: 10

    Grade mapping:
      - high: >= 70
      - medium: 40-69
      - low: 10-39
      - none: < 10

    Args:
        project_root: Root path of the project
        doc_classification: Output from classify_documentation()
        files: List of all file info dicts

    Returns:
        Dict with total_score, grade, breakdown
    """
    doc_files = doc_classification.get("files", {})
    priority_order = doc_classification.get("doc_priority_order", [])
    docs_dirs = doc_classification.get("docs_directories", [])

    # Initialize scores
    base_score = 0
    depth_score = 0
    completeness_score = 0

    # Base score calculations
    has_readme = bool(doc_files.get("readme"))
    has_architecture = bool(doc_files.get("architecture"))
    has_api_docs = bool(doc_files.get("api_docs"))

    if has_readme:
        base_score += 20
    if has_architecture:
        base_score += 10
    if has_api_docs:
        base_score += 10

    # Depth score calculations
    # Check readme size
    readme_size = 0
    for doc in priority_order:
        if doc["category"] == "readme":
            readme_size = max(readme_size, doc["size"])
    if readme_size > 5000:  # > 5KB
        depth_score += 10

    # Check for docs directory
    has_docs_directory = bool(docs_dirs)
    if has_docs_directory:
        depth_score += 10

    # Count docs files
    total_doc_files = len(priority_order)
    if total_doc_files > 5:
        depth_score += 10

    # Completeness score calculations
    has_contributing = bool(doc_files.get("contributing"))
    has_changelog = bool(doc_files.get("changelog"))

    if has_contributing:
        completeness_score += 5
    if has_changelog:
        completeness_score += 5

    # Check for OpenAPI spec
    has_openapi_spec = False
    for doc in priority_order:
        if doc["category"] == "api_docs":
            doc_name = Path(doc["path"]).name.lower()
            if any(kw in doc_name for kw in ["openapi", "swagger"]) and \
               doc_name.endswith((".yaml", ".yml", ".json")):
                has_openapi_spec = True
                break
    if has_openapi_spec:
        completeness_score += 10

    # Check code comment ratio (estimate from file sizes)
    # This is a heuristic: count files that might have significant comments
    # For accurate measurement, we'd need to parse files, but that's expensive
    # Instead, we check if there are inline documentation patterns
    code_extensions = {".py", ".js", ".ts", ".java", ".go", ".rs", ".c", ".cpp", ".h", ".hpp"}
    code_files = [f for f in files if (f.get("extension") or "").lower() in code_extensions]

    # Simple heuristic: if there are docstring/jsdoc patterns in the project
    # we'll check by looking for common doc file patterns
    # For now, give partial credit if there's any API documentation
    if has_api_docs and code_files:
        # Assume documented API implies some code documentation
        completeness_score += 5

    # Additional check: look for code documentation indicators
    for f in files:
        fname = f["name"].lower()
        if fname in ["api.md", "api.rst", "reference.md", "reference.rst"]:
            completeness_score = min(30, completeness_score + 5)
            break

    # Calculate total and grade
    total_score = base_score + depth_score + completeness_score

    if total_score >= 70:
        grade = "high"
    elif total_score >= 40:
        grade = "medium"
    elif total_score >= 10:
        grade = "low"
    else:
        grade = "none"

    return {
        "total_score": total_score,
        "grade": grade,
        "breakdown": {
            "base_score": base_score,
            "depth_score": depth_score,
            "completeness_score": completeness_score,
        },
        "details": {
            "has_readme": has_readme,
            "has_architecture_doc": has_architecture,
            "has_api_doc": has_api_docs,
            "readme_size_bytes": readme_size,
            "has_docs_directory": has_docs_directory,
            "total_doc_files": total_doc_files,
            "has_contributing": has_contributing,
            "has_changelog": has_changelog,
            "has_openapi_spec": has_openapi_spec,
        },
    }


def analyze_documentation(
    project_root: Path,
    files: List[Dict],
    directories: List[str],
) -> Dict[str, Any]:
    """
    Perform comprehensive documentation analysis for Phase 1.1.

    Args:
        project_root: Root path of the project
        files: List of file info dicts from list_files()
        directories: List of directory paths

    Returns:
        Dict containing complete documentation analysis
    """
    # Classify documentation
    doc_classification = classify_documentation(project_root, files, directories)

    # Calculate quality score
    quality_score = calculate_doc_quality_score(project_root, doc_classification, files)

    # Determine if project has meaningful documentation
    has_documentation = quality_score["total_score"] >= 10

    return {
        "has_documentation": has_documentation,
        "quality_grade": quality_score["grade"],
        "quality_score": quality_score["total_score"],
        "score_breakdown": quality_score["breakdown"],
        "score_details": quality_score["details"],
        "files": doc_classification["files"],
        "doc_priority_order": doc_classification["doc_priority_order"],
        "docs_directories": doc_classification["docs_directories"],
    }


def main():
    parser = argparse.ArgumentParser(
        description="List project files for STRIDE threat modeling analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # List all files in a project
    python list_files.py /path/to/project

    # Filter by extensions
    python list_files.py /path/to/project --extensions py,js,ts

    # Limit directory depth
    python list_files.py /path/to/project --max-depth 3

    # Categorize files by purpose
    python list_files.py /path/to/project --categorize

    # Detect project type
    python list_files.py /path/to/project --detect-type

    # Analyze documentation (Phase 1.1 Doc-Guided Discovery)
    python list_files.py /path/to/project --doc-analysis

    # Combined analysis for threat modeling
    python list_files.py /path/to/project --categorize --detect-type --doc-analysis
        """
    )

    parser.add_argument(
        "path",
        help="Project directory path"
    )

    parser.add_argument(
        "--extensions", "-e",
        help="Filter by file extensions (comma-separated, e.g., py,js,ts)"
    )

    parser.add_argument(
        "--max-depth", "-d",
        type=int,
        help="Maximum directory depth to traverse"
    )

    parser.add_argument(
        "--categorize", "-c",
        action="store_true",
        help="Categorize files by purpose (entry points, API, config, etc.)"
    )

    parser.add_argument(
        "--detect-type", "-t",
        action="store_true",
        help="Detect project type from file patterns"
    )

    parser.add_argument(
        "--doc-analysis", "-D",
        action="store_true",
        help="Analyze documentation files for Phase 1.1 Doc-Guided Discovery"
    )

    parser.add_argument(
        "--summary-only", "-s",
        action="store_true",
        help="Output summary only (no file list)"
    )

    parser.add_argument(
        "--pretty", "-p",
        action="store_true",
        help="Pretty-print JSON output"
    )

    args = parser.parse_args()

    # Validate path
    root = Path(args.path)
    if not root.exists():
        print(json.dumps({"error": f"Path does not exist: {args.path}"}))
        sys.exit(1)
    if not root.is_dir():
        print(json.dumps({"error": f"Path is not a directory: {args.path}"}))
        sys.exit(1)

    # Parse extensions
    extensions = None
    if args.extensions:
        extensions = set(ext.strip().lstrip(".") for ext in args.extensions.split(","))

    # List files
    result = list_files(root, extensions, args.max_depth)

    # Add categorization if requested
    if args.categorize:
        result["categories"] = categorize_files(result["files"])

    # Add project type detection if requested
    if args.detect_type:
        result["project_type"] = detect_project_type(result)

    # Add documentation analysis if requested (Phase 1.1 Doc-Guided Discovery)
    if args.doc_analysis:
        result["documentation"] = analyze_documentation(
            root,
            result["files"],
            result["directories"],
        )

    # Remove file list if summary only
    if args.summary_only:
        del result["files"]
        del result["directories"]

    # Output JSON
    if args.pretty:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(json.dumps(result, ensure_ascii=False))


if __name__ == "__main__":
    main()
