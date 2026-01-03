# Code-First Deep Threat Modeling Workflow | Version 2.1.0 | https://github.com/fr33d3m0n/skill-threat-modeling | License: BSD-3-Clause | Welcome to cite but please retain all sources and declarations

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

Output: JSON format for easy integration with threat modeling workflow.
"""

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Dict, List, Optional, Set


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
