#!/usr/bin/env python3
"""
Code Statistics Collection Script
==================================
Version: 1.0.0
Date: 2026-01-02

Collects quantitative code metrics for threat modeling reports.
Outputs data in formats compatible with Phase 1 and Phase 8 report templates.

Usage:
    python collect_code_stats.py <project-path> [--format json|markdown|yaml]

Example:
    python collect_code_stats.py /path/to/project --format markdown
"""

import os
import sys
import json
import argparse
import subprocess
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from collections import defaultdict
from dataclasses import dataclass, field, asdict


# ============================================================
# Configuration
# ============================================================

# Language extensions mapping
LANGUAGE_EXTENSIONS = {
    'Python': ['.py', '.pyx', '.pxd'],
    'JavaScript': ['.js', '.mjs', '.cjs'],
    'TypeScript': ['.ts', '.tsx'],
    'Java': ['.java'],
    'Go': ['.go'],
    'Rust': ['.rs'],
    'C': ['.c', '.h'],
    'C++': ['.cpp', '.cxx', '.cc', '.hpp', '.hxx'],
    'C#': ['.cs'],
    'Ruby': ['.rb', '.erb'],
    'PHP': ['.php'],
    'Swift': ['.swift'],
    'Kotlin': ['.kt', '.kts'],
    'Scala': ['.scala'],
    'HTML': ['.html', '.htm'],
    'CSS': ['.css', '.scss', '.sass', '.less'],
    'SQL': ['.sql'],
    'Shell': ['.sh', '.bash', '.zsh'],
    'YAML': ['.yml', '.yaml'],
    'JSON': ['.json'],
    'Markdown': ['.md', '.markdown'],
    'Vue': ['.vue'],
    'Svelte': ['.svelte'],
}

# Security-related path patterns
SECURITY_PATTERNS = {
    '认证/授权': ['auth', 'login', 'session', 'oauth', 'jwt', 'permission', 'access'],
    '加密/密钥': ['crypto', 'encrypt', 'decrypt', 'key', 'secret', 'hash', 'sign'],
    '数据访问': ['model', 'database', 'db', 'repository', 'dao', 'orm', 'query'],
    'API接口': ['api', 'route', 'endpoint', 'controller', 'handler', 'view'],
    '配置管理': ['config', 'setting', 'env', 'secret'],
    '输入验证': ['validate', 'sanitize', 'filter', 'escape', 'schema'],
}

# Directories to exclude
EXCLUDE_DIRS = {
    'node_modules', 'venv', '.venv', 'env', '.env',
    '__pycache__', '.git', '.svn', '.hg',
    'dist', 'build', 'target', 'out', 'bin',
    '.idea', '.vscode', '.vs',
    'coverage', '.nyc_output', 'htmlcov',
    'vendor', 'packages', '.pub-cache',
}


@dataclass
class LanguageStats:
    """Statistics for a single programming language."""
    name: str
    file_count: int = 0
    loc: int = 0  # Lines of code (excluding blanks/comments)
    blank_lines: int = 0
    comment_lines: int = 0
    total_lines: int = 0


@dataclass
class SecurityModuleStats:
    """Statistics for security-related modules."""
    category: str
    paths: List[str] = field(default_factory=list)
    file_count: int = 0
    loc: int = 0
    security_level: str = "中"


@dataclass
class ProjectStats:
    """Complete project statistics."""
    project_path: str
    total_loc: int = 0
    total_files: int = 0
    total_dirs: int = 0
    module_count: int = 0
    dependency_count: int = 0
    languages: List[LanguageStats] = field(default_factory=list)
    security_modules: List[SecurityModuleStats] = field(default_factory=list)


# ============================================================
# File Analysis Functions
# ============================================================

def should_exclude(path: Path) -> bool:
    """Check if path should be excluded from analysis."""
    parts = path.parts
    return any(excluded in parts for excluded in EXCLUDE_DIRS)


def get_language(file_path: Path) -> Optional[str]:
    """Determine the programming language of a file."""
    ext = file_path.suffix.lower()
    for lang, extensions in LANGUAGE_EXTENSIONS.items():
        if ext in extensions:
            return lang
    return None


def count_lines(file_path: Path) -> Tuple[int, int, int]:
    """
    Count lines in a file.
    Returns: (code_lines, blank_lines, comment_lines)
    """
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
    except (IOError, OSError):
        return (0, 0, 0)

    code_lines = 0
    blank_lines = 0
    comment_lines = 0
    in_multiline_comment = False
    ext = file_path.suffix.lower()

    for line in lines:
        stripped = line.strip()

        # Check for blank lines
        if not stripped:
            blank_lines += 1
            continue

        # Python comments
        if ext == '.py':
            if stripped.startswith('#'):
                comment_lines += 1
                continue
            if stripped.startswith('"""') or stripped.startswith("'''"):
                in_multiline_comment = not in_multiline_comment
                comment_lines += 1
                continue

        # C-style comments (JS, TS, Java, Go, C, C++, etc.)
        if ext in ['.js', '.ts', '.tsx', '.java', '.go', '.c', '.cpp', '.h', '.cs', '.swift', '.kt', '.scala', '.rs']:
            if stripped.startswith('//'):
                comment_lines += 1
                continue
            if stripped.startswith('/*'):
                in_multiline_comment = True
                comment_lines += 1
                continue
            if '*/' in stripped:
                in_multiline_comment = False
                comment_lines += 1
                continue

        # HTML/CSS comments
        if ext in ['.html', '.htm', '.css', '.scss']:
            if stripped.startswith('<!--') or stripped.startswith('/*'):
                comment_lines += 1
                continue

        if in_multiline_comment:
            comment_lines += 1
        else:
            code_lines += 1

    return (code_lines, blank_lines, comment_lines)


def try_cloc(project_path: str) -> Optional[Dict]:
    """Try to use cloc for more accurate line counting."""
    try:
        result = subprocess.run(
            ['cloc', project_path, '--json', '--quiet'],
            capture_output=True,
            text=True,
            timeout=300
        )
        if result.returncode == 0:
            return json.loads(result.stdout)
    except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError):
        pass
    return None


def try_tokei(project_path: str) -> Optional[Dict]:
    """Try to use tokei for more accurate line counting."""
    try:
        result = subprocess.run(
            ['tokei', project_path, '--output', 'json'],
            capture_output=True,
            text=True,
            timeout=300
        )
        if result.returncode == 0:
            return json.loads(result.stdout)
    except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError):
        pass
    return None


# ============================================================
# Statistics Collection
# ============================================================

def collect_stats(project_path: str) -> ProjectStats:
    """Collect all project statistics."""
    path = Path(project_path).resolve()
    stats = ProjectStats(project_path=str(path))

    lang_stats: Dict[str, LanguageStats] = defaultdict(
        lambda: LanguageStats(name="")
    )
    security_stats: Dict[str, SecurityModuleStats] = {}
    dirs_seen = set()
    top_level_modules = set()

    # Initialize security module stats
    for category in SECURITY_PATTERNS:
        security_stats[category] = SecurityModuleStats(
            category=category,
            security_level="高" if category in ['认证/授权', '加密/密钥', '数据访问'] else "中"
        )

    # Walk the project directory
    for root, dirs, files in os.walk(path):
        root_path = Path(root)

        # Skip excluded directories
        dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]

        if should_exclude(root_path):
            continue

        # Track directories
        rel_root = root_path.relative_to(path)
        if rel_root != Path('.'):
            dirs_seen.add(str(rel_root))
            # Track top-level modules
            parts = rel_root.parts
            if len(parts) >= 1 and parts[0] not in ['.', '..']:
                top_level_modules.add(parts[0])

        # Process files
        for file_name in files:
            file_path = root_path / file_name

            if should_exclude(file_path):
                continue

            lang = get_language(file_path)
            if not lang:
                continue

            # Count lines
            code, blank, comment = count_lines(file_path)

            # Update language stats
            if lang not in lang_stats:
                lang_stats[lang] = LanguageStats(name=lang)
            lang_stats[lang].file_count += 1
            lang_stats[lang].loc += code
            lang_stats[lang].blank_lines += blank
            lang_stats[lang].comment_lines += comment
            lang_stats[lang].total_lines += code + blank + comment

            # Check for security-related paths
            rel_path = str(file_path.relative_to(path)).lower()
            for category, patterns in SECURITY_PATTERNS.items():
                if any(p in rel_path for p in patterns):
                    sec_stat = security_stats[category]
                    if str(root_path.relative_to(path)) not in sec_stat.paths:
                        sec_stat.paths.append(str(root_path.relative_to(path)))
                    sec_stat.file_count += 1
                    sec_stat.loc += code
                    break  # Only count in first matching category

    # Count dependencies
    stats.dependency_count = count_dependencies(path)

    # Compile final stats
    stats.total_dirs = len(dirs_seen)
    stats.module_count = len(top_level_modules)

    # Convert language stats
    for lang_name, lang_stat in lang_stats.items():
        lang_stat.name = lang_name
        stats.total_loc += lang_stat.loc
        stats.total_files += lang_stat.file_count
        stats.languages.append(lang_stat)

    # Sort languages by LOC
    stats.languages.sort(key=lambda x: x.loc, reverse=True)

    # Convert security stats
    for category, sec_stat in security_stats.items():
        if sec_stat.file_count > 0:
            stats.security_modules.append(sec_stat)

    return stats


def count_dependencies(project_path: Path) -> int:
    """Count direct dependencies from package manifests."""
    dep_count = 0

    # package.json (Node.js)
    package_json = project_path / 'package.json'
    if package_json.exists():
        try:
            with open(package_json) as f:
                data = json.load(f)
                deps = data.get('dependencies', {})
                dev_deps = data.get('devDependencies', {})
                dep_count += len(deps) + len(dev_deps)
        except (json.JSONDecodeError, IOError):
            pass

    # requirements.txt (Python)
    requirements_txt = project_path / 'requirements.txt'
    if requirements_txt.exists():
        try:
            with open(requirements_txt) as f:
                lines = [l.strip() for l in f if l.strip() and not l.startswith('#')]
                dep_count += len(lines)
        except IOError:
            pass

    # pyproject.toml (Python)
    pyproject_toml = project_path / 'pyproject.toml'
    if pyproject_toml.exists():
        try:
            with open(pyproject_toml) as f:
                content = f.read()
                # Simple parsing for dependencies section
                if 'dependencies' in content:
                    # Count lines between [dependencies] sections
                    import re
                    matches = re.findall(r'dependencies\s*=\s*\[([^\]]+)\]', content)
                    for match in matches:
                        deps = [d.strip() for d in match.split(',') if d.strip()]
                        dep_count += len(deps)
        except IOError:
            pass

    # go.mod (Go)
    go_mod = project_path / 'go.mod'
    if go_mod.exists():
        try:
            with open(go_mod) as f:
                content = f.read()
                require_count = content.count('require')
                dep_count += require_count
        except IOError:
            pass

    # Cargo.toml (Rust)
    cargo_toml = project_path / 'Cargo.toml'
    if cargo_toml.exists():
        try:
            with open(cargo_toml) as f:
                content = f.read()
                if '[dependencies]' in content:
                    # Count lines after [dependencies] until next section
                    lines = content.split('[dependencies]')[1].split('[')[0].strip().split('\n')
                    dep_count += len([l for l in lines if l.strip() and '=' in l])
        except IOError:
            pass

    return dep_count


# ============================================================
# Output Formatters
# ============================================================

def format_json(stats: ProjectStats) -> str:
    """Format stats as JSON."""
    data = {
        'project_path': stats.project_path,
        'summary': {
            'total_loc': stats.total_loc,
            'total_files': stats.total_files,
            'total_dirs': stats.total_dirs,
            'module_count': stats.module_count,
            'dependency_count': stats.dependency_count,
        },
        'languages': [
            {
                'name': lang.name,
                'file_count': lang.file_count,
                'loc': lang.loc,
                'percentage': round(lang.loc / stats.total_loc * 100, 1) if stats.total_loc > 0 else 0
            }
            for lang in stats.languages
        ],
        'security_modules': [
            {
                'category': sec.category,
                'paths': sec.paths[:3],  # Top 3 paths
                'file_count': sec.file_count,
                'loc': sec.loc,
                'security_level': sec.security_level,
            }
            for sec in stats.security_modules
        ]
    }
    return json.dumps(data, indent=2, ensure_ascii=False)


def format_markdown(stats: ProjectStats) -> str:
    """Format stats as Markdown tables (compatible with report templates)."""
    lines = []

    # Project Scale Metrics
    lines.append("## 项目规模指标\n")
    lines.append("### 代码统计")
    lines.append("| 指标 | 数值 | 说明 |")
    lines.append("|------|------|------|")
    lines.append(f"| **代码总行数** | {stats.total_loc:,} | 不含空行和注释 |")
    lines.append(f"| **文件总数** | {stats.total_files:,} | 源代码文件 |")
    lines.append(f"| **目录数** | {stats.total_dirs:,} | 代码目录 |")
    lines.append(f"| **主要模块数** | {stats.module_count} | 顶层功能模块 |")
    lines.append(f"| **依赖数量** | {stats.dependency_count} | 直接依赖 |")
    lines.append("")

    # Language Distribution
    lines.append("### 语言分布")
    lines.append("| 语言 | 文件数 | 代码行数 | 占比 |")
    lines.append("|------|--------|---------|------|")
    for lang in stats.languages[:10]:  # Top 10 languages
        pct = round(lang.loc / stats.total_loc * 100, 1) if stats.total_loc > 0 else 0
        lines.append(f"| {lang.name} | {lang.file_count:,} | {lang.loc:,} | {pct}% |")
    lines.append("")

    # Security Modules
    if stats.security_modules:
        lines.append("### 安全相关模块统计")
        lines.append("| 模块类型 | 路径 | 文件数 | 行数 | 安全等级 |")
        lines.append("|---------|------|--------|------|---------|")
        for sec in stats.security_modules:
            if sec.file_count > 0:
                path = sec.paths[0] if sec.paths else "-"
                lines.append(f"| {sec.category} | {path} | {sec.file_count} | {sec.loc:,} | {sec.security_level} |")
        lines.append("")

    return "\n".join(lines)


def format_yaml(stats: ProjectStats) -> str:
    """Format stats as YAML (for template variables)."""
    lines = [
        "# Project Scale Metrics for Report Template",
        f"TOTAL_LOC: \"{stats.total_loc:,}\"",
        f"TOTAL_FILES: \"{stats.total_files:,}\"",
        f"TOTAL_DIRS: \"{stats.total_dirs:,}\"",
        f"MODULE_COUNT: \"{stats.module_count}\"",
        f"DEPENDENCY_COUNT: \"{stats.dependency_count}\"",
        "",
        "# Language Distribution",
    ]

    for i, lang in enumerate(stats.languages[:5], 1):
        pct = round(lang.loc / stats.total_loc * 100, 1) if stats.total_loc > 0 else 0
        lines.append(f"LANG_{i}: \"{lang.name}\"")
        lines.append(f"LANG_{i}_FILES: \"{lang.file_count:,}\"")
        lines.append(f"LANG_{i}_LOC: \"{lang.loc:,}\"")
        lines.append(f"LANG_{i}_PCT: \"{pct}\"")

    return "\n".join(lines)


# ============================================================
# Main
# ============================================================

def main():
    parser = argparse.ArgumentParser(
        description="Collect code statistics for threat modeling reports",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    parser.add_argument('project_path', help='Path to the project directory')
    parser.add_argument(
        '--format', '-f',
        choices=['json', 'markdown', 'yaml'],
        default='markdown',
        help='Output format (default: markdown)'
    )
    parser.add_argument(
        '--output', '-o',
        help='Output file path (default: stdout)'
    )

    args = parser.parse_args()

    # Validate project path
    if not os.path.isdir(args.project_path):
        print(f"Error: {args.project_path} is not a valid directory", file=sys.stderr)
        sys.exit(1)

    # Collect statistics
    print(f"Analyzing project: {args.project_path}", file=sys.stderr)
    stats = collect_stats(args.project_path)

    # Format output
    if args.format == 'json':
        output = format_json(stats)
    elif args.format == 'yaml':
        output = format_yaml(stats)
    else:
        output = format_markdown(stats)

    # Write output
    if args.output:
        with open(args.output, 'w', encoding='utf-8') as f:
            f.write(output)
        print(f"Statistics written to: {args.output}", file=sys.stderr)
    else:
        print(output)


if __name__ == '__main__':
    main()
