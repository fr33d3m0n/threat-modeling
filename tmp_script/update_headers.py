#!/usr/bin/env python3
# Threat Modeling Skill | Version 3.0.0 (20260201a) | https://github.com/fr33d3m0n/threat-modeling | License: BSD-3-Clause

"""
Batch update file headers with standard declaration.
"""

import os
import re
from pathlib import Path

# Standard headers
MD_HEADER = "<!-- Threat Modeling Skill | Version 3.0.0 (20260201a) | https://github.com/fr33d3m0n/threat-modeling | License: BSD-3-Clause -->"
CODE_HEADER = "# Threat Modeling Skill | Version 3.0.0 (20260201a) | https://github.com/fr33d3m0n/threat-modeling | License: BSD-3-Clause"

# Directories to skip
SKIP_DIRS = {'.git', '__pycache__', '.pytest_cache', 'node_modules', '.venv'}

def should_skip(path: Path) -> bool:
    """Check if path should be skipped."""
    for part in path.parts:
        if part in SKIP_DIRS:
            return True
    return False

def update_md_file(filepath: Path) -> bool:
    """Update .md file with standard header."""
    try:
        content = filepath.read_text(encoding='utf-8')

        # Check if already has the correct header
        if content.startswith(MD_HEADER):
            return False

        # Remove old header if exists (various patterns)
        old_patterns = [
            r'^<!-- Code-First Deep Threat Modeling Workflow.*?-->\n*',
            r'^<!-- Threat Modeling Skill.*?-->\n*',
            r'^<!-- STRIDE.*?-->\n*',
        ]

        for pattern in old_patterns:
            content = re.sub(pattern, '', content, flags=re.MULTILINE)

        # Add new header
        new_content = MD_HEADER + '\n\n' + content.lstrip()
        filepath.write_text(new_content, encoding='utf-8')
        return True
    except Exception as e:
        print(f"Error updating {filepath}: {e}")
        return False

def update_code_file(filepath: Path) -> bool:
    """Update .py, .sh, .yaml file with standard header."""
    try:
        content = filepath.read_text(encoding='utf-8')
        lines = content.split('\n')

        # Check if already has the correct header
        if lines and lines[0] == CODE_HEADER:
            return False

        # Handle shebang for .sh and .py files
        shebang = None
        start_idx = 0
        if lines and lines[0].startswith('#!'):
            shebang = lines[0]
            start_idx = 1

        # Remove old header comments at the top (up to 5 lines)
        while start_idx < min(len(lines), 5):
            line = lines[start_idx].strip()
            if line.startswith('# Threat Modeling') or \
               line.startswith('# Code-First') or \
               line.startswith('# STRIDE') or \
               line.startswith('# Version:'):
                start_idx += 1
            elif line == '' or line == '#':
                start_idx += 1
            else:
                break

        # Build new content
        new_lines = []
        if shebang:
            new_lines.append(shebang)
        new_lines.append(CODE_HEADER)

        # Add remaining content
        remaining = lines[start_idx:]
        if remaining and remaining[0].strip():
            new_lines.append('')  # Add blank line before content
        new_lines.extend(remaining)

        new_content = '\n'.join(new_lines)
        filepath.write_text(new_content, encoding='utf-8')
        return True
    except Exception as e:
        print(f"Error updating {filepath}: {e}")
        return False

def main():
    base_dir = Path('/home/elly/STRIDE/threat-modeling')

    stats = {'md': 0, 'py': 0, 'sh': 0, 'yaml': 0, 'skipped': 0}

    # Process .md files
    for filepath in base_dir.rglob('*.md'):
        if should_skip(filepath):
            stats['skipped'] += 1
            continue
        if update_md_file(filepath):
            stats['md'] += 1
            print(f"Updated: {filepath.relative_to(base_dir)}")

    # Process .py files
    for filepath in base_dir.rglob('*.py'):
        if should_skip(filepath):
            stats['skipped'] += 1
            continue
        if update_code_file(filepath):
            stats['py'] += 1
            print(f"Updated: {filepath.relative_to(base_dir)}")

    # Process .sh files
    for filepath in base_dir.rglob('*.sh'):
        if should_skip(filepath):
            stats['skipped'] += 1
            continue
        if update_code_file(filepath):
            stats['sh'] += 1
            print(f"Updated: {filepath.relative_to(base_dir)}")

    # Process .yaml files
    for filepath in base_dir.rglob('*.yaml'):
        if should_skip(filepath):
            stats['skipped'] += 1
            continue
        if update_code_file(filepath):
            stats['yaml'] += 1
            print(f"Updated: {filepath.relative_to(base_dir)}")

    for filepath in base_dir.rglob('*.yml'):
        if should_skip(filepath):
            stats['skipped'] += 1
            continue
        if update_code_file(filepath):
            stats['yaml'] += 1
            print(f"Updated: {filepath.relative_to(base_dir)}")

    print(f"\n=== Summary ===")
    print(f"MD files updated: {stats['md']}")
    print(f"PY files updated: {stats['py']}")
    print(f"SH files updated: {stats['sh']}")
    print(f"YAML files updated: {stats['yaml']}")
    print(f"Files skipped: {stats['skipped']}")

if __name__ == '__main__':
    main()
