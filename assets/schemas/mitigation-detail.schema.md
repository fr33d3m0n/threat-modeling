<!-- Code-First Deep Threat Modeling Workflow | Version 2.1.0 | https://github.com/fr33d3m0n/skill-threat-modeling | License: BSD-3-Clause | Welcome to cite but please retain all sources and declarations -->

# Mitigation Detail Schema

> **Version**: 1.0.0
> **Created**: 2026-01-02
> **Purpose**: Define structure for mitigation measures including fix location tracking

---

## 1. Overview

This schema defines the structure for mitigation measures in STRIDE threat modeling reports,
with a focus on precise fix location tracking to enable rapid developer action.

---

## 2. Core Entity: Mitigation

```yaml
mitigation:
  id:
    type: string
    format: "M-{Seq}"
    example: "M-001"
    required: true

  title:
    type: string
    required: true
    description: "Clear, action-oriented mitigation title"
    example: "Implement JWT Token Validation"

  priority:
    type: enum
    values: [P0, P1, P2, P3]
    required: true
    description: |
      P0: Immediate (Critical risks)
      P1: Urgent (High risks)
      P2: High priority (Medium risks)
      P3: Planned (Low risks, architectural)

  threat_refs:
    type: array[string]
    format: "VR-{Seq}"
    required: true
    min_length: 1
    description: "Validated risks this mitigation addresses"
    example: ["VR-001", "VR-002"]

  risk_reduction:
    type: number
    unit: percentage
    range: [0, 100]
    required: true
    description: "Estimated risk reduction after implementation"
```

---

## 3. Fix Location Structure (v2.0.5 NEW)

The `fix_location` field provides precise code location for developers.

### 3.1 Primary Fix Location

```yaml
fix_location:
  primary:
    module:
      type: string
      required: true
      description: "High-level module or package name"
      examples: ["auth", "api", "middleware", "models", "services"]

    function:
      type: string
      required: true
      description: "Function, method, or class name"
      format: "{name}()" for functions, "{ClassName}" for classes
      examples: ["validateToken()", "UserAuth", "handleRequest()"]

    file:
      type: string
      format: relative_path
      required: true
      description: "File path relative to project root"
      examples: ["src/middleware/auth.py", "lib/security/jwt.ts"]

    line_range:
      type: string
      format: "{start}-{end}" or "{line}"
      required: true
      description: "Line number or range requiring modification"
      examples: ["45-52", "123", "1-50"]
```

### 3.2 Code Context

```yaml
fix_location:
  context:
    before:
      type: array[string]
      max_items: 3
      description: "Lines before the vulnerable code (for context)"

    vulnerable:
      type: string
      required: true
      description: "The specific line or code block with vulnerability"

    after:
      type: array[string]
      max_items: 3
      description: "Lines after the vulnerable code (for context)"
```

### 3.3 Related Fix Locations

```yaml
fix_location:
  related:
    type: array
    description: "Other files requiring coordinated changes"
    items:
      file:
        type: string
        required: true
        description: "Related file path"

      line:
        type: integer
        required: true
        description: "Line number in related file"

      change_type:
        type: enum
        values: [add, modify, delete, config]
        required: true
        description: |
          add: New code to be added
          modify: Existing code to be changed
          delete: Code to be removed
          config: Configuration change

      description:
        type: string
        required: true
        description: "Brief description of required change"
```

---

## 4. Complete Mitigation Structure

```yaml
mitigation:
  # Identity
  id: "M-001"
  title: "Implement JWT Token Validation"
  priority: P0

  # Traceability
  threat_refs: ["VR-001", "VR-003"]
  risk_reduction: 85

  # ⚠️ Fix Location (REQUIRED in v2.0.5+)
  fix_location:
    primary:
      module: "middleware"
      function: "validateToken()"
      file: "src/middleware/auth.py"
      line_range: "45-52"
    context:
      before:
        - "def validateToken(token):"
        - "    # TODO: Add proper validation"
      vulnerable: "    return True  # Always returns True - INSECURE!"
      after:
        - ""
        - "def refreshToken(token):"
    related:
      - file: "src/routes/api.py"
        line: 23
        change_type: "modify"
        description: "Apply @require_auth decorator to protected routes"
      - file: "src/config/security.yaml"
        line: 15
        change_type: "config"
        description: "Configure JWT secret and expiration"

  # Current State
  current_state:
    description: "Token validation always returns True, allowing bypass"
    vulnerable_code: |
      def validateToken(token):
          return True  # FIXME

  # Recommended Control
  recommended_control:
    description: "Implement proper JWT signature and expiration validation"
    secure_code: |
      import jwt
      from datetime import datetime

      def validateToken(token):
          try:
              payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
              if payload['exp'] < datetime.utcnow().timestamp():
                  return False
              return True
          except jwt.InvalidTokenError:
              return False

  # Implementation
  implementation_steps:
    - "Install PyJWT library: pip install pyjwt"
    - "Configure JWT_SECRET in environment variables"
    - "Replace validateToken() function with secure implementation"
    - "Add token expiration check"
    - "Update all routes to use the decorator"

  # Dependencies
  dependencies:
    - name: "PyJWT"
      type: "library"
      version: ">=2.0.0"
    - name: "JWT_SECRET"
      type: "config"
      description: "256-bit secret key for signing"

  # Verification
  verification:
    method: "automated_test + manual_review"
    test_code: |
      def test_invalid_token_rejected():
          response = client.get('/api/protected', headers={'Authorization': 'invalid'})
          assert response.status_code == 401
    expected_result: "All unauthenticated requests return 401"

  # Rollback
  rollback_plan: |
    1. Revert auth.py to previous version
    2. Remove JWT dependency if added
    3. Clear any cached tokens
```

---

## 5. Validation Rules

### 5.1 Required Fields

| Field | Required | Validation |
|-------|----------|------------|
| `id` | Yes | Format: `M-{Seq}` |
| `title` | Yes | Non-empty string |
| `priority` | Yes | One of: P0, P1, P2, P3 |
| `threat_refs` | Yes | Array with at least 1 VR-xxx |
| `fix_location.primary` | Yes | All 4 subfields required |
| `current_state` | Yes | Description + code |
| `recommended_control` | Yes | Description + code |

### 5.2 Fix Location Validation

```python
def validate_fix_location(mitigation):
    """Validate fix_location structure completeness."""
    errors = []

    fix_loc = mitigation.get('fix_location', {})
    primary = fix_loc.get('primary', {})

    # Check required primary fields
    required_primary = ['module', 'function', 'file', 'line_range']
    for field in required_primary:
        if not primary.get(field):
            errors.append(f"Missing fix_location.primary.{field}")

    # Validate line_range format
    line_range = primary.get('line_range', '')
    if not re.match(r'^\d+(-\d+)?$', line_range):
        errors.append(f"Invalid line_range format: {line_range}")

    # Validate file path format
    file_path = primary.get('file', '')
    if not file_path or file_path.startswith('/'):
        errors.append("file should be relative path, not absolute")

    # Validate related changes
    for i, related in enumerate(fix_loc.get('related', [])):
        if not related.get('file'):
            errors.append(f"Missing file in related[{i}]")
        if related.get('change_type') not in ['add', 'modify', 'delete', 'config']:
            errors.append(f"Invalid change_type in related[{i}]")

    return errors
```

---

## 6. Integration with Other Schemas

### 6.1 Traceability Chain

```
Threat (P5)  →  ValidatedRisk (P6)  →  Mitigation (P7)
T-{S}-{E}-{Seq}     VR-{Seq}             M-{Seq}
                         │                    │
                    threat_refs[]        threat_refs[]
```

### 6.2 Cross-References

| This Schema | Related Schema | Relationship |
|-------------|----------------|--------------|
| `threat_refs` | risk-detail.schema.md | VR IDs from P6 |
| `fix_location.file` | Phase 1 output | Must exist in project tree |
| `priority` | phase-risk-summary.schema.md | Derived from risk severity |

---

**Schema Version**: 1.0.0
**Last Updated**: 2026-01-02
