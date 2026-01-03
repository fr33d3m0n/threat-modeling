-- ============================================================================
-- STRIDE Knowledge Base Schema Extension
-- Layer 3: Security Verification Tables
-- Layer 4: Compliance Framework Tables
-- Version: 1.0.0
-- Created: 2024-12-26
-- ============================================================================

-- ============================================================================
-- LAYER 3: SECURITY VERIFICATION TABLES
-- ============================================================================

-- WSTG Test Cases Table
-- Stores OWASP Web Security Testing Guide test cases
CREATE TABLE IF NOT EXISTS wstg_test (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    test_id TEXT NOT NULL UNIQUE,           -- e.g., 'WSTG-INPV-05'
    category TEXT NOT NULL,                  -- e.g., 'INPV'
    category_name TEXT NOT NULL,             -- e.g., 'Input Validation Testing'
    name TEXT NOT NULL,                      -- Test name
    objective TEXT,                          -- Test objective
    test_steps TEXT,                         -- JSON array of test steps
    tools TEXT,                              -- JSON array of recommended tools
    severity TEXT CHECK(severity IN ('Critical', 'High', 'Medium', 'Low', 'Info')),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- MASTG Test Cases Table
-- Stores OWASP Mobile Application Security Testing Guide test cases
CREATE TABLE IF NOT EXISTS mastg_test (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    test_id TEXT NOT NULL UNIQUE,           -- e.g., 'MASTG-TEST-0017'
    masvs_id TEXT NOT NULL,                  -- e.g., 'MASVS-AUTH'
    platform TEXT NOT NULL CHECK(platform IN ('android', 'ios', 'both')),
    name TEXT NOT NULL,
    objective TEXT,
    static_analysis TEXT,                    -- Static analysis guidance
    dynamic_analysis TEXT,                   -- Dynamic analysis guidance
    tools TEXT,                              -- JSON array of tools
    severity TEXT CHECK(severity IN ('Critical', 'High', 'Medium', 'Low', 'Info')),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ASVS Requirements Table
-- Stores OWASP Application Security Verification Standard requirements
CREATE TABLE IF NOT EXISTS asvs_requirement (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    requirement_id TEXT NOT NULL UNIQUE,    -- e.g., 'V2.1.1'
    chapter TEXT NOT NULL,                   -- e.g., 'V2'
    chapter_name TEXT NOT NULL,              -- e.g., 'Authentication'
    section TEXT,                            -- e.g., 'V2.1'
    section_name TEXT,                       -- e.g., 'Password Security'
    description TEXT NOT NULL,               -- Requirement description
    level_1 BOOLEAN DEFAULT FALSE,           -- L1 applicability
    level_2 BOOLEAN DEFAULT FALSE,           -- L2 applicability
    level_3 BOOLEAN DEFAULT FALSE,           -- L3 applicability
    verification_method TEXT,                -- Suggested verification method
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- CWE to Verification Test Mapping
-- Maps CWE weaknesses to applicable verification tests
CREATE TABLE IF NOT EXISTS cwe_verification (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cwe_id TEXT NOT NULL,                    -- e.g., 'CWE-89'
    test_type TEXT NOT NULL CHECK(test_type IN ('wstg', 'mastg', 'asvs')),
    test_id TEXT NOT NULL,                   -- Foreign key reference
    relevance TEXT CHECK(relevance IN ('primary', 'secondary')),
    notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (cwe_id) REFERENCES cwe(cwe_id)
);

-- STRIDE to Verification Test Mapping
-- Maps STRIDE categories to verification tests
CREATE TABLE IF NOT EXISTS stride_verification (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    stride_code TEXT NOT NULL CHECK(stride_code IN ('S', 'T', 'R', 'I', 'D', 'E')),
    test_type TEXT NOT NULL CHECK(test_type IN ('wstg', 'mastg', 'asvs')),
    test_id TEXT NOT NULL,
    relevance TEXT CHECK(relevance IN ('primary', 'secondary')),
    notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Verification Procedures Table
-- Stores detailed verification procedures for STRIDE categories
CREATE TABLE IF NOT EXISTS verification_procedure (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    stride_code TEXT NOT NULL CHECK(stride_code IN ('S', 'T', 'R', 'I', 'D', 'E')),
    procedure_type TEXT NOT NULL CHECK(procedure_type IN ('manual', 'automated', 'hybrid')),
    step_order INTEGER NOT NULL,
    action TEXT NOT NULL,                    -- What to do
    expected_result TEXT NOT NULL,           -- Expected outcome
    tools TEXT,                              -- JSON array of applicable tools
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================================
-- LAYER 4: COMPLIANCE FRAMEWORK TABLES
-- ============================================================================

-- Compliance Frameworks Master Table
CREATE TABLE IF NOT EXISTS compliance_framework (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    framework_id TEXT NOT NULL UNIQUE,       -- e.g., 'NIST-800-53'
    name TEXT NOT NULL,
    version TEXT NOT NULL,
    category TEXT NOT NULL CHECK(category IN (
        'sdlc_security',
        'application_security',
        'information_security',
        'cloud_security',
        'ai_governance',
        'ai_security_technical',
        'regional_regulation'
    )),
    url TEXT,
    document_path TEXT,                      -- Local document path
    control_count INTEGER,
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Compliance Controls Table
-- Stores individual controls from each framework
CREATE TABLE IF NOT EXISTS compliance_control (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    framework_id TEXT NOT NULL,
    control_id TEXT NOT NULL,                -- e.g., 'AC-2', 'IAM-01'
    control_family TEXT,                     -- e.g., 'AC' for Access Control
    name TEXT NOT NULL,
    description TEXT,
    guidance TEXT,                           -- Implementation guidance
    priority TEXT CHECK(priority IN ('P1', 'P2', 'P3')),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (framework_id) REFERENCES compliance_framework(framework_id),
    UNIQUE(framework_id, control_id)
);

-- STRIDE to Compliance Control Mapping
CREATE TABLE IF NOT EXISTS stride_compliance (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    stride_code TEXT NOT NULL CHECK(stride_code IN ('S', 'T', 'R', 'I', 'D', 'E')),
    framework_id TEXT NOT NULL,
    control_id TEXT NOT NULL,
    relevance TEXT CHECK(relevance IN ('primary', 'secondary')),
    notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (framework_id) REFERENCES compliance_framework(framework_id)
);

-- CWE to Compliance Control Mapping
CREATE TABLE IF NOT EXISTS cwe_compliance (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cwe_id TEXT NOT NULL,
    framework_id TEXT NOT NULL,
    control_id TEXT NOT NULL,
    notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (cwe_id) REFERENCES cwe(cwe_id),
    FOREIGN KEY (framework_id) REFERENCES compliance_framework(framework_id)
);

-- OWASP Category to Compliance Mapping
CREATE TABLE IF NOT EXISTS owasp_compliance (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    owasp_category TEXT NOT NULL,            -- e.g., 'A01', 'LLM01'
    owasp_type TEXT NOT NULL CHECK(owasp_type IN ('top10_web', 'top10_api', 'top10_llm', 'agentic_ai')),
    framework_id TEXT NOT NULL,
    control_id TEXT NOT NULL,
    notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (framework_id) REFERENCES compliance_framework(framework_id)
);

-- AI-Specific Compliance Requirements
CREATE TABLE IF NOT EXISTS ai_compliance_requirement (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    threat_id TEXT NOT NULL,                 -- e.g., 'LLM01', 'A01'
    threat_source TEXT NOT NULL CHECK(threat_source IN ('owasp_llm', 'agentic_ai', 'mitre_atlas')),
    stride_codes TEXT NOT NULL,              -- Comma-separated: 'S,T,E'
    iso_42001_controls TEXT,                 -- JSON array of controls
    nist_ai_rmf_controls TEXT,               -- JSON array of controls
    eu_ai_act_articles TEXT,                 -- JSON array of articles
    notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================================
-- INDEXES FOR PERFORMANCE
-- ============================================================================

-- Layer 3 Indexes
CREATE INDEX IF NOT EXISTS idx_wstg_category ON wstg_test(category);
CREATE INDEX IF NOT EXISTS idx_mastg_masvs ON mastg_test(masvs_id);
CREATE INDEX IF NOT EXISTS idx_mastg_platform ON mastg_test(platform);
CREATE INDEX IF NOT EXISTS idx_asvs_chapter ON asvs_requirement(chapter);
CREATE INDEX IF NOT EXISTS idx_asvs_level ON asvs_requirement(level_1, level_2, level_3);
CREATE INDEX IF NOT EXISTS idx_cwe_verification_cwe ON cwe_verification(cwe_id);
CREATE INDEX IF NOT EXISTS idx_cwe_verification_test ON cwe_verification(test_type, test_id);
CREATE INDEX IF NOT EXISTS idx_stride_verification ON stride_verification(stride_code, test_type);
CREATE INDEX IF NOT EXISTS idx_verification_procedure ON verification_procedure(stride_code, procedure_type);

-- Layer 4 Indexes
CREATE INDEX IF NOT EXISTS idx_framework_category ON compliance_framework(category);
CREATE INDEX IF NOT EXISTS idx_control_framework ON compliance_control(framework_id);
CREATE INDEX IF NOT EXISTS idx_control_family ON compliance_control(control_family);
CREATE INDEX IF NOT EXISTS idx_stride_compliance_stride ON stride_compliance(stride_code);
CREATE INDEX IF NOT EXISTS idx_stride_compliance_framework ON stride_compliance(framework_id);
CREATE INDEX IF NOT EXISTS idx_cwe_compliance_cwe ON cwe_compliance(cwe_id);
CREATE INDEX IF NOT EXISTS idx_cwe_compliance_framework ON cwe_compliance(framework_id);
CREATE INDEX IF NOT EXISTS idx_owasp_compliance ON owasp_compliance(owasp_category, owasp_type);
CREATE INDEX IF NOT EXISTS idx_ai_compliance ON ai_compliance_requirement(threat_id, threat_source);

-- ============================================================================
-- FULL-TEXT SEARCH INDEXES
-- ============================================================================

-- FTS5 for verification test search
CREATE VIRTUAL TABLE IF NOT EXISTS wstg_test_fts USING fts5(
    test_id,
    name,
    objective,
    content='wstg_test',
    content_rowid='id'
);

CREATE VIRTUAL TABLE IF NOT EXISTS mastg_test_fts USING fts5(
    test_id,
    name,
    objective,
    content='mastg_test',
    content_rowid='id'
);

CREATE VIRTUAL TABLE IF NOT EXISTS asvs_requirement_fts USING fts5(
    requirement_id,
    chapter_name,
    section_name,
    description,
    content='asvs_requirement',
    content_rowid='id'
);

-- FTS5 for compliance control search
CREATE VIRTUAL TABLE IF NOT EXISTS compliance_control_fts USING fts5(
    control_id,
    name,
    description,
    guidance,
    content='compliance_control',
    content_rowid='id'
);

-- ============================================================================
-- TRIGGERS FOR FTS SYNC
-- ============================================================================

-- WSTG FTS triggers
CREATE TRIGGER IF NOT EXISTS wstg_test_ai AFTER INSERT ON wstg_test BEGIN
    INSERT INTO wstg_test_fts(rowid, test_id, name, objective)
    VALUES (NEW.id, NEW.test_id, NEW.name, NEW.objective);
END;

CREATE TRIGGER IF NOT EXISTS wstg_test_ad AFTER DELETE ON wstg_test BEGIN
    INSERT INTO wstg_test_fts(wstg_test_fts, rowid, test_id, name, objective)
    VALUES ('delete', OLD.id, OLD.test_id, OLD.name, OLD.objective);
END;

-- MASTG FTS triggers
CREATE TRIGGER IF NOT EXISTS mastg_test_ai AFTER INSERT ON mastg_test BEGIN
    INSERT INTO mastg_test_fts(rowid, test_id, name, objective)
    VALUES (NEW.id, NEW.test_id, NEW.name, NEW.objective);
END;

CREATE TRIGGER IF NOT EXISTS mastg_test_ad AFTER DELETE ON mastg_test BEGIN
    INSERT INTO mastg_test_fts(mastg_test_fts, rowid, test_id, name, objective)
    VALUES ('delete', OLD.id, OLD.test_id, OLD.name, OLD.objective);
END;

-- ASVS FTS triggers
CREATE TRIGGER IF NOT EXISTS asvs_requirement_ai AFTER INSERT ON asvs_requirement BEGIN
    INSERT INTO asvs_requirement_fts(rowid, requirement_id, chapter_name, section_name, description)
    VALUES (NEW.id, NEW.requirement_id, NEW.chapter_name, NEW.section_name, NEW.description);
END;

CREATE TRIGGER IF NOT EXISTS asvs_requirement_ad AFTER DELETE ON asvs_requirement BEGIN
    INSERT INTO asvs_requirement_fts(asvs_requirement_fts, rowid, requirement_id, chapter_name, section_name, description)
    VALUES ('delete', OLD.id, OLD.requirement_id, OLD.chapter_name, OLD.section_name, OLD.description);
END;

-- Compliance Control FTS triggers
CREATE TRIGGER IF NOT EXISTS compliance_control_ai AFTER INSERT ON compliance_control BEGIN
    INSERT INTO compliance_control_fts(rowid, control_id, name, description, guidance)
    VALUES (NEW.id, NEW.control_id, NEW.name, NEW.description, NEW.guidance);
END;

CREATE TRIGGER IF NOT EXISTS compliance_control_ad AFTER DELETE ON compliance_control BEGIN
    INSERT INTO compliance_control_fts(compliance_control_fts, rowid, control_id, name, description, guidance)
    VALUES ('delete', OLD.id, OLD.control_id, OLD.name, OLD.description, OLD.guidance);
END;

-- ============================================================================
-- VIEWS FOR COMMON QUERIES
-- ============================================================================

-- View: STRIDE to all verification tests
CREATE VIEW IF NOT EXISTS v_stride_all_tests AS
SELECT
    sv.stride_code,
    sc.name AS stride_name,
    sc.security_property,
    sv.test_type,
    sv.test_id,
    sv.relevance,
    CASE
        WHEN sv.test_type = 'wstg' THEN wt.name
        WHEN sv.test_type = 'mastg' THEN mt.name
        WHEN sv.test_type = 'asvs' THEN ar.description
    END AS test_name,
    CASE
        WHEN sv.test_type = 'wstg' THEN wt.objective
        WHEN sv.test_type = 'mastg' THEN mt.objective
        WHEN sv.test_type = 'asvs' THEN ar.verification_method
    END AS test_detail
FROM stride_verification sv
LEFT JOIN stride_category sc ON sv.stride_code = sc.code
LEFT JOIN wstg_test wt ON sv.test_type = 'wstg' AND sv.test_id = wt.test_id
LEFT JOIN mastg_test mt ON sv.test_type = 'mastg' AND sv.test_id = mt.test_id
LEFT JOIN asvs_requirement ar ON sv.test_type = 'asvs' AND sv.test_id = ar.requirement_id;

-- View: CWE with all verification tests
CREATE VIEW IF NOT EXISTS v_cwe_all_tests AS
SELECT
    cv.cwe_id,
    c.name AS cwe_name,
    cv.test_type,
    cv.test_id,
    cv.relevance,
    CASE
        WHEN cv.test_type = 'wstg' THEN wt.name
        WHEN cv.test_type = 'mastg' THEN mt.name
        WHEN cv.test_type = 'asvs' THEN ar.description
    END AS test_name
FROM cwe_verification cv
LEFT JOIN cwe c ON cv.cwe_id = c.cwe_id
LEFT JOIN wstg_test wt ON cv.test_type = 'wstg' AND cv.test_id = wt.test_id
LEFT JOIN mastg_test mt ON cv.test_type = 'mastg' AND cv.test_id = mt.test_id
LEFT JOIN asvs_requirement ar ON cv.test_type = 'asvs' AND cv.test_id = ar.requirement_id;

-- View: STRIDE to all compliance controls
CREATE VIEW IF NOT EXISTS v_stride_all_compliance AS
SELECT
    sco.stride_code,
    sc.name AS stride_name,
    sc.security_property,
    sco.framework_id,
    cf.name AS framework_name,
    cf.category AS framework_category,
    sco.control_id,
    cc.name AS control_name,
    cc.description AS control_description,
    sco.relevance
FROM stride_compliance sco
LEFT JOIN stride_category sc ON sco.stride_code = sc.code
LEFT JOIN compliance_framework cf ON sco.framework_id = cf.framework_id
LEFT JOIN compliance_control cc ON sco.framework_id = cc.framework_id AND sco.control_id = cc.control_id;

-- View: CWE with all compliance controls
CREATE VIEW IF NOT EXISTS v_cwe_all_compliance AS
SELECT
    cwec.cwe_id,
    c.name AS cwe_name,
    cwec.framework_id,
    cf.name AS framework_name,
    cwec.control_id,
    cc.name AS control_name,
    cc.description AS control_description
FROM cwe_compliance cwec
LEFT JOIN cwe c ON cwec.cwe_id = c.cwe_id
LEFT JOIN compliance_framework cf ON cwec.framework_id = cf.framework_id
LEFT JOIN compliance_control cc ON cwec.framework_id = cc.framework_id AND cwec.control_id = cc.control_id;

-- View: Complete STRIDE knowledge chain
CREATE VIEW IF NOT EXISTS v_stride_knowledge_chain AS
SELECT
    sc.code AS stride_code,
    sc.name AS stride_name,
    sc.security_property,
    scw.cwe_id,
    c.name AS cwe_name,
    -- Verification tests
    (SELECT GROUP_CONCAT(test_id) FROM stride_verification WHERE stride_code = sc.code AND test_type = 'wstg') AS wstg_tests,
    (SELECT GROUP_CONCAT(test_id) FROM stride_verification WHERE stride_code = sc.code AND test_type = 'asvs') AS asvs_requirements,
    -- Compliance controls
    (SELECT GROUP_CONCAT(framework_id || ':' || control_id) FROM stride_compliance WHERE stride_code = sc.code AND relevance = 'primary') AS primary_controls
FROM stride_category sc
LEFT JOIN stride_cwe scw ON sc.code = scw.stride_code
LEFT JOIN cwe c ON scw.cwe_id = c.cwe_id;

-- ============================================================================
-- SECURITY CONTROLS TABLE (security-controls directory content)
-- Stores curated security implementation patterns with STRIDE mappings
-- ============================================================================

CREATE TABLE IF NOT EXISTS security_control (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    control_id TEXT NOT NULL UNIQUE,             -- e.g., 'codeguard-0-input-validation-injection'
    name TEXT NOT NULL,                           -- e.g., 'Input Validation & Injection Defense'
    description TEXT NOT NULL,                    -- Main description from frontmatter
    category TEXT NOT NULL,                       -- e.g., 'input_validation', 'authentication', 'data_storage'
    languages TEXT,                               -- JSON array of applicable languages
    stride_mitigations TEXT,                      -- JSON: {"S": true, "T": true, ...}
    core_principles TEXT,                         -- JSON array of core principles
    implementation_checklist TEXT,                -- JSON array of checklist items
    code_examples TEXT,                           -- JSON: {"typescript": "...", "java": "..."}
    tools TEXT,                                   -- JSON array of recommended tools
    related_cwes TEXT,                            -- JSON array of related CWE IDs
    source_file TEXT NOT NULL,                    -- Original markdown file path
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- STRIDE to Security Control Mapping
CREATE TABLE IF NOT EXISTS stride_security_control (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    stride_code TEXT NOT NULL CHECK(stride_code IN ('S', 'T', 'R', 'I', 'D', 'E')),
    control_id TEXT NOT NULL,
    relevance TEXT CHECK(relevance IN ('primary', 'secondary')),
    notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (control_id) REFERENCES security_control(control_id)
);

-- Indexes for security controls
CREATE INDEX IF NOT EXISTS idx_security_control_category ON security_control(category);
CREATE INDEX IF NOT EXISTS idx_stride_security_control ON stride_security_control(stride_code);
CREATE INDEX IF NOT EXISTS idx_stride_security_control_id ON stride_security_control(control_id);

-- FTS5 for security control search
CREATE VIRTUAL TABLE IF NOT EXISTS security_control_fts USING fts5(
    control_id,
    name,
    description,
    core_principles,
    implementation_checklist,
    content='security_control',
    content_rowid='id'
);

-- Security Control FTS triggers
CREATE TRIGGER IF NOT EXISTS security_control_ai AFTER INSERT ON security_control BEGIN
    INSERT INTO security_control_fts(rowid, control_id, name, description, core_principles, implementation_checklist)
    VALUES (NEW.id, NEW.control_id, NEW.name, NEW.description, NEW.core_principles, NEW.implementation_checklist);
END;

CREATE TRIGGER IF NOT EXISTS security_control_ad AFTER DELETE ON security_control BEGIN
    INSERT INTO security_control_fts(security_control_fts, rowid, control_id, name, description, core_principles, implementation_checklist)
    VALUES ('delete', OLD.id, OLD.control_id, OLD.name, OLD.description, OLD.core_principles, OLD.implementation_checklist);
END;

-- View: STRIDE to Security Controls
CREATE VIEW IF NOT EXISTS v_stride_security_controls AS
SELECT
    ssc.stride_code,
    sc_cat.name AS stride_name,
    sc_cat.security_property,
    ssc.control_id,
    sec.name AS control_name,
    sec.description,
    sec.category,
    sec.languages,
    ssc.relevance
FROM stride_security_control ssc
LEFT JOIN stride_category sc_cat ON ssc.stride_code = sc_cat.code
LEFT JOIN security_control sec ON ssc.control_id = sec.control_id;

-- ============================================================================
-- METADATA TABLE
-- ============================================================================

CREATE TABLE IF NOT EXISTS schema_metadata (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    schema_version TEXT NOT NULL,
    layer TEXT NOT NULL,
    description TEXT,
    applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insert schema version record
INSERT INTO schema_metadata (schema_version, layer, description)
VALUES
    ('1.0.0', 'layer_3', 'Security Verification Knowledge Layer - WSTG, MASTG, ASVS mappings'),
    ('1.0.0', 'layer_4', 'Compliance Framework Knowledge Layer - NIST, CIS, CSA, ISO mappings'),
    ('1.0.0', 'security_controls', 'Security Implementation Patterns - Curated security control patterns with STRIDE mappings');
