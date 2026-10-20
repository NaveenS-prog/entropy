import os
import docx
from docx import Document
from docx.shared import Inches, Pt, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT, WD_ALIGN_VERTICAL
from docx.oxml import OxmlElement, parse_xml
from docx.oxml.ns import nsdecls, qn

def set_cell_background(cell, fill_hex):
    tcPr = cell._tc.get_or_add_tcPr()
    shd = parse_xml(f'<w:shd {nsdecls("w")} w:fill="{fill_hex}"/>')
    tcPr.append(shd)

def set_cell_margins(cell, top=80, bottom=80, left=120, right=120):
    tcPr = cell._tc.get_or_add_tcPr()
    tcMar = parse_xml(f'''
        <w:tcMar {nsdecls("w")}>
            <w:top w:w="{top}" w:type="dxa"/>
            <w:bottom w:w="{bottom}" w:type="dxa"/>
            <w:left w:w="{left}" w:type="dxa"/>
            <w:right w:w="{right}" w:type="dxa"/>
        </w:tcMar>
    ''')
    tcPr.append(tcMar)

def add_callout(doc, text, title="CORE PRINCIPLE", border_color="059669", bg_color="ECFDF5"):
    tbl = doc.add_table(rows=1, cols=1)
    tbl.alignment = WD_TABLE_ALIGNMENT.CENTER
    tbl.autofit = False
    
    cell = tbl.cell(0, 0)
    cell.width = Inches(7.0)
    set_cell_background(cell, bg_color)
    set_cell_margins(cell, top=100, bottom=100, left=160, right=140)
    
    tcPr = cell._tc.get_or_add_tcPr()
    borders = parse_xml(f'''
        <w:tcBorders {nsdecls("w")}>
            <w:top w:val="none"/>
            <w:left w:val="single" w:sz="24" w:space="0" w:color="{border_color}"/>
            <w:bottom w:val="none"/>
            <w:right w:val="none"/>
        </w:tcBorders>
    ''')
    tcPr.append(borders)
    
    p = cell.paragraphs[0]
    p.paragraph_format.space_before = Pt(2)
    p.paragraph_format.space_after = Pt(2)
    p.paragraph_format.line_spacing = 1.15
    run_t = p.add_run(f"■ {title}: ")
    run_t.bold = True
    run_t.font.name = "Calibri"
    run_t.font.size = Pt(10.0)
    run_t.font.color.rgb = RGBColor.from_string(border_color)
    
    run_body = p.add_run(text)
    run_body.font.name = "Calibri"
    run_body.font.size = Pt(9.5)
    run_body.font.italic = True
    run_body.font.color.rgb = RGBColor(0x1F, 0x29, 0x37)

def add_code_block(doc, code_text):
    tbl = doc.add_table(rows=1, cols=1)
    tbl.alignment = WD_TABLE_ALIGNMENT.CENTER
    tbl.autofit = False
    
    cell = tbl.cell(0, 0)
    cell.width = Inches(7.0)
    set_cell_background(cell, "0F172A")
    set_cell_margins(cell, top=80, bottom=80, left=140, right=140)
    
    tcPr = cell._tc.get_or_add_tcPr()
    borders = parse_xml(f'''
        <w:tcBorders {nsdecls("w")}>
            <w:top w:val="single" w:sz="6" w:space="0" w:color="334155"/>
            <w:left w:val="single" w:sz="18" w:space="0" w:color="10B981"/>
            <w:bottom w:val="single" w:sz="6" w:space="0" w:color="334155"/>
            <w:right w:val="single" w:sz="6" w:space="0" w:color="334155"/>
        </w:tcBorders>
    ''')
    tcPr.append(borders)
    
    p = cell.paragraphs[0]
    p.paragraph_format.space_before = Pt(2)
    p.paragraph_format.space_after = Pt(2)
    p.paragraph_format.line_spacing = 1.1
    run = p.add_run(code_text)
    run.font.name = "Consolas"
    run.font.size = Pt(8.5)
    run.font.color.rgb = RGBColor(0x38, 0xBD, 0xF8)

def format_table(tbl, col_widths, hdr_bg="0F172A", alt_bg="F8FAFC"):
    tbl.alignment = WD_TABLE_ALIGNMENT.CENTER
    for i, row in enumerate(tbl.rows):
        trPr = row._tr.get_or_add_trPr()
        trPr.append(parse_xml(f'<w:cantSplit {nsdecls("w")}/>'))
        
        is_hdr = (i == 0)
        if is_hdr:
            trPr.append(parse_xml(f'<w:tblHeader {nsdecls("w")}/>'))
            
        for j, cell in enumerate(row.cells):
            cell.width = Inches(col_widths[j])
            set_cell_margins(cell, top=60, bottom=60, left=90, right=90)
            cell.vertical_alignment = WD_ALIGN_VERTICAL.CENTER
            
            tcPr = cell._tc.get_or_add_tcPr()
            borders = parse_xml(f'''
                <w:tcBorders {nsdecls("w")}>
                    <w:top w:val="single" w:sz="4" w:space="0" w:color="CBD5E1"/>
                    <w:left w:val="none"/>
                    <w:bottom w:val="single" w:sz="{"10" if is_hdr else "4"}" w:space="0" w:color="{"059669" if is_hdr else "E2E8F0"}"/>
                    <w:right w:val="none"/>
                </w:tcBorders>
            ''')
            tcPr.append(borders)
            
            if is_hdr:
                set_cell_background(cell, hdr_bg)
                for p in cell.paragraphs:
                    p.paragraph_format.space_before = Pt(2)
                    p.paragraph_format.space_after = Pt(2)
                    p.paragraph_format.line_spacing = 1.05
                    for r in p.runs:
                        r.font.name = "Calibri"
                        r.font.size = Pt(9.0)
                        r.bold = True
                        r.font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)
            else:
                if i % 2 == 1:
                    set_cell_background(cell, "FFFFFF")
                else:
                    set_cell_background(cell, alt_bg)
                for p in cell.paragraphs:
                    p.paragraph_format.space_before = Pt(2)
                    p.paragraph_format.space_after = Pt(2)
                    p.paragraph_format.line_spacing = 1.05
                    for r in p.runs:
                        r.font.name = "Calibri"
                        r.font.size = Pt(8.5)
                        r.font.color.rgb = RGBColor(0x33, 0x41, 0x55)

def build_document(output_path):
    doc = Document()
    
    # Page Setup
    for s in doc.sections:
        s.top_margin = Inches(0.7)
        s.bottom_margin = Inches(0.7)
        s.left_margin = Inches(0.75)
        s.right_margin = Inches(0.75)
        
        # Header / Footer
        hdr = s.header
        hp = hdr.paragraphs[0]
        hp.alignment = WD_ALIGN_PARAGRAPH.RIGHT
        hrun = hp.add_run("ENTROPY • System Architecture & Technical Deep Dive")
        hrun.font.name = "Calibri"
        hrun.font.size = Pt(8.0)
        hrun.font.color.rgb = RGBColor(0x94, 0xA3, 0xB8)
        
        ftr = s.footer
        fp = ftr.paragraphs[0]
        fp.alignment = WD_ALIGN_PARAGRAPH.CENTER
        frun = fp.add_run("Entropy Architectural Security Debt Platform • Authoritative Specification")
        frun.font.name = "Calibri"
        frun.font.size = Pt(8.0)
        frun.font.color.rgb = RGBColor(0x94, 0xA3, 0xB8)

    # Document Title Block
    title_p = doc.add_paragraph()
    title_p.paragraph_format.space_before = Pt(4)
    title_p.paragraph_format.space_after = Pt(2)
    trun = title_p.add_run("ENTROPY")
    trun.font.name = "Calibri"
    trun.font.size = Pt(26.0)
    trun.bold = True
    trun.font.color.rgb = RGBColor(0x0F, 0x17, 0x2A)
    
    sub_p = doc.add_paragraph()
    sub_p.paragraph_format.space_before = Pt(0)
    sub_p.paragraph_format.space_after = Pt(4)
    srun = sub_p.add_run("Architectural Security-Debt Analyzer for AI-Assisted Codebases")
    srun.font.name = "Calibri"
    srun.font.size = Pt(13.0)
    srun.bold = True
    srun.font.color.rgb = RGBColor(0x05, 0x96, 0x69)
    
    meta_p = doc.add_paragraph()
    meta_p.paragraph_format.space_before = Pt(0)
    meta_p.paragraph_format.space_after = Pt(14)
    mrun = meta_p.add_run("Comprehensive Technical Architecture, Mathematical Model & Layer-by-Layer Rationale")
    mrun.font.name = "Calibri"
    mrun.font.size = Pt(10.0)
    mrun.font.italic = True
    mrun.font.color.rgb = RGBColor(0x64, 0x74, 0x8B)

    # Divider line
    div = doc.add_paragraph()
    div.paragraph_format.space_after = Pt(10)
    drun = div.add_run("―" * 58)
    drun.font.color.rgb = RGBColor(0xCB, 0xD5, 0xE1)

    # Section 1
    h1 = doc.add_heading("1. Executive Summary & Core Threat Model", level=1)
    h1.paragraph_format.space_before = Pt(12)
    h1.paragraph_format.space_after = Pt(4)
    h1.runs[0].font.color.rgb = RGBColor(0x0F, 0x17, 0x2A)

    p = doc.add_paragraph()
    p.paragraph_format.space_after = Pt(6)
    p.paragraph_format.line_spacing = 1.15
    p.add_run(
        "As engineering teams increasingly leverage generative AI coding assistants (Copilot, Claude, Cursor, Gemini), "
        "software development velocity has accelerated dramatically. However, AI models optimize for local completion "
        "rather than global architectural coherence. This dynamic produces a distinct category of hazard: "
    )
    r = p.add_run("Architectural Security Debt.")
    r.bold = True
    r.font.color.rgb = RGBColor(0x05, 0x96, 0x69)

    add_callout(
        doc,
        "Traditional SAST/DAST scanners look for known CVEs or immediate exploit payloads in code today (such as SQL injections). "
        "Entropy focuses on observable architectural patterns that may not be an immediate vulnerability today, but accumulate "
        "compound maintenance, security, and failure risk over time.",
        title="CORE THREAT MODEL"
    )

    doc.add_paragraph().paragraph_format.space_after = Pt(4)

    # Comparison Table
    t1 = doc.add_table(rows=6, cols=2)
    t1.rows[0].cells[0].paragraphs[0].add_run("Traditional SAST / DAST Focus")
    t1.rows[0].cells[1].paragraphs[0].add_run("Entropy Architectural Focus")
    
    rows_data = [
        ("SQL injection strings, raw exploit payloads", "Overly broad exception handlers swallowing auth/crypto errors"),
        ("Known CVE library dependencies", "Missing authentication/authorization checks across endpoints"),
        ("Buffer overflows & memory corruption", "Fragmented, ad-hoc validation logic across service layers"),
        ("Hardcoded plain-text passwords (regex matching)", "High Shannon entropy string literals (>3.2) & unredacted logging"),
        ("Immediate exploitability today (point-in-time snapshot)", "Cumulative structural debt & maintainability degradation over time")
    ]
    for idx, (c1, c2) in enumerate(rows_data, start=1):
        t1.rows[idx].cells[0].paragraphs[0].add_run(c1)
        t1.rows[idx].cells[1].paragraphs[0].add_run(c2)
    format_table(t1, [3.4, 3.6])

    # Section 2
    h2 = doc.add_heading("2. The Non-Attribution Covenant (Anti-Hallucination)", level=1)
    h2.paragraph_format.space_before = Pt(16)
    h2.paragraph_format.space_after = Pt(4)
    h2.runs[0].font.color.rgb = RGBColor(0x0F, 0x17, 0x2A)

    p = doc.add_paragraph()
    p.paragraph_format.space_after = Pt(6)
    p.paragraph_format.line_spacing = 1.15
    p.add_run(
        "Early security ventures attempted to market 'AI Code Detectors' that output claims like 'This repository is 68% AI-authored.' "
        "Entropy fundamentally rejects this practice for three scientific and engineering reasons:"
    )

    bullets = [
        ("Statistical Unreliability: ", "LLM watermarking and statistical stylometry classifiers produce prohibitive false-positive rates on standard boilerplate, library wrappers, and frameworks."),
        ("Defect Liability: ", "Attributing defects to author identity (human vs. machine) alienates engineering teams. Code review must analyze the verifiable syntactic properties of the software, not guess authorship."),
        ("Product Integrity: ", "Entropy's Engineering Constitution strictly forbids calculating 'AI probability' or 'authorship percentage'. Every finding traces to concrete, line-numbered AST structures.")
    ]
    for b_title, b_desc in bullets:
        bp = doc.add_paragraph(style='List Bullet')
        bp.paragraph_format.space_after = Pt(2)
        bp.paragraph_format.line_spacing = 1.1
        r1 = bp.add_run(b_title)
        r1.bold = True
        r1.font.color.rgb = RGBColor(0x0F, 0x17, 0x2A)
        r2 = bp.add_run(b_desc)
        r2.font.color.rgb = RGBColor(0x33, 0x41, 0x55)

    add_callout(
        doc,
        "\"The Entropy Score is an indicator of architectural and security debt detected by Entropy's static-analysis rules. "
        "It is not a vulnerability probability and does not measure AI authorship.\"",
        title="ARTICLE II CONSTITUTIONAL MANDATE",
        border_color="0284C7",
        bg_color="F0F9FF"
    )

    # Section 3
    h3 = doc.add_heading("3. The 8-Layer Architectural Pipeline", level=1)
    h3.paragraph_format.space_before = Pt(16)
    h3.paragraph_format.space_after = Pt(4)
    h3.runs[0].font.color.rgb = RGBColor(0x0F, 0x17, 0x2A)

    p = doc.add_paragraph()
    p.paragraph_format.space_after = Pt(6)
    p.paragraph_format.line_spacing = 1.15
    p.add_run(
        "Entropy enforces strict architectural decoupling across 8 distinct pipeline stages. "
        "Static analysis rules never live inside API route handlers, and the frontend never computes scores."
    )

    pipeline_stages = [
        ("Layer 1: Repository Ingestion & Discovery", 
         "Walks filesystem, respects .gitignore hierarchies, extracts git branch/commit SHA via subprocess. Enforces Zero Code Execution (target code is treated strictly as passive text, never imported into the Python runtime)."),
        ("Layer 2: Multi-Language AST Parsing", 
         "Transforms raw code into Abstract Syntax Trees. Python uses native ast.NodeVisitor; JS/TS uses a recursive visitor covering Express, Fastify, Next.js, Hono, and NestJS. Syntax errors fail gracefully without crashing scans."),
        ("Layer 3: Static Analysis Engine (7 Categories)", 
         "Modular analyzers evaluate verifiable structural properties across Error Handling, AuthN, AuthZ, Validation, Secrets, Architecture, and Duplication."),
        ("Layer 4: Finding Generation & Stable Fingerprinting", 
         "Constructs structured Finding objects with verbatim code snippets. Generates line-drift invariant SHA-256 fingerprints: hash(rule_id || relative_path || symbol || ast_tokens) to preserve finding identity across git edits."),
        ("Layer 5: Mathematical Scoring Engine", 
         "Calculates the deterministic 0–100 Entropy Debt Score. Incorporates rule-level logarithmic diminishing returns, KLOC density normalization, exponential asymptotic saturation, and anti-dilution severity floors."),
        ("Layer 6: Policy Engine & Delta Baselines", 
         "Compares current commit against baseline scans to determine delta debt (Δ = Current - Base). Evaluates pass/fail CI policies and generates OASIS SARIF 2.1.0 reports for GitHub Security tabs."),
        ("Layer 7: Grounded AI Explanations", 
         "Integrates Google Gemini to synthesize architectural impact explanations and remediation diffs. Operates strictly read-only after scrubbing source code via a PII/secret redaction pipeline."),
        ("Layer 8: Presentation Tier (API & UI)", 
         "FastAPI exposes versioned REST endpoints (/api/v1). Next.js 14 + Tailwind dashboard renders live metrics. Follows Invariant 5: The frontend is strictly a visualization layer and NEVER calculates debt scores.")
    ]

    for stage_title, stage_desc in pipeline_stages:
        sp = doc.add_paragraph()
        sp.paragraph_format.space_before = Pt(4)
        sp.paragraph_format.space_after = Pt(2)
        sp.paragraph_format.line_spacing = 1.12
        r1 = sp.add_run(f"■ {stage_title}: ")
        r1.bold = True
        r1.font.color.rgb = RGBColor(0x0F, 0x17, 0x2A)
        r2 = sp.add_run(stage_desc)
        r2.font.color.rgb = RGBColor(0x33, 0x41, 0x55)

    # Section 4
    h4 = doc.add_heading("4. The 7 Static Analysis Engines", level=1)
    h4.paragraph_format.space_before = Pt(16)
    h4.paragraph_format.space_after = Pt(4)
    h4.runs[0].font.color.rgb = RGBColor(0x0F, 0x17, 0x2A)

    t2 = doc.add_table(rows=8, cols=4)
    headers = ["Category", "Weight", "Supported Frameworks", "Core Architectural Detection Mechanics"]
    for i, h_text in enumerate(headers):
        t2.rows[0].cells[i].paragraphs[0].add_run(h_text)
        
    cat_data = [
        ("Authentication Consistency", "0.20", "FastAPI, Flask, Django, Express, Fastify, Next.js, Hono, NestJS", 
         "Extracts routes; identifies missing route guards; traces Express middleware registration ordering; discards no-op pass-through middleware."),
        ("Authorization Consistency", "0.20", "FastAPI, Flask, Django, Express, Fastify, Next.js, Hono, NestJS", 
         "Detects authenticated endpoints lacking role/scope checks (RBAC) on state-mutating sensitive routes (POST/DELETE admin)."),
        ("Error Handling Debt", "0.15", "Python, JavaScript, TypeScript", 
         "Identifies bare except:, broad except Exception: swallowing errors with pass or return None/{}, and unhandled Promise rejections."),
        ("Input Validation Debt", "0.15", "Pydantic, Zod, Joi, SQLAlchemy, raw SQL", 
         "Taint sink analysis: flags unvalidated query/body inputs reaching cursor.execute(f'...') or raw template literals."),
        ("Logging & Secrets", "0.15", "Python, JavaScript, TypeScript", 
         "Computes Shannon Entropy (H > 3.2 threshold for high-randomness string literals); regex secret signatures; unredacted logging of PII."),
        ("Architectural Consistency", "0.10", "Python, JavaScript, TypeScript", 
         "Graph-theoretic cycle detection (Tarjan's algorithm) for circular imports; filters safe if TYPE_CHECKING: guards."),
        ("Code Duplication", "0.05", "Python, JavaScript, TypeScript", 
         "AST subtree hashing (stripping variable names and comments) to detect copy-pasted blocks across service boundaries.")
    ]

    for idx, (c1, c2, c3, c4) in enumerate(cat_data, start=1):
        t2.rows[idx].cells[0].paragraphs[0].add_run(c1)
        t2.rows[idx].cells[1].paragraphs[0].add_run(c2)
        t2.rows[idx].cells[2].paragraphs[0].add_run(c3)
        t2.rows[idx].cells[3].paragraphs[0].add_run(c4)
    format_table(t2, [1.6, 0.6, 2.0, 2.8])

    # Section 5: Math
    h5 = doc.add_heading("5. Mathematical Scoring Engine Derivation", level=1)
    h5.paragraph_format.space_before = Pt(16)
    h5.paragraph_format.space_after = Pt(4)
    h5.runs[0].font.color.rgb = RGBColor(0x0F, 0x17, 0x2A)

    p = doc.add_paragraph()
    p.paragraph_format.space_after = Pt(6)
    p.paragraph_format.line_spacing = 1.15
    p.add_run(
        "A naive defect counter fails on real software: 5 swallowed exceptions in a 200-line script is severe, "
        "while in a 500,000-line monorepo it represents excellent discipline. "
        "Entropy's mathematical model guarantees scale invariance, monotonicity, and anti-dilution."
    )

    math_steps = [
        ("Step 1: Rule-Level Logarithmic Diminishing Returns",
         "Points(f) = W_severity(f) × M_confidence(f)\n"
         "Weights: CRITICAL = 10.0, HIGH = 7.0, MEDIUM = 4.0, LOW = 1.0, INFO = 0.0\n"
         "Multipliers: HIGH = 1.0, MEDIUM = 0.8, LOW = 0.5\n"
         "To prevent one noisy rule from flooding the score, findings exceeding N = 20 scale logarithmically:\n"
         "Penalty(r) = Σ Points(f_i) [for i=1..20] + AvgPoints(r) × 5.0 × ln(1 + (k - 20) / 1.0)\n"
         "Guarantees 4,000 duplicate instances cannot exceed ~3.1x the penalty of 20 instances."),
        ("Step 2: Effective Codebase Scale & KLOC Floor",
         "Effective LOC = max(Total_LOC, 200)\n"
         "KLOC = Effective LOC / 1000.0\n"
         "Weighted Debt Density_c = Raw Penalty_c / KLOC\n"
         "Guarantees scale invariance: 1 defect per 100 LOC yields the same density across 500 lines or 500,000 lines."),
        ("Step 3: Asymptotic Exponential Saturation (0–100)",
         "Category Score_c = 100.0 × (1.0 - exp(- Weighted Debt Density_c / 40.0))\n"
         "Uses a natural saturation constant K = 40.0. Scores are mathematically bounded in [0, 100] with smooth asymptotic saturation."),
        ("Step 4: Anti-Dilution Severity Floors",
         "The fatal flaw of pure density: in a 1,000,000 LOC codebase, an unauthenticated admin route or raw AWS root secret would yield a density of 0.001 (score ~0).\n"
         "Entropy enforces a non-negotiable Severity Floor:\n"
         "• 1 HIGH finding (HIGH confidence) ==> Minimum Score = 41 (MODERATE)\n"
         "• 1 CRITICAL finding (HIGH confidence) ==> Minimum Score = 61 (HIGH)\n"
         "• ≥ 2 CRITICAL findings ==> Minimum Score = 81 (VERY HIGH)\n"
         "Final Score = max(Score_density, Severity Floor)"),
        ("Step 5: Dynamic Weight Normalization",
         "If a repository has no web frameworks (e.g. pure CLI tool), AuthN and AuthZ are marked NOT_ANALYZED.\n"
         "Entropy NEVER assigns fake 0.0 scores. Active category weights (A) are normalized dynamically:\n"
         "w_c(rel) = W_c / Σ W_a [for a in A]\n"
         "Entropy Score = round(Σ w_c(rel) × Category Score_c)")
    ]

    for m_title, m_code in math_steps:
        p_m = doc.add_paragraph()
        p_m.paragraph_format.space_before = Pt(6)
        p_m.paragraph_format.space_after = Pt(2)
        r_mt = p_m.add_run(f"■ {m_title}")
        r_mt.bold = True
        r_mt.font.color.rgb = RGBColor(0x05, 0x96, 0x69)
        add_code_block(doc, m_code)

    # Section 6: Technology Rationale
    h6 = doc.add_heading("6. Technology Stack Rationale", level=1)
    h6.paragraph_format.space_before = Pt(16)
    h6.paragraph_format.space_after = Pt(4)
    h6.runs[0].font.color.rgb = RGBColor(0x0F, 0x17, 0x2A)

    t3 = doc.add_table(rows=9, cols=3)
    t3.rows[0].cells[0].paragraphs[0].add_run("Layer")
    t3.rows[0].cells[1].paragraphs[0].add_run("Technology")
    t3.rows[0].cells[2].paragraphs[0].add_run("Engineering Rationale & Selection Criteria")

    stack_data = [
        ("Backend Core", "Python 3.11+", "High-performance typing, native standard library ast module, zero external parser dependencies for core Python parsing."),
        ("Web API", "FastAPI", "High-throughput asynchronous ASGI engine with native OpenAPI/Swagger generation and dependency-injection security architecture."),
        ("Serialization", "Pydantic v2", "Rust-based validation core (pydantic-core) delivering sub-millisecond serialization across thousands of finding objects."),
        ("Frontend", "Next.js 14 / React", "App Router with Server/Client boundary separation, streaming state for long-running repository AST scans."),
        ("Styling", "Tailwind CSS", "Zero-runtime utility CSS implementing Entropy's obsidian/emerald developer aesthetic without stylesheet bloat."),
        ("CI/CD Output", "OASIS SARIF 2.1.0", "Universal standard for static analysis interoperability, rendering natively inside GitHub Code Scanning tabs."),
        ("Advisory AI", "Google Gemini", "Large context window for whole-file architectural comprehension and generating grounded remediation diffs."),
        ("Video Engine", "Hyperframes & FFmpeg", "Deterministic headless browser video composition (30fps) with local H.264 muxing and frame-0 poster baking.")
    ]

    for idx, (c1, c2, c3) in enumerate(stack_data, start=1):
        t3.rows[idx].cells[0].paragraphs[0].add_run(c1)
        t3.rows[idx].cells[1].paragraphs[0].add_run(c2)
        t3.rows[idx].cells[2].paragraphs[0].add_run(c3)
    format_table(t3, [1.5, 1.8, 3.7])

    # Section 7: Constitution Rules
    h7 = doc.add_heading("7. The 10 Inviolable Engineering Rules", level=1)
    h7.paragraph_format.space_before = Pt(16)
    h7.paragraph_format.space_after = Pt(4)
    h7.runs[0].font.color.rgb = RGBColor(0x0F, 0x17, 0x2A)

    const_rules = [
        "No Mock Security Findings: Every finding must originate from real AST syntax in scanned source files.",
        "No Fake Scan Results: Never return canned responses. An empty codebase produces zero findings.",
        "No Hardcoded Dashboard Metrics: Every number, percentage, and badge must be computed by the backend engine.",
        "No Pretending an Analyzer Exists: If an analyzer is not implemented, its status is transparently marked NOT_ANALYZED.",
        "Backend is the Source of Truth: The frontend is strictly a presentation tier and never computes or alters debt scores.",
        "Every Score Must Be Explainable: The engine generates a step-by-step mathematical audit trail detailing raw penalties and weights.",
        "Prefer Deterministic Static Analysis Over LLM Guesses: Static syntax inspection produces findings; LLMs do not invent them.",
        "AI Explains Findings, Not Invents Them: AI synthesizes rationale and refactor suggestions strictly grounded in AST findings.",
        "Fail Gracefully on Parse Errors: When a file contains syntax errors, record a non-fatal warning and continue scanning.",
        "Preserve Exact Source Locations: Every finding must capture exact file paths, line ranges, and surrounding verbatim code snippets."
    ]

    for idx, rule in enumerate(const_rules, start=1):
        rp = doc.add_paragraph()
        rp.paragraph_format.space_before = Pt(3)
        rp.paragraph_format.space_after = Pt(2)
        rp.paragraph_format.line_spacing = 1.1
        r_num = rp.add_run(f"{idx}. ")
        r_num.bold = True
        r_num.font.color.rgb = RGBColor(0x05, 0x96, 0x69)
        r_text = rp.add_run(rule)
        r_text.font.color.rgb = RGBColor(0x1F, 0x29, 0x37)

    # Save
    doc.save(output_path)
    print(f"Document saved successfully to {output_path}")

if __name__ == "__main__":
    import sys
    out = sys.argv[1] if len(sys.argv) > 1 else "Entropy_Architecture_and_Deep_Dive.docx"
    build_document(out)
