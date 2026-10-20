# Hyperframes Composition Brief: Entropy

## Objective
Create a short, polished, shareable launch video for Entropy, the Architectural Security Debt Analyzer for AI-assisted codebases.

## Output
- Composition directory: `brag-output/composition/`
- Rendered video: `brag-output/brag.mp4`
- Format: landscape — 1920x1080 (30fps)
- Duration: 20 seconds

## Source Material
- Project root: `/home/naveen/Entropy`
- Primary files read: `README.md`, `frontend/app/page.tsx`, `frontend/components/dashboard/ScoreBanner.tsx`, `frontend/components/dashboard/CategoryMatrix.tsx`, `frontend/components/findings/FindingsViewer.tsx`, `frontend/app/constitution/page.tsx`, `frontend/tailwind.config.ts`, `frontend/app/globals.css`
- Product name: Entropy
- Tagline / strongest claim: "The Entropy Score is an indicator of architectural and security debt detected by Entropy's static-analysis rules. It does not measure AI authorship."
- Key UI moments to recreate:
  1. CLI terminal execution (`entropy scan .` with discovered files and LOC)
  2. Flagship Debt Score Banner (Score `28 / 100`, `LOW DEBT`, progress gauge)
  3. Category Breakdown Matrix (Authentication Consistency, Error Handling, Input Validation, Logging & Secrets)
  4. Verbatim AST code evidence finding with syntax highlights
  5. The Non-Attribution Covenant from the Constitution
- Copy that must appear verbatim:
  - "Stop guessing if AI wrote the code."
  - "Analyze the architectural security debt it leaves behind."
  - "The Non-Attribution Covenant"
  - "Zero mock findings. Pure deterministic AST analysis."

## Creative Direction
- Tone preset: `polished`
- Creative direction: Precision developer tool launch
- Interpretation: Deep dark obsidian backdrop, sharp neon emerald accents, confident typography, authoritative claims, and rhythmic audio sync.
- Angle: A sharp refutation of superficial "AI detectors"—Entropy delivers grounded, AST-verified security debt analysis with zero hallucinated author attributions.
- Hook (0-4.5s): Terminal scan pulse and bold question.
- Outro (15.5-20s): The Non-Attribution Covenant and open-source GitHub callout.
- Avoid: Generic SaaS jargon, cartoonish graphics, abstract waveform equalizers.

## Visual Identity
- Background: `#090d16`
- Card background: `#0f172a`
- Border: `#1e293b`
- Text: `#f8fafc`
- Accent / Emerald: `#10b981`
- Cyan: `#06b6d4`
- Amber: `#f59e0b`
- Red: `#ef4444`
- Display font: `-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif`
- Monospace font: `ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace`

## Storyboard
1. Scene 1 — The Terminal Ingestion & Hook (0.0s – 4.5s) — 4.5s duration
2. Scene 2 — The Entropy Debt Score (4.5s – 9.5s) — 5.0s duration
3. Scene 3 — Architectural Matrix & AST Evidence (9.5s – 15.5s) — 6.0s duration
4. Scene 4 — The Non-Attribution Covenant & Outro (15.5s – 20.0s) — 4.5s duration

## Audio
- Audio role: Polished electronic synth bed with crisp motion-matched UI accents
- Music: `happy-beats-business-moves-vol-9-by-ende-dot-app.mp3`
- Music treatment: Starts at 0s, volume 0.75, fades smoothly out from 18.5s to 20.0s
- Music cue guidance: Tempo ~114.84 BPM. Key strong cues: 4.23s, 6.34s, 8.44s, 10.54s, 12.65s, 16.34s, 20.02s
- Audio-reactive treatment: Subtle breathing glow on the score card and backdrop
- Audio-coupled moments:
  - t=0.4s: Keyboard click on command entry
  - t=1.8s: Digital sweep on scan completion
  - t=6.34s: Strong cue lock on score counter settling at 28
  - t=10.54s, t=11.06s: Crisp UI switch on category card entries
  - t=16.34s: Subtle impact on the Covenant shield badge
- SFX files: local files in `assets/sfx/`

## Hyperframes Instructions
- Composition directory: `brag-output/composition/`
- Render: `brag.mp4` (1920x1080)
- Single gate: `hyperframes check` must pass with 0 errors
- Use local assets for GSAP and audio
- Keep all text readable with proper settled holds
