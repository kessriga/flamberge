# flamberge — Project Guide

Standalone Rust CLI that reimplements the **DeDRM_tools** Calibre plugins (ebook DRM removal).

## Sources of truth
- `docs/DEDRM_SCHEMES.md` — **the spec.** Byte-level reference for every scheme (offsets, constants, key derivation). **Read the relevant section before implementing any scheme.** Sections: §1 crypto, §2 Mobipocket, §3 KFX/ION, §4 B&N, §5 Topaz, §6 Kindle keys, §7 Adobe ADEPT, §8 eReader, §9 Kobo, §10 Rust guidance.
- `../../external/DeDRM_tools/DeDRM_plugin/` — the original Python source the spec was derived from; consult it when the spec is ambiguous.

## Working conventions
- Tasks live in **Backlog.md** (`backlog/tasks/`), not a Clavix `tasks.md`. Per task: mark In Progress, record a plan in the task, implement with tests, verify build/test/clippy/fmt, mark Done with a final summary.
- **When finishing a task, update this CLAUDE.md too** if the completed work changed anything documented here (e.g. the Status section, conventions, or gotchas). Skip only when there is genuinely nothing to update.
- **Commits: atomic and reasonably short** — one logical change per commit, your judgment on boundaries. Keep unrelated cleanups (e.g. lint fixes) in their own commits.
- **One branch per task**, cut from `main` (e.g. `feat/task-4-topaz`); never commit to `main` directly. `main` is protected — integrate via PR only, with CI green and commits signed. Commit signing (SSH) is configured globally, so commits sign automatically.
  - **Before starting a task:** switch to `main`, pull, then create and switch to the task branch.
  - **After the task is done, before opening the PR:** pull `main` and rebase the task branch onto it.

## Layout & commands
- Cargo workspace under `crates/`; dependency direction: `flamberge-crypto` ← `flamberge-formats`, `flamberge-keys` ← `flamberge-schemes` ← `flamberge-cli` (binary name `flamberge`).
- `cargo build` / `cargo test` from repo root. Unit tests are colocated in each module; every cipher has a round-trip test.
- CI (`.github/workflows/ci.yml`) gates every PR: `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, and build+test on Linux/macOS/Windows. Run `cargo fmt` before committing — warnings and unformatted code fail the merge.
- Errors: `thiserror` in libs, `anyhow` in the CLI. Never `panic!`/`unwrap` on a real code path.

## Status (what's real vs stub)
- **Real + tested:** all of `flamberge-crypto` (PC1, Topaz, AES CBC/ECB/CTR, DES, RC4, CRC-32, PBKDF2, PKCS#7); `flamberge-formats::palmdb`, `mobi` + `topaz_container` (TPZ0 header/payload/metadata parsing) + `ion` (Amazon ION binary pull parser: VarUInt/VarInt, type descriptors, list/struct navigation, symbol table with the `ProtectedData` shared import, annotation resolution); `flamberge-keys` offline generators (`pid`, `ignoble`, `ereader`, `kobo::derive_userkeys`); the **Mobipocket and Topaz schemes end-to-end** (`flamberge-schemes::mobipocket`, `flamberge-schemes::topaz`, wired through the CLI). Topaz emits a repackaged decrypted `TPZ0` (extension `tpz`); HTML/SVG rendering (§5.5–5.6) is out of scope.
- **Stubbed** (return `Unimplemented`, doc-comment points at a spec §): all `flamberge-schemes` decrypt bodies *except mobipocket and topaz*, the remaining `flamberge-formats` containers (`kfx_zip`, `ocf`, `pdf`), and platform key-extraction (`kindle`, `adobe`, `kobo::discover_userkeys`).
- **Next vertical slice:** KFX/ION (§3) — the ION parser (`flamberge-formats::ion`) is done (TASK-6); next is KFX voucher unwrap + content decryption (TASK-7, §3.3–3.4), then the `kfx_zip` container to feed it.

## Implementation gotchas (from the analysis)
- PC1 and Topaz require **wrapping u32 arithmetic** — the tested ports live in `flamberge-crypto`; reuse them, don't reinvent.
- ADEPT/B&N book keys are the **last 16 bytes** after PKCS#7 strip, not the first.
- ADEPT/B&N EPUB per-file decrypt **drops the first 16 bytes** (prepended IV block) before unpad + raw-inflate (windowBits −15).
- Topaz "encrypted" flag = the **sign of the record index** (negative), not a header field.
- All MOBI/PalmDB/ION/PDB integers are **big-endian**; treat every "string" as bytes.
- AES is **no-padding** everywhere; callers strip PKCS#7 themselves (`kdf::pkcs7_unpad`).
- Windows DPAPI paths (`.kinf2011` v5, Adobe `privateLicenseKey`) are **not reproducible offline** — they need the user's Windows profile.
- Scheme dispatch: by file extension, then Kindle-family magic bytes. A handler returns `SchemeError::NotThisScheme` to fall through to the next candidate.

<!-- CLAVIX:START -->
## Clavix Integration

This project uses Clavix for prompt improvement and PRD generation. The following slash commands are available:

> **Command Format:** Commands shown with colon (`:`) format. Some tools use hyphen (`-`): Claude Code uses `/clavix:improve`, Cursor uses `/clavix-improve`. Your tool autocompletes the correct format.

### Prompt Optimization

#### /clavix:improve [prompt]
Optimize prompts with smart depth auto-selection. Clavix analyzes your prompt quality and automatically selects the appropriate depth (standard or comprehensive). Use for all prompt optimization needs.

### PRD & Planning

#### /clavix:prd
Launch the PRD generation workflow. Clavix will guide you through strategic questions and generate both a comprehensive PRD and a quick-reference version optimized for AI consumption.

#### /clavix:plan
Generate an optimized implementation task breakdown from your PRD. Creates a phased task plan with dependencies and priorities.

#### /clavix:implement
Execute tasks or prompts with AI assistance. Auto-detects source: tasks.md (from PRD workflow) or prompts/ (from improve workflow). Supports automatic git commits and progress tracking.

Use `--latest` to implement most recent prompt, `--tasks` to force task mode.

### Session Management

#### /clavix:start
Enter conversational mode for iterative prompt development. Discuss your requirements naturally, and later use `/clavix:summarize` to extract an optimized prompt.

#### /clavix:summarize
Analyze the current conversation and extract key requirements into a structured prompt and mini-PRD.

### Refinement

#### /clavix:refine
Refine existing PRD or prompt through continued discussion. Detects available PRDs and saved prompts, then guides you through updating them with tracked changes.

### Agentic Utilities

These utilities provide structured workflows for common tasks. Invoke them using the slash commands below:

- **Verify** (`/clavix:verify`): Check implementation against PRD requirements. Runs automated validation and generates pass/fail reports.
- **Archive** (`/clavix:archive`): Archive completed work. Moves finished PRDs and outputs to archive for future reference.

**When to use which mode:**
- **Improve mode** (`/clavix:improve`): Smart prompt optimization with auto-depth selection
- **PRD mode** (`/clavix:prd`): Strategic planning with architecture and business impact

**Recommended Workflow:**
1. Start with `/clavix:prd` or `/clavix:start` for complex features
2. Refine requirements with `/clavix:refine` as needed
3. Generate tasks with `/clavix:plan`
4. Implement with `/clavix:implement`
5. Verify with `/clavix:verify`
6. Archive when complete with `/clavix:archive`

**Pro tip**: Start complex features with `/clavix:prd` or `/clavix:start` to ensure clear requirements before implementation.
<!-- CLAVIX:END -->

<!-- BACKLOG.MD MCP GUIDELINES START -->

<CRITICAL_INSTRUCTION>

## BACKLOG WORKFLOW INSTRUCTIONS

This project uses Backlog.md MCP for all task and project management activities.

**CRITICAL GUIDANCE**

- If your client supports MCP resources, read `backlog://workflow/overview` to understand when and how to use Backlog for this project.
- If your client only supports tools or the above request fails, call `backlog.get_backlog_instructions()` to load the tool-oriented overview. Use the `instruction` selector when you need `task-creation`, `task-execution`, or `task-finalization`.

- **First time working here?** Read the overview resource IMMEDIATELY to learn the workflow
- **Already familiar?** You should have the overview cached ("## Backlog.md Overview (MCP)")
- **When to read it**: BEFORE creating tasks, or when you're unsure whether to track work

These guides cover:
- Decision framework for when to create tasks
- Search-first workflow to avoid duplicates
- Links to detailed guides for task creation, execution, and finalization
- MCP tools reference

You MUST read the overview resource to understand the complete workflow. The information is NOT summarized here.

</CRITICAL_INSTRUCTION>

<!-- BACKLOG.MD MCP GUIDELINES END -->
