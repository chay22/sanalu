## Retrieval Routing: zvec-grep (MCP & CLI) and tgrep

Choose the evidence source before the retrieval mode.

### Workspace evidence
- The workspace includes the initial root directory and any additional directories attached via `/add-dir`.
- Treat all currently attached directories as valid local evidence sources.
- Whenever querying an attached directory from `/add-dir`, always explicitly pass its absolute path (or `--root /path/to/dir`) to the tool.
- Do not use workspace retrieval for unrelated open-world questions, current external facts, or web content that does not depend on local evidence.

### Retrieval routing & tool selection
1. **Massive Logs, Traces, & Literal Strings (`tgrep`):**
   - Use `tgrep` when scanning massive raw logs, trace dumps, telemetry, timestamps, transaction IDs, or hex error codes.
   - CLI usage: `tgrep "<pattern>" <path>`

2. **Exact Code & Identifier Search (`zvec_grep_rg` / `zg query --rg`):**
   - When an exact symbol, identifier, filename, configuration key, or function name in standard project files is known:
     - Via MCP: Call `zvec_grep_rg` (only fall back to raw `rg` if `zvec_grep_rg` is unavailable).
     - Via CLI: Run `zg query --rg "<pattern>" -g "<glob>"` (add `--root /absolute/path` for `/add-dir` folders).
   - Do not call raw `rg` directly when `zg query --rg` is available.

3. **Semantic & Conceptual Discovery (`zvec_grep_search` / `zg query`):**
   - Use semantic search when wording or location is unknown, or when resolving architecture, causality, relationships, or fuzzy conceptual queries.
     - Via MCP: Call `zvec_grep_search` with the target absolute `root`.
     - Via CLI: Run `zg query "<question>" --human --limit 5` (add `--root /absolute/path` for `/add-dir` folders).
   - Never use `tgrep`, `zg query --rg`, or raw `rg` if semantic understanding is needed.

4. **Mixed Workflows:**
   - For troubleshooting with large logs: first run `tgrep` to isolate the error lines or timestamps, then run `zvec_grep_search` or `zg query` to understand the root cause across related code.

### Freshness and index lifecycle
- Pass a daemon-visible absolute `root` for the active target workspace/added directory on every zvec-grep call.
- Read `freshness` and `background_refresh` from search results without a status preflight.
- If the semantic index is missing or building, fall back to `tgrep` or `zg query --rg` for exact string lookup.
- Creating, rebuilding, or dropping a persistent index requires explicit user authorization; never execute indexing commands silently.

