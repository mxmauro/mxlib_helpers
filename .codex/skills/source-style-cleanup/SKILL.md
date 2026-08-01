---
name: source-style-cleanup
description: Reformat and edit comments in first-party MXCommonLibrariesHelpers source without changing behavior. Use for requested readability, brace-style, whitespace, line-ending, encoding, or concise comment cleanup across the helper library’s C++ sources and headers.
---

# Source style cleanup

## Select files safely

1. Read `AGENTS.md`, `.editorconfig`, and `git status --short`.
2. Include only clean root-level first-party `.cpp` and `.h` files. Exclude project files that were already dirty, generated outputs, and binaries.

## Apply the cleanup

1. Enforce `.editorconfig` indentation, encoding, line endings, trailing-whitespace, and final-newline rules.
2. Use four-space, Allman-style C++ formatting. Add braces to every control-flow body, including single-statement `if`, `else`, loops, and `do` bodies.
3. Keep behavior, macro structure, includes, identifiers, and public declarations unchanged.
4. Preserve Hungarian variable names and semantic prefixes such as `cStr` for CString values; do not rename identifiers during style-only work.
5. Edit prose comments for clarity and sentence case. Preserve technical terms and keep normal comments to one or two lines when practical.

## Verify

1. Inspect the diff for accidental user-change or artifact edits.
2. Check C++ files for remaining unbraced control-flow bodies and malformed line endings or encodings.
3. Build and run focused tests when the local configuration permits it.
