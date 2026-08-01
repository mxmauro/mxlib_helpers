---
name: mxcommonlibrarieshelpers-maintenance
description: Safely maintain the MXCommonLibrariesHelpers Visual Studio C++ helper-library solution. Use when changing its first-party root-level sources, headers, project files, or repository guidance, especially when preserving existing working-tree changes.
---

# MXCommonLibrariesHelpers maintenance

## Establish scope

1. Read `AGENTS.md`, `.editorconfig`, and `git status --short` before editing.
2. Treat root-level `.cpp` and `.h` files as first-party source. Do not edit `lib/`, `obj/`, `.vs/`, binaries, or generated outputs.
3. Preserve files that were dirty before the task unless the user explicitly includes them.

## Make and validate changes

1. Preserve the existing C/C++ API surface and Visual Studio configuration unless the task requires a change.
2. Follow `.editorconfig`, Allman braces, concise sentence-case comments, and the Hungarian naming convention.
3. Preserve semantic variable prefixes, including `cStr` for CString values; do not rename identifiers for style alone.
4. Review the diff before finishing and build the relevant Debug or Release Win32/x64 configuration when practical.
