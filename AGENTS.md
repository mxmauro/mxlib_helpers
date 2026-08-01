# MXCommonLibrariesHelpers Contributor Guide

## Repository layout

- Root-level `.h` and `.cpp` files are the first-party helper library sources.
- `MXCommonLibrariesHelpers.sln` and `MXCommonLibrariesHelpers.vcxproj` define Debug/Release Win32 and x64 Visual Studio builds.
- Treat `lib/`, `obj/`, `.vs/`, generated outputs, and binaries as non-source artifacts. Confirm ownership before editing any future imported dependency.

## Working rules

- Check `git status --short` before editing and preserve already-dirty files.
- Make the smallest behavior-preserving change. Do not mix bug fixes, dependency upgrades, or identifier renames into formatting work.
- Use `.editorconfig`: C/C++ sources and headers use four spaces, CRLF, and Latin-1; Visual Studio project files use tabs, CRLF, and UTF-8 BOM.
- Use Allman braces for functions, classes, namespaces, and every control-flow body, including a single statement. Retain the established same-line form for C-style `struct` and `enum` declarations.
- Keep comments concise and purposeful. Use sentence case for prose while preserving identifiers, acronyms, URLs, and protocol names.
- Use the established Hungarian naming convention for variables. Preserve semantic prefixes, such as `cStr` for `CStringW`/`CStringA` values; do not rename existing identifiers for style alone.
- Preserve include order and API qualifiers such as `extern "C"`, `noexcept`, `final`, packed layouts, bitfields, and deleted operations unless required by the task.

## Validation

- Review diffs for unrelated user changes and unnecessary whitespace churn.
- Build the relevant solution/project configuration and run focused tests when the local toolchain and dependencies permit it.
- Report pre-existing build failures or unavailable local dependencies separately.
