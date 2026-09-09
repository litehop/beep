#!/usr/bin/env bash
# Shared by scripts/test-check-bead-id-refs-logic.sh and
# scripts/test-check-doc-budget-logic.sh's sandbox-repo git helpers.
# Internal (underscore-prefixed, same convention as
# scripts/conformance/_lib.sh): source this, don't run it directly.
#
# GIT_* variables that redirect git's chosen repository/working-tree/index/
# object-store/config location if inherited from an enclosing process. Both
# test suites above run their sandbox-repo helpers (`git init`/`git
# config`/`git commit` against disposable fixture dirs) from inside
# .githooks/pre-commit and .githooks/pre-push respectively -- exactly the
# ambient environment whose GIT_DIR/GIT_CONFIG leakage already corrupted the
# mayor's real repository twice (a sandbox fixture's `git init`/`git commit`
# inherited the enclosing hook's ambient var and landed in the real repo
# instead of a disposable sandbox). Every git subprocess the sandbox-repo
# helpers spawn MUST go through run_git() to strip these first, or the
# sandbox dir this whole test's safety story depends on could be silently
# ignored in favor of whatever the enclosing hook invocation's environment
# happens to point at.
#
# Also sourced by other sandbox-repo test harnesses under scripts/ --
# test-check-bead-id-refs-logic.sh and test-check-doc-budget-logic.sh. The
# per-variable rationale (including why HOME/XDG_CONFIG_HOME are deliberately
# NOT in the strip list) is inline at the stripping call below.
run_git() {
  env -u GIT_DIR -u GIT_WORK_TREE -u GIT_NAMESPACE -u GIT_INDEX_FILE \
    -u GIT_OBJECT_DIRECTORY -u GIT_ALTERNATE_OBJECT_DIRECTORIES \
    -u GIT_COMMON_DIR -u GIT_CEILING_DIRECTORIES \
    -u GIT_DISCOVERY_ACROSS_FILESYSTEM \
    -u GIT_CONFIG -u GIT_CONFIG_GLOBAL -u GIT_CONFIG_SYSTEM \
    -u GIT_CONFIG_NOSYSTEM -u GIT_CONFIG_COUNT \
    git "$@"
}
