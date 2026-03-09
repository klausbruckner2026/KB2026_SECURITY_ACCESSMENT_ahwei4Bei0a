#!/usr/bin/env bash
# =============================================================================
# Installation script for simple_regex_scan
# Installs dependencies and creates a symlink in /usr/local/bin
# =============================================================================

set -euo pipefail
#     │   │     └─ treat unset variables as error
#     │   └────── exit on error (non-zero exit code)
#     └────────── prevent errors in pipelines from being masked

# ──────────────────────────────────────────────────────────────────────────────
#  Helper functions
# ──────────────────────────────────────────────────────────────────────────────

die() {
    echo "❌  $*" >&2
    exit 1
}

info() {
    echo "ℹ️  $*"
}

success() {
    echo "✅  $*"
}

# ──────────────────────────────────────────────────────────────────────────────
#  Find best available Python pip
# ──────────────────────────────────────────────────────────────────────────────

find_pip() {
    local candidates=(
        "pip3"
        "pip"
        "python3 -m pip"
        "python -m pip"
    )

    for cmd in "${candidates[@]}"; do
        if command -v ${cmd%% *} &>/dev/null; then
            # Test if it actually works
            if $cmd --version &>/dev/null; then
                echo "$cmd"
                return 0
            fi
        fi
    done

    return 1
}

# ──────────────────────────────────────────────────────────────────────────────
#  Main logic
# ──────────────────────────────────────────────────────────────────────────────

main() {
    local pip_cmd

    # Check we're in the right directory (has requirements.txt)
    [[ -f requirements.txt ]] || die "requirements.txt not found in current directory"

    # Check we have the python script
    [[ -f simple_regex_scan.py ]] || die "simple_regex_scan.py not found in current directory"

    info "Looking for a working pip command..."

    pip_cmd=$(find_pip) || die "Could not find a working pip or python -m pip"

    info "Using: $pip_cmd"

    # Install dependencies
    info "Installing dependencies..."
    if ! $pip_cmd install --user -r requirements.txt; then
        die "Failed to install dependencies"
    fi

    success "Dependencies installed"

    # Create symlink
    local target="/usr/local/bin/simple_regex_scan"
    local source="$(pwd)/simple_regex_scan.py"

    info "Creating symlink: $target → $source"

    if [[ -e "$target" && ! -L "$target" ]]; then
        die "Path $target already exists and is not a symlink"
    fi

    # Remove old symlink if it exists
    [[ -L "$target" ]] && rm -f "$target"

    # Try to create symlink - may need sudo
    if ln -sf "$source" "$target" 2>/dev/null; then
        success "Symlink created successfully"
    else
        info "Permission denied → trying with sudo..."
        if sudo ln -sf "$source" "$target"; then
            success "Symlink created with sudo"
        else
            die "Failed to create symlink in /usr/local/bin"
        fi
    fi

    # Final check
    if command -v simple_regex_scan &>/dev/null; then
        success "Installation complete!"
        echo ""
        echo "You can now run:"
        echo "    simple_regex_scan --help"
    else
        info "Installation finished, but command not found in PATH."
        echo "Make sure /usr/local/bin is in your PATH."
    fi
}

# ──────────────────────────────────────────────────────────────────────────────

main "$@"