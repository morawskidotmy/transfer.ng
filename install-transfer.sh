#!/bin/bash
set -e

REPO="https://github.com/morawskidotmy/transfer.ng"
BINARY_NAME="transfer"
INSTALL_DIR="${HOME}/.local/bin"

echo "Installing transfer CLI..."

# Create install directory if it doesn't exist
mkdir -p "${INSTALL_DIR}"

# Create temporary directory for build
TMPDIR=$(mktemp -d)
trap "rm -rf ${TMPDIR}" EXIT

echo "Downloading source code..."
cd "${TMPDIR}"
if ! git clone --depth 1 "${REPO}" . > /dev/null 2>&1; then
    echo "Error: Failed to clone repository"
    echo "Make sure you have git installed and the repository is accessible"
    exit 1
fi

# Check if cmd/transfer exists
if [ ! -d "cmd/transfer" ]; then
    echo "Error: cmd/transfer directory not found in repository"
    echo "The transfer CLI may not be available in this version"
    exit 1
fi

echo "Building binary..."
if ! go build -o "${BINARY_NAME}" ./cmd/transfer; then
    echo "Error: Failed to build binary"
    echo "Make sure you have Go installed (https://golang.org/dl/)"
    exit 1
fi

echo "Installing to ${INSTALL_DIR}/${BINARY_NAME}..."
mv "${BINARY_NAME}" "${INSTALL_DIR}/${BINARY_NAME}"
chmod +x "${INSTALL_DIR}/${BINARY_NAME}"

# Check if INSTALL_DIR is in PATH
if [[ ":${PATH}:" != *":${INSTALL_DIR}:"* ]]; then
    echo "Adding ${INSTALL_DIR} to PATH..."
    
    # Detect shell and config file
    if [ -n "${ZSH_VERSION}" ]; then
        SHELL_CONFIG="${HOME}/.zshrc"
        SHELL_TYPE="zsh"
    elif [ -n "${BASH_VERSION}" ]; then
        SHELL_CONFIG="${HOME}/.bashrc"
        SHELL_TYPE="bash"
    else
        SHELL_CONFIG="${HOME}/.profile"
        SHELL_TYPE="sh"
    fi
    
    # Add to shell config if not already there
    if ! grep -q "${INSTALL_DIR}" "${SHELL_CONFIG}" 2>/dev/null; then
        echo "" >> "${SHELL_CONFIG}"
        echo "# Added by transfer installer" >> "${SHELL_CONFIG}"
        echo "export PATH=\"${INSTALL_DIR}:\${PATH}\"" >> "${SHELL_CONFIG}"
        echo "Added ${INSTALL_DIR} to PATH in ${SHELL_CONFIG}"
    fi
    
    echo ""
    echo "Please restart your shell or run:"
    echo "  source ${SHELL_CONFIG}"
fi

echo ""
echo "✓ Installation complete!"
echo ""
echo "Usage:"
echo "  transfer file.txt"
echo "  transfer file1.txt file2.txt"
echo "  transfer myfolder/"
echo ""
echo "For more options, run: transfer"
