.PHONY: all clean build build-release package-deb package-msi install-tools

all: build

clean:
	cargo clean

build:
	cargo build

build-release:
	cargo build --release

# --- Debian Packaging ---
# Requires: cargo-deb (cargo install cargo-deb)
#           dpkg (brew install dpkg on macOS, or apt-get install dpkg on Linux)
package-deb: build-release
	@if ! command -v cargo-deb > /dev/null; then \
		echo "Error: cargo-deb not found. Run 'make install-tools' or 'cargo install cargo-deb'"; \
		exit 1; \
	fi
	cargo deb

# --- Windows MSI Packaging ---
# Requires: cargo-wix (cargo install cargo-wix)
#           WiX Toolset (Windows only)
# On non-Windows systems, this target will just verify the configuration or attempt a cross-compile 
# if a toolchain is present, but usually fails without WiX.
package-msi: build-release
	@if ! command -v cargo-wix > /dev/null; then \
		echo "Error: cargo-wix not found. Run 'make install-tools' or 'cargo install cargo-wix'"; \
		exit 1; \
	fi
	cargo wix

# Install helper tools
install-tools:
	cargo install cargo-deb
	cargo install cargo-wix

# Verify configuration (Dry run)
verify-packaging:
	@echo "Verifying Debian config..."
	cargo deb --no-build --dry-run
	@echo "Verifying WiX config presence..."
	ls wix/main.wxs
