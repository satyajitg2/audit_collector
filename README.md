# audit_collector
Collect MacOS Audit Events
http://localhost:9357/


Debian (.deb):
    Configured in Cargo.toml.
    Build command: make package-deb (requires cargo-deb).

Windows MSI (.msi):
    Created wix/main.wxs template.
    Build command: make package-msi (requires cargo-wix and Windows/WiX Toolset).
