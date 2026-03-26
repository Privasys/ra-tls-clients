#!/bin/bash
# Copyright (c) Privasys. All rights reserved.
# Licensed under the GNU Affero General Public License v3.0.
#
# Build the RA-TLS mobile FFI library for iOS targets.
# Run this on macOS with Xcode and Rust installed.
#
# Usage:
#   ./scripts/build-ios.sh [release|debug]
#
# Output:
#   target/ios/libratls_mobile.a  (universal static library)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRATE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
PROFILE="${1:-release}"

# iOS targets
TARGETS=(
    "aarch64-apple-ios"           # Physical devices (arm64)
    "aarch64-apple-ios-sim"       # Simulator on Apple Silicon
)

echo "=== Building ratls-mobile for iOS ($PROFILE) ==="
echo "Crate: $CRATE_DIR"

# Ensure targets are installed
for target in "${TARGETS[@]}"; do
    rustup target add "$target" 2>/dev/null || true
done

# Build each target
BUILD_FLAG=""
if [ "$PROFILE" = "release" ]; then
    BUILD_FLAG="--release"
fi

for target in "${TARGETS[@]}"; do
    echo "--- Building for $target ---"
    cargo build $BUILD_FLAG --target "$target" --manifest-path "$CRATE_DIR/Cargo.toml"
done

# Create output directory
OUT_DIR="$CRATE_DIR/target/ios"
mkdir -p "$OUT_DIR"

PROFILE_DIR="$PROFILE"
if [ "$PROFILE" = "debug" ]; then
    PROFILE_DIR="debug"
fi

# Create universal binary with lipo
DEVICE_LIB="$CRATE_DIR/target/aarch64-apple-ios/$PROFILE_DIR/libratls_mobile.a"
SIM_LIB="$CRATE_DIR/target/aarch64-apple-ios-sim/$PROFILE_DIR/libratls_mobile.a"

if [ -f "$DEVICE_LIB" ] && [ -f "$SIM_LIB" ]; then
    # Create an XCFramework for proper simulator + device support
    xcodebuild -create-xcframework \
        -library "$DEVICE_LIB" -headers "$CRATE_DIR/include" \
        -library "$SIM_LIB" -headers "$CRATE_DIR/include" \
        -output "$OUT_DIR/RaTlsMobile.xcframework"
    echo "=== XCFramework: $OUT_DIR/RaTlsMobile.xcframework ==="
else
    # Fallback: just copy the device lib
    cp "$DEVICE_LIB" "$OUT_DIR/libratls_mobile.a"
    echo "=== Static library: $OUT_DIR/libratls_mobile.a ==="
fi

echo "=== iOS build complete ==="
