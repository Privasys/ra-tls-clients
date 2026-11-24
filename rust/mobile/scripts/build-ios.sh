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

# The oldest iOS the library runs on. Without it the C and assembly a crate
# compiles (ring's arithmetic) take the SDK's own version, and an app that
# supports an older iOS links objects built for a newer one. Set it to the
# lowest deployment target of the apps that link the library.
export IPHONEOS_DEPLOYMENT_TARGET="${IPHONEOS_DEPLOYMENT_TARGET:-16.0}"

echo "=== Building ratls-mobile for iOS ($PROFILE), iOS $IPHONEOS_DEPLOYMENT_TARGET and later ==="
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

# Create output directory (clean any stale xcframework from cache)
OUT_DIR="$CRATE_DIR/target/ios"
rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR"

PROFILE_DIR="$PROFILE"
if [ "$PROFILE" = "debug" ]; then
    PROFILE_DIR="debug"
fi

# Create universal binary with lipo
DEVICE_LIB="$CRATE_DIR/target/aarch64-apple-ios/$PROFILE_DIR/libratls_mobile.a"
SIM_LIB="$CRATE_DIR/target/aarch64-apple-ios-sim/$PROFILE_DIR/libratls_mobile.a"

# No object in either library may ask for a newer iOS than the deployment
# target: the linker only warns, and the app would then fail on an older
# iPhone where that object is first used.
for lib in "$DEVICE_LIB" "$SIM_LIB"; do
    [ -f "$lib" ] || continue
    newest=$(xcrun vtool -show-build "$lib" 2>/dev/null | awk '$1 == "minos" || $1 == "version" { print $2 }' | sort -V | tail -1)
    if [ -z "$newest" ]; then
        echo "ERROR: could not read the minimum iOS of the objects in $lib" >&2
        exit 1
    fi
    if [ "$(printf '%s\n%s\n' "$newest" "$IPHONEOS_DEPLOYMENT_TARGET" | sort -V | tail -1)" != "$IPHONEOS_DEPLOYMENT_TARGET" ]; then
        echo "ERROR: $lib has objects built for iOS $newest, newer than $IPHONEOS_DEPLOYMENT_TARGET:" >&2
        xcrun vtool -show-build "$lib" 2>/dev/null | grep -B8 -E "^ *(minos|version) $newest" | grep -E "\.a\(|minos|version" >&2 || true
        exit 1
    fi
    echo "--- $(basename "$(dirname "$(dirname "$lib")")"): no object needs more than iOS $newest ---"
done

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
