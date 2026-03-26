#!/bin/bash
# Copyright (c) Privasys. All rights reserved.
# Licensed under the GNU Affero General Public License v3.0.
#
# Build the RA-TLS mobile FFI library for Android targets.
# Requires Android NDK installed and ANDROID_NDK_HOME set.
#
# Usage:
#   ./scripts/build-android.sh [release|debug]
#
# Output:
#   target/android/jniLibs/arm64-v8a/libratls_mobile.so
#   target/android/jniLibs/x86_64/libratls_mobile.so

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRATE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
PROFILE="${1:-release}"

# Android targets and their ABI names
declare -A TARGETS=(
    ["aarch64-linux-android"]="arm64-v8a"
    ["x86_64-linux-android"]="x86_64"
)

echo "=== Building ratls-mobile for Android ($PROFILE) ==="
echo "Crate: $CRATE_DIR"

# Check NDK
if [ -z "${ANDROID_NDK_HOME:-}" ]; then
    # Try common locations
    for candidate in \
        "$HOME/Library/Android/sdk/ndk"/* \
        "$HOME/Android/Sdk/ndk"/* \
        "/usr/local/lib/android/sdk/ndk"/*; do
        if [ -d "$candidate" ]; then
            export ANDROID_NDK_HOME="$candidate"
            break
        fi
    done
fi

if [ -z "${ANDROID_NDK_HOME:-}" ]; then
    echo "ERROR: ANDROID_NDK_HOME not set and NDK not found"
    echo "Install via: sdkmanager --install 'ndk;27.2.12479018'"
    exit 1
fi

echo "NDK: $ANDROID_NDK_HOME"

# Determine NDK toolchain
HOST_TAG="$(uname -s | tr '[:upper:]' '[:lower:]')-$(uname -m)"
if [ "$HOST_TAG" = "darwin-arm64" ]; then
    HOST_TAG="darwin-x86_64"  # NDK uses x86_64 even on ARM mac
fi
TOOLCHAIN="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/$HOST_TAG"

# Minimum API level
API_LEVEL=24

# Ensure targets are installed
for target in "${!TARGETS[@]}"; do
    rustup target add "$target" 2>/dev/null || true
done

BUILD_FLAG=""
PROFILE_DIR="$PROFILE"
if [ "$PROFILE" = "release" ]; then
    BUILD_FLAG="--release"
fi
if [ "$PROFILE" = "debug" ]; then
    PROFILE_DIR="debug"
fi

# Build each target
for target in "${!TARGETS[@]}"; do
    abi="${TARGETS[$target]}"
    echo "--- Building for $target (ABI: $abi) ---"

    # Set linker for this target
    case "$target" in
        aarch64-linux-android)
            export CC_aarch64_linux_android="$TOOLCHAIN/bin/aarch64-linux-android${API_LEVEL}-clang"
            export AR_aarch64_linux_android="$TOOLCHAIN/bin/llvm-ar"
            export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$CC_aarch64_linux_android"
            ;;
        x86_64-linux-android)
            export CC_x86_64_linux_android="$TOOLCHAIN/bin/x86_64-linux-android${API_LEVEL}-clang"
            export AR_x86_64_linux_android="$TOOLCHAIN/bin/llvm-ar"
            export CARGO_TARGET_X86_64_LINUX_ANDROID_LINKER="$CC_x86_64_linux_android"
            ;;
    esac

    cargo build $BUILD_FLAG --target "$target" --manifest-path "$CRATE_DIR/Cargo.toml"
done

# Copy outputs to jniLibs structure
OUT_DIR="$CRATE_DIR/target/android/jniLibs"
for target in "${!TARGETS[@]}"; do
    abi="${TARGETS[$target]}"
    mkdir -p "$OUT_DIR/$abi"
    cp "$CRATE_DIR/target/$target/$PROFILE_DIR/libratls_mobile.so" "$OUT_DIR/$abi/"
    echo "  → $OUT_DIR/$abi/libratls_mobile.so"
done

echo "=== Android build complete ==="
echo "Copy $OUT_DIR to your Expo module's android/src/main/jniLibs/"
