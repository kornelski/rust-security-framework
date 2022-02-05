#!/bin/bash
set -x
# create-library.sh
# Build the correct Rust target and place
# the resulting library in the build products
#
# The $PATH used by Xcode likely won't contain Cargo, fix that.
# In addition, the $PATH used by XCode has lots of Apple-specific
# developer tools that your Cargo isn't expecting to use, fix that.
# Note: This assumes a default `rustup` setup and default path.
build_path="$HOME/.cargo/bin:/usr/local/bin:/usr/bin:/bin"
#
# Figure out the correct Rust target from the ARCHS and PLATFORM.
# This script expects just one element in ARCHS.
case "$ARCHS" in
	"arm64")	rust_arch="aarch64" ;;
	"x86_64")	rust_arch="x86_64" ;;
	*)			echo "error: unsupported architecture: $ARCHS" ;;
esac
if [[ "$PLATFORM_NAME" == "macosx" ]]; then
	rust_platform="apple-darwin"
else
	rust_platform="apple-ios"
fi
if [[ "$PLATFORM_NAME" == "iphonesimulator" ]]; then
    if [[ "${rust_arch}" == "aarch64" ]]; then
        rust_abi="-sim"
    else
        rust_abi=""
    fi
else
	rust_abi=""
fi
rust_target="${rust_arch}-${rust_platform}${rust_abi}"
#
# Build library in debug or release
build_args=(--manifest-path ../Cargo.toml --target "${rust_target}")
if [[ "$CONFIGURATION" == "Release" ]]; then
	rust_config="release"
	env PATH="${build_path}" cargo build --release "${build_args[@]}"
elif [[ "$CONFIGURATION" == "Debug" ]]; then
	rust_config="debug"
	env PATH="${build_path}" cargo build "${build_args[@]}"
else
    echo "error: Unexpected build configuration: $CONFIGURATION"
fi
#
# Copy the built library to the derived files directory
cp -v "../../target/${rust_target}/${rust_config}/libiostest.a" ${DERIVED_FILES_DIR}
