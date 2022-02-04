#!/bin/sh
set -x
# delete-library.sh
# Remove the build Rust library so it will be rebuilt next time.
#
rm -fv ${DERIVED_FILES_DIR}/libiostest.a
