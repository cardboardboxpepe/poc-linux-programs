#!/usr/bin/env bash

function err() {
    echo -e "[ERR]: $*" >&2
}

# vars
base="$(realpath "$(dirname "$0")")"
work="$base/build"
FPATH="$base/src/flag.txt"
FLAG="$(head -n1 "$FPATH")"

# the name of the final object
prog="cain"

# --- checking the flag ---

# checking that those two vars are valid
if [[ ! -f "$FPATH" ]]; then
    err "Flag file at $FPATH isn't a real file."
    exit 1
fi
if [[ -z "$FLAG" ]]; then
    err "Flag is empty, cannot proceed."
    exit 1
fi

# --- start the building process ---

# logging
echo "Compiling cain"

# -- reset the build directory --
rm -rf "$work/*" && mkdir -p "$work/"

# -- copy everything over to the build directory --
if ! cp -af -t "$work" "$base/src/."; then
    echo "Failed to copy files to build dir" >&2
    exit 1
fi
echo "populated the build dir"

# -- base64 encoding stuff --

# xor and b64encode the flag
if ! python helper.py --write-base64 -f "$FPATH" -o "$work/flag.enc"; then
    err "Failure to encrypt the flag using the xor cipher"
    exit 1
fi
EFLAG="$(head -n1 "$work/flag.enc" | tr -d '\n\r\f')"

b64encode() {
    printf '%s' "$1" | base64 -w0
}

# replacing strings in cain
echo "replacing strings in cain.h"
sed -i "$work/cain.h" -e "s!{{ ABEL_FILE_NAME }}!$(b64encode '/tmp/libabel.so')!g"
sed -i "$work/cain.h" -e "s!{{ ABEL_MAIN_FUNC }}!$(b64encode 'check')!g"
sed -i "$work/cain.h" -e "s!{{ ABEL_DLOPEN }}!$(b64encode '/proc/self/fd/%d')!g"

# replacing strings in abel
echo "replacing strings in abel.h"
sed -i "$work/abel.h" -e "s!{{ FLAG }}!$EFLAG!g"
sed -i "$work/abel.h" -e "s!{{ FLAG_OK }}!$(b64encode 'you got it!')!g"
sed -i "$work/abel.h" -e "s!{{ FLAG_FAIL }}!$(b64encode 'nope >:(')!g"

# -- actually build the binary --

cd "$work" || exit 1
make clean
if ! make; then
    err "Failed to build the binary, aborting"
    exit 1
fi
cd "$base" || exit 1

# copy files to dist
cp -vf "$work/libs/libabel.so" "$base/dist/libabel.so"
cp -vf "$work/cain" "$base/dist/$prog"

# hash binary
sha1sum -b "$base/dist/$prog" | awk -v prog="$prog" "{ print \$1, prog }" >"$base/dist/$(cut -d '.' -f 1 <<<$prog).sha1.sig"

# --- done ---
echo "main build done"

# --- post build steps ---

# checking the sections of the binary
if readelf -S "$base/dist/$prog" | grep -q '.comment'; then
    err "Found the .comment section in the final binary, build failure"
    exit 1
fi
if readelf -S "$base/dist/$prog" | grep -q -Po '.note\.\w*'; then
    err "Found a note section in the final binary, build failure"
    exit 1
fi
if ! readelf -S "$base/dist/$prog" | grep -q -Po 'libabel'; then
    err "Missing section .libabel in the final binary, build failure"
    exit 1
fi
echo "Section checks OK"

if ! readelf -sW "$base/dist/libabel.so" | grep -q "check"; then
    err "Missing main export abel from $base/dist/libabel.so"
    exit 1
fi
echo "Found all main exports"

# -- checks are done --
echo "post build checks are done"
exit 0
