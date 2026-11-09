#!/bin/sh
# Linux-only: strip the ABI-tag note from system Qt ELF libraries.
# No-op on macOS (Mach-O) and when the files are absent.
if [ "$(uname -s)" != "Linux" ]; then
    echo "fixQt: not Linux, skipping."
    exit 0
fi
for f in /usr/local/lib/python3.8/dist-packages/PyQt6/Qt6/lib/libQt6Core.so.6 \
         /usr/lib/x86_64-linux-gnu/libQt5Core.so.5; do
    if [ -f "$f" ]; then
        strip --remove-section=.note.ABI-tag "$f" || true
    fi
done
