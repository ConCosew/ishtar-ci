"""Patch the fetched ShengUfs sources for the ishtar dual-boot bring-up.

Two independent, verifiable edits:

1. RootLayout.h looks for the GPT partition literally named "userdata". On a
   dual-boot device that name belongs to Android's /data (sda30); the iOS root
   image lives in "ios_root" (sda31). Change the lookup name so the SHNGROOT
   manifest is read from the right partition. "userdata" and "ios_root" are
   both 8 characters, so the sizeof(wanted) comparison is unchanged.

2. The queueing update adds two weak_import SPI hooks (armcpu_spi_attach /
   armcpu_spi_mask) supplied by an ArmCpu driver that ishtar does not have. A
   static arm64e kernel link still requires the symbols. Remove the interrupt
   setup and keep polling, exactly what the driver does when attach is refused
   ("Bring-up and the panic path always poll").

The script walks the whole workspace because ./unixnu fetch materializes feeds
under out/feeds/<name>-<hash>/ and links them into the build tree. Nothing is
copied, so patching the feed file is sufficient.
"""

import os
import sys

ROOT_NAME = sys.argv[1] if len(sys.argv) > 1 else "ios_root"
assert ROOT_NAME in ("userdata", "ios_root"), ROOT_NAME

# --- 1. GPT partition name -------------------------------------------------
needle = 'static const char wanted[] = "userdata";'
replacement = 'static const char wanted[] = "%s";' % ROOT_NAME
layout_hits = []
for root, dirs, files in os.walk("."):
    if "RootLayout.h" in files:
        path = os.path.join(root, "RootLayout.h")
        text = open(path, encoding="utf-8").read()
        if needle in text:
            open(path, "w", encoding="utf-8").write(text.replace(needle, replacement))
            layout_hits.append(path)
            print("PATCHED", path, "->", ROOT_NAME)
if not layout_hits:
    print("FATAL: no RootLayout.h with the expected declaration was found")
    for root, dirs, files in os.walk("."):
        if "RootLayout.h" in files:
            print("  CANDIDATE", os.path.join(root, "RootLayout.h"))
    raise SystemExit(1)
print("patched", len(layout_hits), "RootLayout.h file(s)")

# --- 2. No ArmCpu SPI driver: keep polling ---------------------------------
externs = (
    'extern "C" IOReturn armcpu_spi_attach (uint32_t, bool, void (*) (void *), void *, uint32_t *, uint64_t *) __attribute__((weak_import));\n'
    'extern "C" IOReturn armcpu_spi_mask (uint32_t, bool) __attribute__((weak_import));\n'
)
old_fn = """static void hostEnableInterrupt (void)
{
  if (gIrqMode || !&armcpu_spi_attach || !&armcpu_spi_mask) return;
  if (armcpu_spi_attach (kUfsIrq, false, hostInterrupt, nullptr, nullptr, nullptr) != kIOReturnSuccess) return;
  hostWrite (0x24, 1);                      // UTRCE only
  if (armcpu_spi_mask (kUfsIrq, false) != kIOReturnSuccess) { hostWrite (0x24, 0); return; }
  gIrqMode = true;
  native_ufs_irq_mode = 1;
}"""
new_fn = """static void hostEnableInterrupt (void)
{
  // ishtar bring-up: no ArmCpu SPI driver. Poll exactly as the pre-update driver did.
  (void) kUfsIrq; (void) hostInterrupt;
}"""

src_hits = []
for root, dirs, files in os.walk("."):
    if "NativeUfs.cpp" in files:
        path = os.path.join(root, "NativeUfs.cpp")
        text = open(path, encoding="utf-8").read()
        if externs not in text or old_fn not in text:
            continue
        text = text.replace(externs, "", 1).replace(old_fn, new_fn, 1)
        open(path, "w", encoding="utf-8").write(text)
        src_hits.append(path)
        print("PATCHED", path, "-> polling only")
if not src_hits:
    print("NOTE: no ShengUfs interrupt setup to patch (older pin)")
print("patched", len(src_hits), "NativeUfs.cpp file(s)")
