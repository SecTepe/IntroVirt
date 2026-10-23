# Linux guest profiles for IntroVirt (SecTepe)

The native Linux guest model (see `docs/introvirt-linux-port.md`) resolves
kernel symbols and struct member offsets from an **offline-generated
profile** instead of an in-image PDB. This directory holds the generator.

## What a profile contains

A compact JSON (`sectepe-linux-isf/1`) with exactly what the model walks:

```json
{
  "format": "sectepe-linux-isf/1",
  "metadata": { "arch": "x86_64", "source_producer": "dwarf2json" },
  "symbols": { "init_task": 18446744071578834944, "_text": ..., "entry_SYSCALL_64": ... },
  "types":   { "task_struct": { "comm": 1544, "pid": 1232, "tasks": 1080, "mm": 1096 }, ... },
  "sizes":   { "task_struct": 9216, ... }
}
```

Symbol addresses are **link-time** addresses; the live KASLR slide is
applied at runtime by `LinuxKernel`.

## Generating one

1. Get the **uncompressed `vmlinux`** with DWARF for the guest kernel
   (the `-dbg`/`-debuginfo` package, or build output). The compressed
   `vmlinuz` on `/boot` does *not* carry DWARF.

2. Produce a Volatility3 ISF with
   [`dwarf2json`](https://github.com/volatilityfoundation/dwarf2json):

   ```bash
   dwarf2json linux --elf vmlinux > vmlinux.isf.json
   ```

3. Downselect + validate to the SecTepe profile:

   ```bash
   python3 generate_isf.py --in vmlinux.isf.json \
       --out ~/.introvirt/profiles/linux-$(uname -r)-x86_64.json
   ```

   `generate_isf.py` **fails loudly** if the kernel's DWARF is missing any
   symbol or struct member the model depends on (the `REQUIRED_SYMBOLS` /
   `REQUIRED_TYPES` manifest at the top of the script) — so an incomplete
   profile is caught on the build host, not on a live detonation. Use
   `--check` to validate without writing.

## Versioning notes

- The manifest tolerates kernel-version drift where the layout genuinely
  changed: the pre-6.1 `mm_struct.mmap` VMA list **or** the >=6.1
  `mm_struct.mm_mt` maple tree satisfies the memory-map requirement
  (`OPTIONAL_MEMBERS` in the script).
- One profile per guest kernel release; the model selects it via
  `LinuxProfile::load_for_release(release, arch)`.

## Android-x86

Android-x86 is "Android userspace on a stock x86_64 Linux kernel", so the
**Linux model and this generator apply unchanged** — `REQUIRED_SYMBOLS` /
`REQUIRED_TYPES` are all generic kernel symbols/structs that the Android-x86
9.0 kernel (a ~4.19/5.x x86_64 build) satisfies. No script change is needed;
run `generate_isf.py --check` against the produced ISF to confirm.

The one wrinkle is getting `vmlinux` **with DWARF**, which Android-x86 release
ISOs do not ship (only a stripped `kernel` bzImage). Three tiers, in order of
preference:

1. **DWARF from a debug kernel** — if a `vmlinux` with DWARF is available
   (e.g. an android-x86 source build's
   `out/target/product/x86_64/obj/kernel/.../vmlinux`), use the standard flow
   above. This is the **supported production path** — only DWARF resolves the
   struct member offsets exactly.

2. **Build the kernel from android-x86 source** — check out the matching
   android-x86 9.0 r2 kernel tree/config, build with `CONFIG_DEBUG_INFO=y`
   (and `CONFIG_DEBUG_INFO_BTF=n` to keep `dwarf2json` happy), then feed the
   resulting `vmlinux` to the flow. Yields a complete, exact-match profile.

3. **kallsyms fallback (last resort, brittle)** — `/proc/kallsyms` (read in
   the guest or from a memory dump) supplies the `REQUIRED_SYMBOLS` *addresses*
   but **not** the `REQUIRED_TYPES` struct offsets, so kallsyms alone cannot
   build a valid profile (`generate_isf.py` will reject it). The only way to
   use it is to overlay the live kallsyms addresses onto struct offsets borrowed
   from a DWARF profile of an **identical kernel version/`.config`** (offsets are
   config-stable across builds). Prefer tier 2.

The Android VMI provisioning role (`SecTepe.Comm` `vmi-introvirt-host`,
`08c-android-domain`) automates tier 1/2 generation and installs the result to
`~/.introvirt/profiles/`, then sets `INTROVIRT_LINUX_PROFILE` in the runner env.

Once the profile is in place the model walks the Android process tree natively —
`ivprocinfo` shows `init`, `zygote`/`zygote64`, `system_server` and per-app
package processes; `ivsyscallmon` decodes Binder IPC (`ioctl(BINDER_WRITE_READ)`)
via `src/linux/android/BinderDecode`.
