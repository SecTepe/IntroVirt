/*
 * Copyright 2026 SecTepe.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * ---------------------------------------------------------------------------
 * Android Binder IPC decoding (SecTepe addition; see SECTEPE_VENDOR.md).
 *
 * Android is "Linux userspace on a stock x86_64 kernel", so the IntroVirt
 * Linux guest model introspects it unchanged at the kernel/syscall layer.
 * The one piece of *Android* semantics that is not visible as a plain syscall
 * is Binder IPC — all inter-process / inter-app calls travel through
 * ``ioctl(/dev/binder, BINDER_WRITE_READ, ...)``. This decoder lifts the
 * BC_TRANSACTION / BC_REPLY records out of that ioctl's command buffer so the
 * syscall stream carries inter-app call edges (target handle + transaction
 * code + direction), the highest-value Android behavioural signal.
 *
 * Scope: targets/codes/direction only — NOT full Parcel unmarshalling or
 * handle->service-name resolution (that needs ServiceManager state and per-
 * service AIDL descriptors, which live above the kernel). Best-effort: a
 * malformed buffer must never abort a trace, so all reads are guarded.
 */
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace introvirt {

class Vcpu;

namespace linux_guest {
namespace android {

// ioctl request code for binder read/write — _IOWR('b', 1, binder_write_read).
// Stable across the relevant kernels (uapi/linux/android/binder.h).
constexpr uint64_t BINDER_WRITE_READ = 0xC0306201ULL;

/// A single decoded binder transaction record.
struct BinderTransaction {
    bool reply = false;        ///< BC_REPLY (true) vs BC_TRANSACTION (false)
    bool oneway = false;       ///< TF_ONE_WAY async transaction
    uint32_t target_handle = 0; ///< target.handle (the remote service handle)
    uint32_t code = 0;          ///< transaction code (the AIDL method ordinal)
    uint32_t flags = 0;         ///< raw transaction flags
};

/**
 * @brief Parse binder BC_TRANSACTION/BC_REPLY records out of a flat copy of a
 * binder ``write_buffer`` command stream.
 *
 * Pure function over an in-memory byte buffer (no hypervisor dependency) so it
 * is unit-testable with a synthetic buffer. @p buf points at the command
 * stream, @p len is its length (the caller's ``write_size``).
 */
std::vector<BinderTransaction> parse_binder_commands(const uint8_t* buf, std::size_t len);

/**
 * @brief Decode the binder transactions in an ``ioctl(BINDER_WRITE_READ)``.
 *
 * Reads the ``binder_write_read`` struct at @p bwr_addr from the guest @p vcpu
 * (user CR3 — the same context the other syscall arg decoders read in), copies
 * the ``write_buffer`` command stream out and hands it to
 * ::parse_binder_commands. Returns an empty vector on any read error
 * (best-effort).
 *
 * @param vcpu     the faulting vcpu (arg memory mapped under its CR3)
 * @param bwr_addr guest virtual address of the binder_write_read struct (arg2)
 */
std::vector<BinderTransaction> decode_binder_write_read(const Vcpu& vcpu,
                                                        uint64_t bwr_addr);

/**
 * @brief Render decoded transactions as ``(label, value)`` pairs for the
 * syscall record's ``decoded_`` list (so they flow through write()/json()).
 */
std::vector<std::pair<std::string, std::string>>
binder_decoded_fields(const std::vector<BinderTransaction>& txns);

} // namespace android
} // namespace linux_guest
} // namespace introvirt
