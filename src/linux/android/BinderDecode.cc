/*
 * Copyright 2026 SecTepe.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 */
#include "BinderDecode.hh"

#include <introvirt/core/domain/Vcpu.hh>
#include <introvirt/core/exception/TraceableException.hh>
#include <introvirt/core/memory/guest_ptr.hh>

#include <cstddef>
#include <cstring>

namespace introvirt {
namespace linux_guest {
namespace android {

namespace {

// uapi/linux/android/binder.h — layouts are uABI-stable for the 64-bit kernels
// Android-x86 ships. We mirror the on-the-wire structs rather than #include the
// kernel header so the decoder builds without an Android sysroot.

// Binder command protocol opcodes (host -> driver), in the write_buffer.
// _IOW('c', N, ...) low byte == N; we only need the ones that carry a
// transaction payload. BC_* numbering from enum binder_driver_command_protocol.
constexpr uint32_t BC_TRANSACTION = 0x40406300; // _IOW('c', 0, binder_transaction_data)
constexpr uint32_t BC_REPLY = 0x40406301;       // _IOW('c', 1, binder_transaction_data)
constexpr uint32_t BC_TRANSACTION_SG = 0x40486311; // with buffers_size suffix
constexpr uint32_t BC_REPLY_SG = 0x40486312;

constexpr uint32_t TF_ONE_WAY = 0x01; // async, no return expected

struct binder_write_read {
    uint64_t write_size;
    uint64_t write_consumed;
    uint64_t write_buffer; // guest pointer to the command stream
    uint64_t read_size;
    uint64_t read_consumed;
    uint64_t read_buffer;
};

// struct binder_transaction_data (the 64-bit layout). We only read the leading
// fields we report; the trailing data pointers are skipped.
struct binder_transaction_data {
    uint64_t target_handle; // union { __u32 handle; binder_uintptr_t ptr; }
    uint64_t cookie;
    uint32_t code;
    uint32_t flags;
    int32_t sender_pid;
    uint32_t sender_euid;
    uint64_t data_size;
    uint64_t offsets_size;
    uint64_t data_ptr;     // union buffer/ptr
    uint64_t data_offsets;
};

template <typename T>
bool read_struct(const Vcpu& vcpu, uint64_t addr, T& out) {
    if (addr == 0)
        return false;
    try {
        guest_ptr<char[]> ptr(vcpu, addr, sizeof(T));
        std::memcpy(&out, ptr.get(), sizeof(T));
        return true;
    } catch (const TraceableException&) {
        return false; // unmapped / unreadable — best-effort
    }
}

} // namespace

std::vector<BinderTransaction> parse_binder_commands(const uint8_t* buf, std::size_t len) {
    std::vector<BinderTransaction> out;
    if (buf == nullptr || len == 0 || len > (1u << 20)) // sanity cap: 1 MiB
        return out;

    std::size_t off = 0;
    // Walk the command stream: each record is a 4-byte BC_* opcode optionally
    // followed by a fixed-size payload. We only decode transaction-bearing
    // opcodes; an unknown opcode aborts the walk (best-effort, never throws).
    int guard = 0;
    while (off + sizeof(uint32_t) <= len && guard++ < 4096) {
        uint32_t cmd = 0;
        std::memcpy(&cmd, buf + off, sizeof(uint32_t));
        off += sizeof(uint32_t);

        const bool is_txn = (cmd == BC_TRANSACTION || cmd == BC_REPLY ||
                             cmd == BC_TRANSACTION_SG || cmd == BC_REPLY_SG);
        if (!is_txn) {
            // Unknown / payload-less command — we cannot reliably know its
            // size, so stop rather than misparse. Transactions are normally the
            // first record in a write_buffer, so this still captures them.
            break;
        }
        if (off + sizeof(binder_transaction_data) > len)
            break;
        binder_transaction_data td{};
        std::memcpy(&td, buf + off, sizeof(binder_transaction_data));
        BinderTransaction t;
        t.reply = (cmd == BC_REPLY || cmd == BC_REPLY_SG);
        t.target_handle = static_cast<uint32_t>(td.target_handle);
        t.code = td.code;
        t.flags = td.flags;
        t.oneway = (td.flags & TF_ONE_WAY) != 0;
        out.push_back(t);
        off += sizeof(binder_transaction_data);
        // The _SG variants carry an extra 8-byte buffers_size suffix.
        if (cmd == BC_TRANSACTION_SG || cmd == BC_REPLY_SG)
            off += sizeof(uint64_t);
    }
    return out;
}

std::vector<BinderTransaction> decode_binder_write_read(const Vcpu& vcpu,
                                                        uint64_t bwr_addr) {
    binder_write_read bwr{};
    if (!read_struct(vcpu, bwr_addr, bwr))
        return {};

    // Only the portion the caller actually wrote is meaningful.
    const uint64_t size = bwr.write_size;
    const uint64_t base = bwr.write_buffer;
    if (base == 0 || size == 0 || size > (1u << 20)) // sanity cap: 1 MiB
        return {};

    // Copy the command stream out of the guest in one read, then parse the flat
    // buffer with the pure (unit-testable) walker.
    try {
        guest_ptr<char[]> ptr(vcpu, base, size);
        return parse_binder_commands(reinterpret_cast<const uint8_t*>(ptr.get()),
                                     static_cast<std::size_t>(size));
    } catch (const TraceableException&) {
        return {}; // unmapped / unreadable — best-effort
    }
}

std::vector<std::pair<std::string, std::string>>
binder_decoded_fields(const std::vector<BinderTransaction>& txns) {
    std::vector<std::pair<std::string, std::string>> fields;
    if (txns.empty())
        return fields;
    fields.emplace_back("binder", txns.front().reply ? "reply" : "transaction");
    // Report the first transaction's primary identifiers; multi-record buffers
    // are rare for BC_TRANSACTION and the first is the salient call edge.
    const auto& t = txns.front();
    fields.emplace_back("binder_target_handle", std::to_string(t.target_handle));
    fields.emplace_back("binder_code", std::to_string(t.code));
    if (t.oneway)
        fields.emplace_back("binder_oneway", "1");
    if (txns.size() > 1)
        fields.emplace_back("binder_txn_count", std::to_string(txns.size()));
    return fields;
}

} // namespace android
} // namespace linux_guest
} // namespace introvirt
