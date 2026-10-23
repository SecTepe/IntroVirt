/*
 * Copyright 2026 SecTepe.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#pragma once

/*
 * Step logic of the out-of-VM debugger:
 * `action=step` single-steps from a breakpoint hit (BreakpointMonitor.hh).
 *
 * IntroVirt steps with the Monitor Trap Flag but has no disassembler, and a
 * trace only needs to know four things about the instruction at RIP: is it a
 * call (and how long, to step over it), a return, a system call, or anything
 * else. That is what classify() reads from the raw bytes - legacy and REX
 * prefixes, ModRM/SIB/displacement for `call r/m`. Every other instruction is
 * "other"; its length is not needed, the next step shows where it went.
 *
 * The code's mode comes from the vcpu at every step (a WOW64 trace can cross
 * into 64-bit code through the transition gate): in 32-bit code 0x40-0x4F are
 * inc/dec, not REX; 66 makes `call rel` a rel16, 67 switches the ModRM to
 * 16-bit addressing, and `call far ptr16:32` (9A) exists.
 *
 * decide() is the trace policy:
 *   - a call deeper than `depth` is stepped OVER (temporary breakpoint on the
 *     return address), so depth 0 traces the hit function itself;
 *   - a system call is always stepped over (no stepping through the kernel);
 *   - the return out of the hit function ends the trace;
 *   - at most `budget` instructions are recorded.
 *
 * Pure logic, no hypervisor: tests/unit_tests.cc covers it under ctest.
 */

#include <cstddef>
#include <cstdint>
#include <string>

namespace sectepe {

enum class InsnKind { Other, Call, Ret, Syscall };

struct Insn {
    InsnKind kind = InsnKind::Other;
    size_t length = 0; // known for Call / Ret / Syscall, 0 for Other
};

inline const char* insn_kind_name(InsnKind kind) {
    switch (kind) {
    case InsnKind::Call:
        return "call";
    case InsnKind::Ret:
        return "ret";
    case InsnKind::Syscall:
        return "syscall";
    case InsnKind::Other:
        break;
    }
    return "other";
}

namespace detail {

// Length of ModRM (+ SIB + displacement) starting at b[i]; 0 if out of bytes.
inline size_t modrm_length(const uint8_t* b, size_t n, size_t i) {
    if (i >= n)
        return 0;
    const uint8_t modrm = b[i];
    const uint8_t mod = modrm >> 6, rm = modrm & 7;
    size_t len = 1;
    if (mod == 3)
        return len;
    if (rm == 4) { // SIB
        if (i + 1 >= n)
            return 0;
        const uint8_t base = b[i + 1] & 7;
        len += 1;
        if (mod == 0 && base == 5)
            len += 4;
    } else if (mod == 0 && rm == 5) { // RIP-relative
        len += 4;
    }
    if (mod == 1)
        len += 1;
    else if (mod == 2)
        len += 4;
    return i + len <= n ? len : 0;
}

// 16-bit addressing (a 67 prefix in 32-bit code): no SIB, 16-bit displacements.
inline size_t modrm16_length(const uint8_t* b, size_t n, size_t i) {
    if (i >= n)
        return 0;
    const uint8_t mod = b[i] >> 6, rm = b[i] & 7;
    size_t len = 1;
    if (mod == 1)
        len += 1;
    else if (mod == 2 || (mod == 0 && rm == 6))
        len += 2;
    return i + len <= n ? len : 0;
}

inline bool is_legacy_prefix(uint8_t c) {
    switch (c) {
    case 0x66: case 0x67: case 0xF0: case 0xF2: case 0xF3:
    case 0x2E: case 0x36: case 0x3E: case 0x26: case 0x64: case 0x65:
        return true;
    default:
        return false;
    }
}

} // namespace detail

/**
 * Classify the instruction at @p b (up to @p n bytes) in 64-bit code (@p x64,
 * long mode with a 64-bit code segment) or 32-bit code (protected or
 * compatibility mode, e.g. a WOW64 process).
 */
inline Insn classify(const uint8_t* b, size_t n, bool x64 = true) {
    size_t i = 0;
    bool opsize16 = false, addr16 = false;
    while (i < n && i < 14 && detail::is_legacy_prefix(b[i])) {
        opsize16 |= b[i] == 0x66;
        addr16 |= b[i] == 0x67;
        ++i;
    }
    if (x64 && i < n && (b[i] & 0xF0) == 0x40) // REX (inc/dec in 32-bit code)
        ++i;
    if (i >= n)
        return {};
    // In long mode 66 does not shorten a near call, and 67 selects 32-bit
    // addressing, which has the same ModRM lengths as 64-bit.
    const bool rel16 = !x64 && opsize16;
    const bool modrm16 = !x64 && addr16;

    const uint8_t op = b[i];
    switch (op) {
    case 0xE8: { // call rel32 (rel16 with 66 in 32-bit code)
        const size_t len = i + (rel16 ? 3 : 5);
        return len <= n ? Insn{InsnKind::Call, len} : Insn{};
    }
    case 0x9A: { // call far ptr16:32 / ptr16:16 -- 32-bit code only
        if (x64)
            return {};
        const size_t len = i + (rel16 ? 5 : 7);
        return len <= n ? Insn{InsnKind::Call, len} : Insn{};
    }
    case 0xFF: { // group 5: /2 call r/m, /3 call far m16:xx
        if (i + 1 >= n)
            return {};
        const uint8_t reg = (b[i + 1] >> 3) & 7;
        if (reg != 2 && reg != 3)
            return {};
        const size_t m = modrm16 ? detail::modrm16_length(b, n, i + 1)
                                 : detail::modrm_length(b, n, i + 1);
        return m ? Insn{InsnKind::Call, i + 1 + m} : Insn{};
    }
    case 0xC3: // ret
    case 0xCB: // retf
        return {InsnKind::Ret, i + 1};
    case 0xC2: // ret imm16
    case 0xCA: // retf imm16
        return i + 3 <= n ? Insn{InsnKind::Ret, i + 3} : Insn{};
    case 0xCD: // int imm8: int 0x2e is the legacy system call gate
        return (i + 1 < n && b[i + 1] == 0x2E) ? Insn{InsnKind::Syscall, i + 2} : Insn{};
    case 0x0F:
        if (i + 1 < n && (b[i + 1] == 0x05 || b[i + 1] == 0x34)) // syscall, sysenter
            return {InsnKind::Syscall, i + 2};
        return {};
    default:
        return {};
    }
}

struct StepPolicy {
    unsigned depth = 0;    // call levels to step INTO below the hit function
    unsigned budget = 256; // instructions recorded per hit
};

enum class StepAction { Continue, StepOver, Stop };

struct StepDecision {
    StepAction action = StepAction::Continue;
    unsigned depth = 0;      // call depth after the instruction executes
    uint64_t resume_at = 0;  // StepOver: where the thread comes back
    const char* reason = ""; // Stop: why
};

/**
 * What to do with the instruction at @p rip, the @p recorded-th of the trace
 * (1-based, already counted), at call depth @p depth below the hit function.
 */
inline StepDecision decide(const Insn& insn, uint64_t rip, unsigned depth, unsigned recorded,
                           const StepPolicy& policy) {
    StepDecision d;
    d.depth = depth;
    switch (insn.kind) {
    case InsnKind::Ret:
        if (depth == 0) {
            d.action = StepAction::Stop;
            d.reason = "returned";
            return d;
        }
        d.depth = depth - 1;
        break;
    case InsnKind::Call:
        if (depth >= policy.depth) {
            d.action = StepAction::StepOver;
            d.resume_at = rip + insn.length;
        } else {
            d.depth = depth + 1;
        }
        break;
    case InsnKind::Syscall:
        d.action = StepAction::StepOver;
        d.resume_at = rip + insn.length;
        break;
    case InsnKind::Other:
        break;
    }
    if (recorded >= policy.budget) {
        // Nothing after this one would be recorded: no step-over either.
        d.action = StepAction::Stop;
        d.resume_at = 0;
        d.reason = "step budget reached";
    }
    return d;
}

/** Lower-case hex of @p n bytes, for the trace line. */
inline std::string hex_bytes(const uint8_t* b, size_t n) {
    static const char* digits = "0123456789abcdef";
    std::string out;
    out.reserve(n * 2);
    for (size_t i = 0; i < n; ++i) {
        out += digits[b[i] >> 4];
        out += digits[b[i] & 0xF];
    }
    return out;
}

} // namespace sectepe
