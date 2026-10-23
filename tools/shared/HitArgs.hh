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
 * Call arguments at a breakpoint hit (BreakpointMonitor.hh, SECTEPE-BP line).
 *
 * At a function's first instruction the arguments sit where the calling
 * convention put them:
 *   - 64-bit code (long mode, 64-bit code segment): RCX, RDX, R8, R9; the
 *     return address is the 64-bit word at RSP.
 *   - 32-bit code (a WOW64 process in compatibility mode, or a 32-bit guest):
 *     stdcall/cdecl, everything on the stack -- [ESP] is the return address,
 *     the arguments follow at ESP+4, ESP+8, ... as 32-bit words.
 * This is the same decision WindowsFunctionCall makes
 * (`long_mode() && !long_compatibility_mode()` = 64-bit).
 *
 * Most samples run as 32-bit WOW64 processes; before this, their hits showed
 * the x64 registers, which are not the call's arguments.
 *
 * The monitor reads the stack words from the guest (guest_ptr on RSP); what
 * becomes of them is here, without a hypervisor: tests/unit_tests.cc.
 */

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <string>

namespace sectepe {

// Arguments reported per hit (the first four: x64 passes four in registers).
constexpr size_t kHitArgs = 4;
// 32-bit stack words read at ESP: the return address + kHitArgs arguments.
constexpr size_t kHitStackWords32 = kHitArgs + 1;

struct HitArgs {
    bool x64 = true;
    bool ret_known = false;
    uint64_t ret = 0;
    // Number of valid entries in args (0 when a 32-bit stack was not readable).
    size_t count = 0;
    uint64_t args[kHitArgs] = {};
};

// 64-bit code: arguments from the registers, the return address from [RSP]
// when it could be read (@p ret null otherwise).
inline HitArgs hit_args_x64(uint64_t rcx, uint64_t rdx, uint64_t r8, uint64_t r9,
                            const uint64_t* ret) {
    HitArgs out;
    out.x64 = true;
    out.args[0] = rcx;
    out.args[1] = rdx;
    out.args[2] = r8;
    out.args[3] = r9;
    out.count = kHitArgs;
    if (ret != nullptr) {
        out.ret_known = true;
        out.ret = *ret;
    }
    return out;
}

// 32-bit code: @p stack holds the @p words 32-bit words read at ESP (fewer
// than kHitStackWords32 when the stack ends at an unreadable page, 0 when not
// even [ESP] was readable).
inline HitArgs hit_args_x86(const uint32_t* stack, size_t words) {
    HitArgs out;
    out.x64 = false;
    if (stack == nullptr || words == 0)
        return out;
    out.ret_known = true;
    out.ret = stack[0];
    for (size_t i = 1; i < words && out.count < kHitArgs; ++i)
        out.args[out.count++] = stack[i];
    return out;
}

// The fields of a SECTEPE-BP line this adds, starting with a comma:
//   ,"mode":"x64|x86","ret":"0x..."|null,"args":["0x..",...]
inline std::string hit_args_json(const HitArgs& a) {
    char buf[24];
    std::string out = ",\"mode\":\"";
    out += a.x64 ? "x64" : "x86";
    out += "\",\"ret\":";
    if (a.ret_known) {
        std::snprintf(buf, sizeof(buf), "\"0x%llx\"", static_cast<unsigned long long>(a.ret));
        out += buf;
    } else {
        out += "null";
    }
    out += ",\"args\":[";
    for (size_t i = 0; i < a.count; ++i) {
        std::snprintf(buf, sizeof(buf), "%s\"0x%llx\"", i ? "," : "",
                      static_cast<unsigned long long>(a.args[i]));
        out += buf;
    }
    out += ']';
    return out;
}

} // namespace sectepe
