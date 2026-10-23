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
 * Breakpoint spec of the out-of-VM debugger.
 *
 * `ivsyscallmon --bp "target=kernel32!CreateFileW,action=trace,access=exec,hits=1"`
 * takes one spec per breakpoint. The runner (tools/vmi-runner/runner.py) builds
 * these strings from the debug spec the sandbox controller validated
 * (api/sandbox-controller/connectors/debug_options.py); the rules below are the
 * same ones, so a spec accepted there is accepted here. This header is pure
 * logic (no hypervisor), so tests/unit_tests.cc covers it under ctest.
 *
 *   target  0xADDR | module!export | ep+0xNN | ep-0xNN     (required)
 *   action  trace (default) | dump | step | custom | scan
 *   access  exec (default) | write | readwrite
 *   hits    0..65535; the breakpoint is removed after that many hits, 0 = never
 *   depth   0..64 (action=step): call levels to step into below the hit function
 *   steps   1..4096 (action=step): instructions recorded per hit, default 256
 */

#include <cstdint>
#include <initializer_list>
#include <string>
#include <utility>

namespace sectepe {

struct BreakpointSpec {
    enum class TargetKind { Address, Export, EntryPoint };

    std::string target; // as given, e.g. "kernel32!CreateFileW"
    std::string action = "trace";
    std::string access = "exec";
    uint32_t hits = 0;
    uint32_t depth = 0;   // action=step: call levels to step into
    uint32_t steps = 256; // action=step: instructions recorded per hit

    TargetKind kind = TargetKind::Address;
    uint64_t address = 0;  // Address: the address; EntryPoint: the offset (absolute value)
    bool negative = false; // EntryPoint: "ep-0x..."
    std::string module;    // Export: "kernel32" or "kernel32.dll"
    std::string symbol;    // Export: "CreateFileW"

    bool read() const { return access == "readwrite"; }
    bool write() const { return access == "write" || access == "readwrite"; }
};

namespace detail {

inline bool is_hex(char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

inline bool is_alnum(char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

// "0x" + 1..max_digits hex digits at s[from..]; returns false otherwise.
inline bool parse_hex(const std::string& s, size_t from, size_t max_digits, uint64_t& out) {
    if (s.size() < from + 3 || s[from] != '0' || (s[from + 1] != 'x' && s[from + 1] != 'X'))
        return false;
    const size_t digits = s.size() - from - 2;
    if (digits < 1 || digits > max_digits)
        return false;
    uint64_t value = 0;
    for (size_t i = from + 2; i < s.size(); ++i) {
        if (!is_hex(s[i]))
            return false;
        const char c = s[i];
        const uint64_t nibble = (c <= '9') ? (c - '0') : ((c | 0x20) - 'a' + 10);
        value = (value << 4) | nibble;
    }
    out = value;
    return true;
}

inline bool valid_module(const std::string& s) {
    if (s.empty() || s.size() > 64)
        return false;
    for (char c : s) {
        if (!is_alnum(c) && c != '_' && c != '.' && c != '-')
            return false;
    }
    return true;
}

inline bool valid_symbol(const std::string& s) {
    if (s.empty() || s.size() > 128)
        return false;
    for (char c : s) {
        if (!is_alnum(c) && c != '_' && c != '@' && c != '?' && c != '$')
            return false;
    }
    return true;
}

inline bool parse_target(const std::string& target, BreakpointSpec& out, std::string& error) {
    uint64_t value = 0;
    if (parse_hex(target, 0, 16, value)) {
        out.kind = BreakpointSpec::TargetKind::Address;
        out.address = value;
        return true;
    }
    if (target.size() > 2 && target[0] == 'e' && target[1] == 'p' &&
        (target[2] == '+' || target[2] == '-')) {
        if (!parse_hex(target, 3, 8, value)) {
            error = "invalid entry-point offset in target '" + target + "'";
            return false;
        }
        out.kind = BreakpointSpec::TargetKind::EntryPoint;
        out.address = value;
        out.negative = target[2] == '-';
        return true;
    }
    const size_t bang = target.find('!');
    if (bang != std::string::npos) {
        const std::string module = target.substr(0, bang);
        const std::string symbol = target.substr(bang + 1);
        if (!valid_module(module) || !valid_symbol(symbol)) {
            error = "invalid module!export in target '" + target + "'";
            return false;
        }
        out.kind = BreakpointSpec::TargetKind::Export;
        out.module = module;
        out.symbol = symbol;
        return true;
    }
    error = "invalid target '" + target + "' (expected 0xADDR, module!export or ep+0xNN)";
    return false;
}

// Decimal 0..max (at most 5 digits); false otherwise.
inline bool parse_uint(const std::string& value, uint32_t max, uint32_t& out) {
    if (value.empty() || value.size() > 5)
        return false;
    uint32_t n = 0;
    for (char c : value) {
        if (c < '0' || c > '9')
            return false;
        n = n * 10 + static_cast<uint32_t>(c - '0');
    }
    if (n > max)
        return false;
    out = n;
    return true;
}

inline bool one_of(const std::string& value, std::initializer_list<const char*> allowed) {
    for (const char* a : allowed) {
        if (value == a)
            return true;
    }
    return false;
}

} // namespace detail

/**
 * Parse "target=...[,action=...][,access=...][,hits=N]".
 *
 * @return true and fill @p out, or false with a human-readable @p error.
 */
inline bool parse_breakpoint_spec(const std::string& text, BreakpointSpec& out,
                                  std::string& error) {
    BreakpointSpec spec;
    bool have_target = false, have_action = false, have_access = false, have_hits = false;
    bool have_depth = false, have_steps = false;

    size_t pos = 0;
    while (pos <= text.size()) {
        size_t comma = text.find(',', pos);
        if (comma == std::string::npos)
            comma = text.size();
        const std::string field = text.substr(pos, comma - pos);
        pos = comma + 1;

        const size_t eq = field.find('=');
        if (eq == std::string::npos || eq == 0) {
            error = "expected key=value, got '" + field + "'";
            return false;
        }
        const std::string key = field.substr(0, eq);
        const std::string value = field.substr(eq + 1);

        if (key == "target") {
            if (have_target) {
                error = "duplicate key 'target'";
                return false;
            }
            have_target = true;
            spec.target = value;
            if (!detail::parse_target(value, spec, error))
                return false;
        } else if (key == "action") {
            if (have_action) {
                error = "duplicate key 'action'";
                return false;
            }
            have_action = true;
            if (!detail::one_of(value, {"trace", "dump", "step", "custom", "scan"})) {
                error = "invalid action '" + value + "'";
                return false;
            }
            spec.action = value;
        } else if (key == "access") {
            if (have_access) {
                error = "duplicate key 'access'";
                return false;
            }
            have_access = true;
            if (!detail::one_of(value, {"exec", "write", "readwrite"})) {
                error = "invalid access '" + value + "'";
                return false;
            }
            spec.access = value;
        } else if (key == "hits") {
            if (have_hits) {
                error = "duplicate key 'hits'";
                return false;
            }
            have_hits = true;
            if (value.empty() || value.size() > 5) {
                error = "invalid hits '" + value + "'";
                return false;
            }
            uint32_t n = 0;
            for (char c : value) {
                if (c < '0' || c > '9') {
                    error = "invalid hits '" + value + "'";
                    return false;
                }
                n = n * 10 + static_cast<uint32_t>(c - '0');
            }
            if (n > 65535) {
                error = "hits out of range (0..65535)";
                return false;
            }
            spec.hits = n;
        } else if (key == "depth") {
            if (have_depth) {
                error = "duplicate key 'depth'";
                return false;
            }
            have_depth = true;
            if (!detail::parse_uint(value, 64, spec.depth)) {
                error = "invalid depth '" + value + "' (0..64)";
                return false;
            }
        } else if (key == "steps") {
            if (have_steps) {
                error = "duplicate key 'steps'";
                return false;
            }
            have_steps = true;
            if (!detail::parse_uint(value, 4096, spec.steps) || spec.steps == 0) {
                error = "invalid steps '" + value + "' (1..4096)";
                return false;
            }
        } else {
            error = "unknown key '" + key + "'";
            return false;
        }
    }

    if (!have_target) {
        error = "missing target";
        return false;
    }
    out = std::move(spec);
    return true;
}

/** Escape @p s for use inside a JSON string literal. */
inline std::string json_escape(const std::string& s) {
    static const char* hex = "0123456789abcdef";
    std::string out;
    out.reserve(s.size() + 8);
    for (unsigned char c : s) {
        switch (c) {
        case '"':
            out += "\\\"";
            break;
        case '\\':
            out += "\\\\";
            break;
        case '\n':
            out += "\\n";
            break;
        case '\r':
            out += "\\r";
            break;
        case '\t':
            out += "\\t";
            break;
        default:
            if (c < 0x20 || c == 0x7f) {
                out += "\\u00";
                out += hex[c >> 4];
                out += hex[c & 0xf];
            } else {
                out += static_cast<char>(c);
            }
        }
    }
    return out;
}

} // namespace sectepe
