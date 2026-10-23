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
#include <introvirt/core/arch/Architecture.hh>

namespace introvirt {

const std::string& to_string(Architecture arch) {
    static const std::string X86_64Str("x86_64");
    static const std::string Aarch64Str("aarch64");
    static const std::string UnknownStr("Unknown");

    switch (arch) {
    case Architecture::x86_64:
        return X86_64Str;
    case Architecture::aarch64:
        return Aarch64Str;
    case Architecture::Unknown:
        return UnknownStr;
    }
    return UnknownStr;
}

std::ostream& operator<<(std::ostream& os, Architecture arch) {
    os << to_string(arch);
    return os;
}

} // namespace introvirt
