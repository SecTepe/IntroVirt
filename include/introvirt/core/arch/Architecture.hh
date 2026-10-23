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

#include <ostream>
#include <string>

namespace introvirt {

/**
 * @brief The CPU architecture of a guest / vcpu.
 *
 * IntroVirt is x86-only today, so everything reports @ref Architecture::x86_64.
 * This enum is the arch-neutral seam for the arm64 port (see
 * docs/introvirt-arm64.md, Phase 1): callers that must branch on architecture
 * (e.g. the syscall decoder, which reads the number from `rax` on x86_64 but
 * `x8` on AArch64) ask for it here instead of assuming x86. The @ref
 * Architecture::aarch64 concretions land in later phases (arm64 register model,
 * page-table walker, guest model) once the KVMi backend exists.
 *
 * Mirrors the @ref OS enum (introvirt/core/event/Event.hh).
 */
enum class Architecture { Unknown, x86_64, aarch64 };

/**
 * @brief Get a human-readable name for an Architecture (e.g. "x86_64").
 */
const std::string& to_string(Architecture arch);

/**
 * @brief Stream an Architecture by name.
 */
std::ostream& operator<<(std::ostream& os, Architecture arch);

} // namespace introvirt
