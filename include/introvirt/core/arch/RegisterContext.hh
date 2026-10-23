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

#include <introvirt/core/arch/Architecture.hh>

#include <cstdint>

namespace introvirt {

/**
 * @brief An architecture-neutral system/control register, named by role.
 *
 * These are the cross-arch concepts the (future) arm64 Linux guest model needs;
 * each maps to a concrete x86 MSR/CR today and to an AArch64 system register in
 * a later phase. Naming them by *role* — rather than by the x86 MSR — is what
 * lets the guest model stay arch-neutral (see docs/introvirt-arm64.md, Phase 1).
 */
enum class SystemRegister {
    SyscallEntry,        ///< x86_64: MSR_LSTAR        | AArch64: VBAR_EL1
    CurrentTaskPointer,  ///< x86_64: kernel GS base   | AArch64: SP_EL0
    KernelPageTableBase, ///< x86_64: CR3 (swapper)    | AArch64: TTBR1_EL1
    UserPageTableBase,   ///< x86_64: CR3              | AArch64: TTBR0_EL1
};

/**
 * @brief Architecture-neutral view of a vcpu's register state.
 *
 * The x86 register interface (@ref x86::Registers) derives from this and keeps
 * all of its x86 accessors (`rax()`, `rip()`, `msr()`, …) unchanged, so every
 * existing call site is untouched. New, arch-neutral consumers — most notably
 * the syscall decoder — take a @ref RegisterContext and ask for the
 * instruction/stack pointer, the syscall number/arguments/return value, and the
 * role-named system registers above, without assuming x86.
 *
 * The AArch64 concretion (number in `x8`; args `x0`–`x5`; return `x0`; system
 * registers via the `one_reg` interface) lands in Phase 2 of the arm64 port.
 */
class RegisterContext {
  public:
    /**
     * @brief The architecture these registers belong to.
     */
    virtual Architecture architecture() const = 0;

    /**
     * @brief Get the instruction pointer (x86_64: `rip`; AArch64: `pc`).
     */
    virtual uint64_t pc() const = 0;
    /**
     * @brief Set the instruction pointer.
     */
    virtual void pc(uint64_t val) = 0;

    /**
     * @brief Get the stack pointer (x86_64: `rsp`; AArch64: `sp`).
     */
    virtual uint64_t sp() const = 0;
    /**
     * @brief Set the stack pointer.
     */
    virtual void sp(uint64_t val) = 0;

    /**
     * @brief Get the syscall number register (x86_64: `rax`; AArch64: `x8`).
     */
    virtual uint64_t syscall_number() const = 0;

    /**
     * @brief Get a syscall argument by index.
     *
     * @param index Argument index, 0-5 (x86_64: rdi,rsi,rdx,r10,r8,r9;
     *              AArch64: x0-x5).
     */
    virtual uint64_t syscall_argument(unsigned index) const = 0;

    /**
     * @brief Get the syscall return value register (x86_64: `rax`;
     *        AArch64: `x0`).
     */
    virtual uint64_t syscall_return_value() const = 0;

    /**
     * @brief Read a role-named system register (see @ref SystemRegister).
     */
    virtual uint64_t system_register(SystemRegister reg) const = 0;

    /**
     * @brief Destroy the instance
     */
    virtual ~RegisterContext() = default;
};

} // namespace introvirt
