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

#include <introvirt/core/arch/x86/x86.hh>
#include <introvirt/core/domain/Vcpu.hh>

#include <cstdint>
#include <memory>

namespace introvirt {
namespace x86 {

/**
 * @brief The x86-specific slice of the Vcpu interface.
 *
 * These are the vcpu operations whose signature names an x86 type (exception
 * injection, segment/descriptor-table/TSS access) or an x86 instruction
 * (SYSCALL/SYSENTER injection). They live here — rather than on the
 * architecture-neutral @ref Vcpu base — so a future arm64 vcpu can derive from
 * `Vcpu` without being forced to implement x86-only methods (see
 * docs/introvirt-arm64.md, Phase 1). The concrete x86 vcpu chain
 * (`VcpuImpl` → `KvmVcpu`) derives from this.
 *
 * Arch-neutral callers stay on `Vcpu`; code that needs the x86 surface reaches
 * it via `Vcpu::x86()` (which returns `nullptr` on a non-x86 vcpu). This mirrors
 * how `x86::Registers` extends @ref RegisterContext.
 *
 * Deliberately NOT named `x86::Vcpu`: a class named `Vcpu` in this namespace
 * would shadow `introvirt::Vcpu` for every unqualified `Vcpu` inside
 * `namespace introvirt::x86` (and as an injected-class-name in subclasses),
 * which silently breaks existing x86 code (e.g. `PageDirectory::reconfigure`).
 */
class VcpuOps : public introvirt::Vcpu {
  public:
    /**
     * @brief Inject an exception for this vcpu
     *
     * @param vector The exception type to inject
     * @throws CommandFailedException If the hypervisor reports an error
     */
    virtual void inject_exception(x86::Exception vector) = 0;

    /**
     * @copydoc x86::VcpuOps::inject_exception(x86::Exception)
     * @param error_code The error code to deliver
     */
    virtual void inject_exception(x86::Exception vector, int64_t error_code) = 0;

    /**
     * @copydoc x86::VcpuOps::inject_exception(x86::Exception, int64_t error_code)
     * @param cr2 The cr2 value to set (only for x86::Exception::PAGE_FAULT)
     */
    virtual void inject_exception(x86::Exception vector, int64_t error_code, uint64_t cr2) = 0;

    /**
     * @brief Inject a SYSCALL instruction into the VCPU
     *
     * You probably don't want to call this yourself.
     */
    virtual void inject_syscall() = 0;

    /**
     * @brief Inject a SYSENTER instruction into the VCPU
     *
     * You probably don't want to call this yourself.
     */
    virtual void inject_sysenter() = 0;

    /**
     * @brief Get a segement descriptor given the current selector
     *
     * Check the GDT or LDT for the correct segment descriptor
     *
     * @param selector
     * @return x86::Segment
     */
    virtual x86::Segment segment(x86::SegmentSelector selector) const = 0;

    /**
     * @brief Gets the Global Descriptor Table (GDT) for this VCPU
     *
     * @return The GDT for this VCPU
     */
    virtual x86::SegmentDescriptorTable global_descriptor_table() const = 0;

    /**
     * @brief Gets the active Local Descriptor Table (LDT) for this VCPU
     *
     * @return The active LDT for this VCPU
     */
    virtual x86::SegmentDescriptorTable local_descriptor_table() const = 0;

    /**
     * @brief Gets the Interrupt Descriptor Table (IDT) for this VCPU
     *
     * @return The Idt for this VCPU
     */
    virtual std::unique_ptr<const x86::Idt> interrupt_descriptor_table() const = 0;

    /**
     * @brief Get the x86 Task State Segment (TSS)
     * @return The x86 task state segment
     */
    virtual const x86::Tss& task_state_segment() const = 0;

    /**
     * @brief Identify this vcpu as the x86 concretion (see Vcpu::x86()).
     */
    x86::VcpuOps* x86() noexcept override { return this; }
    const x86::VcpuOps* x86() const noexcept override { return this; }

    ~VcpuOps() override = default;
};

} // namespace x86
} // namespace introvirt
