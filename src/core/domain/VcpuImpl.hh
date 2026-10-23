/*
 * Copyright 2021 Assured Information Security, Inc.
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

#include "core/event/HypervisorEvent.hh"

#include <introvirt/core/arch/x86/VcpuOps.hh>
#include <introvirt/core/domain/Vcpu.hh>
#include <introvirt/core/fwd.hh>

#include <cstdint>
#include <memory>
#include <string>

namespace introvirt {

/**
 * @brief A class representing a single virtual processor
 *
 * It is subclassed for specific hypervisors, such as the KvmVcpu and the
 * XenVcpu.
 */
class VcpuImpl : public x86::VcpuOps {
  public:
    /**
     * @brief Get the architecture of this processor
     *
     * IntroVirt is x86-only today, so every concrete vcpu is x86_64. An arm64
     * vcpu (Phase 2 of the arm64 port) overrides this.
     */
    Architecture architecture() const override { return Architecture::x86_64; }

    /**
     * @brief Enable single stepping for this VCPU
     *
     * When single stepping, IntroVirt will deliver an EVENT_SINGLE_STEP event for
     * every instruction executed on the vcpu.
     *
     * @param enabled If set to true, the processor will single step instructions
     * @throws NotImplementedException if single stepping is not supported
     * @throws CommandFailedException If the hypervisor reports an error
     */
    virtual void single_step(bool enabled) = 0;

    /**
     * @brief Check if single stepping is enabled
     *
     * @return true if single stepping is enabled
     * @return false if single stepping is disabled
     */
    virtual bool single_step() const = 0;

    /**
     * @brief Get the file descriptor for polling events from this vcpu
     *
     * @return The file descriptor for polling if an event is ready
     * @throws NotImplementedException If vcpu-level event polling is not supported
     */
    virtual int event_fd() const;

    /**
     * @brief Get the pending event for this vcpu
     *
     * @return The pending event, or nullptr if no event is pending
     * @throws NotImplementedException If vcpu-level event polling is not supported
     * @throws CommandFailedException If the hypervisor reports an error
     */
    virtual std::unique_ptr<HypervisorEvent> event();

    /**
     * @brief Make sure system call intercepts can't be disabled while active
     */
    virtual void syscall_injection_start() = 0;

    /**
     * @brief Decrement system call injection counter
     */
    virtual void syscall_injection_end() = 0;

    // SECTEPE CEILING: backend-neutral syscall-filter modes. KVM maps these 1:1 to
    // KVM_SYSCALL_FILTER_* (static_assert'd in KvmVcpu.cc); other backends ignore
    // them. Defined here so windows/injection can pick a mode without including any
    // kvm header (layering).
    static constexpr uint32_t SYSCALL_FILTER_NONE = 0;
    static constexpr uint32_t SYSCALL_FILTER_THREAD_ID = 1;
    static constexpr uint32_t SYSCALL_FILTER_CR3 = 2;
    static constexpr uint32_t SYSCALL_FILTER_THREAD_OR_CR3 = 3;

    /**
     * @brief SECTEPE CEILING: program the per-vcpu syscall-hook emission filter so
     * the kernel only emits FAST_SYSCALL[_RET] events for the injecting thread /
     * address space, starving the ~6500-event flood that drives the head-#4 race.
     *
     * Default no-op: only the KVM backend implements it, and only when the patched
     * kernel advertises the ioctl (otherwise it latches unsupported and no-ops).
     * mode is KVM_SYSCALL_FILTER_* (ship THREAD_OR_CR3 only); deadline_ns is a
     * monotonic auto-revert backstop so a mis-keyed filter degrades to the flood,
     * never a hang.
     */
    virtual void set_syscall_filter(uint32_t mode, uint64_t thread_id, uint64_t cr3,
                                    uint64_t deadline_ns) {
        (void)mode;
        (void)thread_id;
        (void)cr3;
        (void)deadline_ns;
    }

    /**
     * @brief SECTEPE CEILING: clear any active syscall-hook emission filter
     * (revert to emit-all). Default no-op; KVM backend overrides.
     */
    virtual void clear_syscall_filter() {}

    SystemCallFilter& system_call_filter() override;
    const SystemCallFilter& system_call_filter() const override;

    x86::Segment segment(x86::SegmentSelector selector) const override;
    x86::SegmentDescriptorTable global_descriptor_table() const override;
    x86::SegmentDescriptorTable local_descriptor_table() const override;

    bool long_mode() const override;
    bool long_compatibility_mode() const override;

    std::unique_ptr<const x86::Idt> interrupt_descriptor_table() const override;

    const x86::Tss& task_state_segment() const override;

    uint32_t id() const override;

    Domain& domain() override;
    const Domain& domain() const override;

    /**
     * @brief Have the VCPU resume the currently active event
     */
    virtual void complete_event() = 0;

    /**
     * @brief Write the registers back to the hypervisor
     */
    virtual void write_registers() = 0;

    /**
     * @brief Destroy the instance
     */
    ~VcpuImpl() override;

    /**
     * @brief Move constructor
     */
    VcpuImpl(VcpuImpl&&) noexcept;

    /**
     * @brief Move constructor
     */
    VcpuImpl& operator=(VcpuImpl&&) noexcept;

  protected:
    /**
     * @brief Construct a new Vcpu object
     *
     * @param domain The domain this vcpu belongs to
     * @param id The id of this vcpu
     */
    VcpuImpl(Domain& domain, uint32_t id);

    /**
     * @brief Copy constructor
     */
    VcpuImpl(const VcpuImpl&);

  private:
    class IMPL;
    std::unique_ptr<IMPL> pImpl_;
};

} // namespace introvirt