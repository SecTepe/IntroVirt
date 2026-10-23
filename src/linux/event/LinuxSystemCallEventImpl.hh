/*
 * Copyright 2026 SecTepe.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 */
#pragma once

#include "core/event/SystemCallEventImpl.hh"
#include "linux/event/LinuxSystemCall.hh"
#include "linux/kernel/LinuxSyscalls.hh"
#include "linux/kernel/LinuxSyscallsArm64.hh"

#include <introvirt/core/arch/Architecture.hh>
#include <introvirt/core/arch/x86/Registers.hh>
#include <introvirt/core/domain/Vcpu.hh>
#include <introvirt/core/event/EventType.hh>
#include <introvirt/core/event/SystemCallEvent.hh>
#include <introvirt/core/syscall/SystemCall.hh>

#include <cstdint>
#include <memory>
#include <string>

namespace introvirt {
namespace linux_guest {

/**
 * @brief Linux fast-syscall event (mirrors WindowsSystemCallEventImpl).
 *
 * SystemCallEventImplTpl supplies instruction()/hook_return()/return_address()/
 * impl() from the hypervisor event. This adds the Linux specifics: raw_index
 * from the architecture-neutral syscall-number register (x86_64: RAX;
 * AArch64: x8), name() via the matching LinuxSyscalls/LinuxSyscallsArm64 table,
 * and a lazily-created LinuxSystemCall handler() that decodes the argument
 * registers (+ pathname strings) — what ivsyscallmon surfaces via
 * handler()->write()/json().
 */
class LinuxSystemCallEventImpl final : public SystemCallEventImplTpl<SystemCallEvent> {
  public:
    SystemCall* handler() override {
        const auto* const_this = this;
        return const_cast<SystemCall*>(const_this->handler());
    }
    const SystemCall* handler() const override {
        if (!system_call_)
            system_call_ = std::make_unique<LinuxSystemCall>(hypervisor_event_);
        return system_call_.get();
    }
    std::unique_ptr<SystemCall> release_handler() override { return std::move(system_call_); }
    void handler(std::unique_ptr<SystemCall>&& handler) override {
        system_call_ = std::move(handler);
    }

    uint64_t raw_index() const override { return raw_index_; }
    void raw_index(uint64_t value) override { raw_index_ = value; }

    std::string name() const override {
        return (arch_ == Architecture::aarch64)
                   ? LinuxSyscallsArm64::name(static_cast<uint32_t>(raw_index_))
                   : LinuxSyscalls::name(static_cast<uint32_t>(raw_index_));
    }

    explicit LinuxSystemCallEventImpl(HypervisorEvent& hypervisor_event)
        : SystemCallEventImplTpl<SystemCallEvent>(hypervisor_event) {
        // Read the syscall number through the architecture-neutral accessor
        // (x86_64: RAX; AArch64: x8) and remember the architecture so name()
        // picks the matching syscall table. See docs/introvirt-arm64.md.
        arch_ = hypervisor_event.vcpu().registers().architecture();
        if (hypervisor_event.type() == EventType::EVENT_FAST_SYSCALL)
            raw_index(hypervisor_event.vcpu().registers().syscall_number());
    }

  private:
    Architecture arch_ = Architecture::x86_64;
    uint64_t raw_index_ = 0;
    mutable std::unique_ptr<SystemCall> system_call_;
};

} // namespace linux_guest
} // namespace introvirt
