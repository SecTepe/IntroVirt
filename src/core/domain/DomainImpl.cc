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
#include "DomainImpl.hh"

#include "core/breakpoint/BreakpointImpl.hh"
#include "core/breakpoint/SingleStepImpl.hh"
#include "core/breakpoint/WatchpointImpl.hh"
#include "core/domain/VcpuImpl.hh"
#include "core/event/EventImpl.hh"
#include "core/event/NoOsEvent.hh"
#include "core/event/SystemCallEventImpl.hh"
#include "linux/LinuxGuestImpl.hh"
#include "windows/WindowsGuestImpl.hh"

#include <introvirt/core/domain/Vcpu.hh>
#include <introvirt/core/event/EventFilter.hh>
#include <introvirt/core/event/ThreadLocalEvent.hh>
#include <introvirt/core/exception/EventPollException.hh>
#include <introvirt/core/exception/GuestDetectionException.hh>
#include <introvirt/core/exception/InterruptedException.hh>
#include <introvirt/core/exception/MemoryException.hh>
#include <introvirt/core/exception/NotImplementedException.hh>
#include <introvirt/core/syscall/SystemCall.hh>
#include <introvirt/util/compiler.hh>
#include <introvirt/windows/WindowsGuest.hh>
#include <introvirt/windows/exception/IncorrectTypeException.hh>

#include <log4cxx/logger.h>

#include <cassert>
#include <cerrno>
#include <csignal>
#include <cstring>
#include <functional>
#include <pthread.h>
#include <sys/eventfd.h>
#include <thread>
#include <tuple>
#include <unistd.h>
#include <vector>

namespace introvirt {

static log4cxx::LoggerPtr logger(log4cxx::Logger::getLogger("introvirt.domain.Domain"));

inline static int poll_fds(struct pollfd* fds, int nfds, int timeout, uint32_t domain_id);

void DomainImpl::step_breakpoints(Event& event) {
    auto& vcpu = event.vcpu();

    // Let these guys clean everything up
    breakpoint_manager_.step(event);
    watchpoint_manager_.step(event);

    // Let the single step manager do some stuff
    single_step_manager_.handle_event(event);

    // Resume our other VCPUs
    resume_all_other_vcpus(vcpu);
}

void DomainImpl::handle_breakpoint(Event& event) {
    std::unique_ptr<Event> new_event;
    Event* working_event = &event;
    auto& vcpu = event.vcpu();

    // We only want one of these to happen at a time
    std::lock_guard lock(bp_mutex_);

    pause_all_other_vcpus(vcpu);

    bool deliver_events;
    {
        std::lock_guard lock(injection_tids_.mtx_);
        deliver_events = injection_tids_.set_.count(event.task().tid()) == 0;
    }

retry:
    bool step_required = false;

    switch (working_event->type()) {
    case EventType::EVENT_EXCEPTION:
        step_required |= breakpoint_manager_.handle_int3_event(*working_event, deliver_events);
        break;
    case EventType::EVENT_MEM_ACCESS:
        step_required |= watchpoint_manager_.handle_mem_event(*working_event);
        break;
    default:
        break;
    }

    if (step_required == false) {
        step_breakpoints(event);
        resume_all_other_vcpus(event.vcpu());
        return;
    }

    const uint64_t old_rip = vcpu.registers().rip();

    LOG4CXX_TRACE(logger, "Stepping VCPU " << vcpu.id());
    new_event = event.impl().step();
    working_event = new_event.get();

    LOG4CXX_TRACE(logger, "Stepped VCPU: " << new_event->type() << std::hex << " rip: 0x" << old_rip
                                           << "->0x" << vcpu.registers().rip());

    if (old_rip != vcpu.registers().rip())
        goto done;

    switch (working_event->type()) {
    case EventType::EVENT_SINGLE_STEP:
        LOG4CXX_WARN(logger, "Failed to step, received event " << working_event->type());
        break;
    case EventType::EVENT_EXCEPTION:
        LOG4CXX_TRACE(logger, "Step exception type: " << new_event->exception().vector());
        // Fall through
    case EventType::EVENT_MEM_ACCESS:
        // We're still not fixed, try again.
        goto retry;
    default:
        // Not sure why we didn't step.
        LOG4CXX_WARN(logger, "Failed to step, received event " << working_event->type());
        break;
    }

done:
    step_breakpoints(event);
    resume_all_other_vcpus(event.vcpu());
}

std::unique_ptr<Event>
DomainImpl::get_guest_event(std::unique_ptr<HypervisorEvent>&& hypervisor_event) {
    if (guest_) {
        // We have guest support, wrap the hypervisor event
        return guest_->impl().filter_event(std::move(hypervisor_event));
    } else {
        // No guest support.
        return std::make_unique<NoOsEvent>(std::move(hypervisor_event));
    }
}

std::unique_ptr<Event>
DomainImpl::filter_event(std::unique_ptr<HypervisorEvent>&& hypervisor_event) {
    auto& vcpu = hypervisor_event->vcpu();

    // Before we do anything, check if there is a stepping event for the current vcpu
    {
        std::lock_guard lock(stepping_events_.mtx_);
        Event* stepping_event = stepping_events_.by_vcpu_[vcpu.id()];

        if (unlikely(stepping_event != nullptr)) {
            LOG4CXX_DEBUG(logger, "Delivering stepping event for VCPU "
                                      << vcpu.id() << ": " << hypervisor_event->type());

            auto event = get_guest_event(std::move(hypervisor_event));
            stepping_events_.by_vcpu_[vcpu.id()] = nullptr;
            event->impl().discard(true);
            stepping_event->impl().wake_step(std::move(event));
            return nullptr;

            // Note that the only things using this are breakpoint/watchpoint
            // managers. If there is a suspended thread for syscall/function
            // injection, it will still be woken up on this event, below, but in
            // another thread!
        }
    }

    // Check if there is another thread pending for this thread
    {
        std::unique_lock lock(suspended_events_.mtx_);
        if (guest_) {
            // SECTEPE head#4 (the REAL strand fix, part 1): get_current_thread_id reads
            // KPCR.current_thread_address. Post-reschedule of a heavy injected syscall
            // (NtCreateUserProcess / NtResumeThread) the injecting vcpu's KPCR page can be
            // momentarily NON-PRESENT (KPTI user CR3) or yield a bad type index, throwing
            // MemoryException / IncorrectTypeException. For a genuine FAST_SYSCALL_RET this
            // must NOT escape filter_event: the RET is a unique_ptr moved into this scope
            // and would self-complete via ~KvmEvent on unwind, stranding the suspended
            // injector (created-but-not-resumed). Swallow ONLY for FAST_SYSCALL_RET (both
            // bad-read families, mirroring the poller-skip catch set) and fall through to
            // the FAST_SYSCALL_RET fallback below, which offers the RET to injector waiters
            // by RIP/RSP. Any other event type rethrows (the poller-skip already catches
            // both families, so no behavior change).
            uint64_t thread_id = 0;
            bool tid_ok = true;
            try {
                thread_id = guest_->impl().get_current_thread_id(vcpu);
            } catch (const MemoryException&) {
                if (hypervisor_event->type() != EventType::EVENT_FAST_SYSCALL_RET)
                    throw;
                tid_ok = false;
            } catch (const windows::IncorrectTypeException&) {
                if (hypervisor_event->type() != EventType::EVENT_FAST_SYSCALL_RET)
                    throw;
                tid_ok = false;
            }
            // When tid_ok is false the range is empty, the keyed block is skipped, and
            // control falls through to the FAST_SYSCALL_RET fallback with hypervisor_event
            // still valid (the release() reclaim below is only reached on a non-empty range).
            auto callbacks = tid_ok ? suspended_events_.map_.equal_range(thread_id)
                                    : std::make_pair(suspended_events_.map_.end(),
                                                     suspended_events_.map_.end());
            if (callbacks.first != callbacks.second) {
                auto event = get_guest_event(std::move(hypervisor_event));
                WakeAction action;

                for (auto iter = callbacks.first; iter != callbacks.second; ++iter) {
                    action = iter->second->impl().wake(std::move(event));

                    switch (action) {
                    case WakeAction::ACCEPT:
                        suspended_events_.map_.erase(iter);
                        // Fall through
                    case WakeAction::DROP:
                        goto out;
                    case WakeAction::PASS:
                        // Let other stuff handle it
                        break;
                    }
                }

            out:
                if (action != WakeAction::PASS) {
                    if (event.get()) {
                        // If it's a breakpoint event, pass it through anyway.
                        // Callbacks won't be delivered, but we need to fix up the INT3.
                        switch (event->type()) {
                        case EventType::EVENT_EXCEPTION:
                            if (event->exception().vector() != x86::Exception::INT3)
                                break;
                        // Fall through
                        case EventType::EVENT_MEM_ACCESS:
                            return event;
                        default:
                            break;
                        }
                    }
                    return nullptr;
                } else {
                    hypervisor_event = event->impl().release();
                    hypervisor_event->discard(false);
                }
            }
        }
    }

    if (hypervisor_event->type() == EventType::EVENT_CR_WRITE) {
        // Verify the VCPU is configured to want it
        if (!hypervisor_event->vcpu().intercept_cr_writes(hypervisor_event->control_register())) {
            return nullptr;
        }
    }

    if (hypervisor_event->type() == EventType::EVENT_FAST_SYSCALL_RET) {
        // SECTEPE: a FAST_SYSCALL_RET that NO thread_id-keyed suspended injector
        // claimed above. A heavy injected syscall (e.g. NtCreateUserProcess) can make
        // the guest reschedule, so at the return the vcpu's current thread
        // (KPCR.current_thread, used for the keying above) is a DIFFERENT KTHREAD than
        // the injected one -- equal_range(thread_id) misses and the return would be
        // DROPPED here, stranding the suspended injector (its suspend() cv never wakes
        // -> chain stalls -> "miss"). Before dropping, offer it to ALL suspended
        // injectors; each one's wake lambda matches by its own captured return RIP/RSP
        // (the RET fires in the injected thread's context, so its rip == the
        // injection's return address even when the KPCR keying is stale) and PASSes if
        // not theirs. PURE FALLBACK: only runs for an otherwise-dropped
        // FAST_SYSCALL_RET, so the normal tid-matched path (Win10/Linux) is unchanged.
        {
            std::unique_lock lock(suspended_events_.mtx_);
            if (!suspended_events_.map_.empty()) {
                // SECTEPE head#4 (the REAL strand fix, part 2): two-phase fan-out.
                //
                // PHASE 1 -- INJECTOR waiters only: offer a REGISTER-ONLY NoOsEvent. The
                // injector wake lambdas (syscall/function/page_fault) read ONLY vcpu
                // registers (rip/rsp) and event.type(), never task/pcr/CurrentThread, so a
                // task-less NoOsEvent is sufficient AND avoids the eager KPCR read that
                // throws when the post-reschedule KPCR page is non-present (the original
                // strand cause -- get_guest_event below would throw and the RET would
                // self-complete on unwind). NoOsEvent's ctor materializes no task, so it
                // cannot throw here. DROP is treated as PASS in this fan-out: only
                // function.hh/page_fault.hh return DROP for a FAST_SYSCALL_RET (their
                // lambda's default arm; they do not own it -- their EVENT_EXCEPTION guard
                // is false for a RET), and the syscall injector that DOES own a RET returns
                // only ACCEPT/PASS. So DROP must not swallow the RET before the owning
                // injector is visited. hook_return waiters (plain suspend(), flag false)
                // are SKIPPED here -- they legitimately deref the return event as a
                // WindowsEvent (process_event), so a NoOsEvent must never reach them.
                auto event = std::unique_ptr<Event>(
                    std::make_unique<NoOsEvent>(std::move(hypervisor_event)));
                bool consumed = false;
                for (auto iter = suspended_events_.map_.begin();
                     iter != suspended_events_.map_.end(); ++iter) {
                    if (!iter->second->impl().is_injection_suspend())
                        continue; // hook_return waiter -> Phase 2 only
                    const WakeAction action = iter->second->impl().wake(std::move(event));
                    if (action == WakeAction::ACCEPT) {
                        suspended_events_.map_.erase(iter);
                        consumed = true;
                        break;
                    }
                    // DROP -> PASS: wake() only moves `event` out on ACCEPT, so on PASS/DROP
                    // it is still valid -- keep iterating to the owning injector.
                }
                if (consumed)
                    return nullptr;

                // No injector matched. Reclaim the hypervisor_event from the un-consumed
                // NoOsEvent (release() moves it back out; the spent NoOsEvent then holds a
                // null hypervisor_event_ and is destroyed harmlessly).
                hypervisor_event = event->impl().release();

                // PHASE 2 -- hook_return waiters: build the EAGER (task-bearing)
                // WindowsEvent and offer it. hook_return waiters legitimately deref the
                // return event as a WindowsEvent (process_event -> task()/syscall()), so
                // they must receive the eager event, never the NoOsEvent. If the eager
                // build throws (non-present KPCR / bad type index), the catch drops the
                // event == today's no-regression worst case (identical to the poller-skip).
                try {
                    auto eager = get_guest_event(std::move(hypervisor_event));
                    for (auto iter = suspended_events_.map_.begin();
                         iter != suspended_events_.map_.end(); ++iter) {
                        if (iter->second->impl().is_injection_suspend())
                            continue; // already offered in Phase 1
                        const WakeAction action = iter->second->impl().wake(std::move(eager));
                        if (action == WakeAction::ACCEPT) {
                            suspended_events_.map_.erase(iter);
                            return nullptr;
                        }
                        if (action == WakeAction::DROP)
                            return nullptr;
                        // PASS: eager not moved; try the next hook_return waiter.
                    }
                } catch (const MemoryException&) {
                    return nullptr; // non-present KPCR during eager build -> drop (== today)
                } catch (const windows::IncorrectTypeException&) {
                    return nullptr; // bad type index during eager build -> drop (== today)
                }
            }
        }
        // This would've been handled by a suspended thread above
        return nullptr;
    }

    std::unique_ptr<Event> event;

    // Filter out system calls that we don't want
    if (hypervisor_event->type() == EventType::EVENT_FAST_SYSCALL) {
        if (!vcpu.intercept_system_calls())
            return nullptr;

        /*
         * The correct operation here is to check the vcpu syscall filter first.
         * If that matches, just return true. Otherwise check the domain filter.
         */
        if (!matches_syscall_filters(vcpu))
            return nullptr;

        // Matches our filter, jump down to test the task filter
        event = get_guest_event(std::move(hypervisor_event));
        goto check_task_filter;
    }

    event = get_guest_event(std::move(hypervisor_event));

    switch (event->type()) {
    case EventType::EVENT_EXCEPTION:
        if (event->exception().vector() != x86::Exception::INT3)
            break;
    // Fall through
    case EventType::EVENT_MEM_ACCESS:
        // Don't check the task filter for breakpoint and mem_access events
        return event;
    default:
        break;
    }

check_task_filter:

    // Return the result if it matches our task filter
    if (task_filter_.matches(*event)) {
        return event;
    }

    return nullptr;
}

void DomainImpl::pause() {
    for (uint32_t i = 0; i < vcpu_count(); ++i) {
        vcpu(i).pause();
    }
}

void DomainImpl::resume() {
    for (uint32_t i = 0; i < vcpu_count(); ++i) {
        vcpu(i).resume();
    }
}

bool DomainImpl::detect_guest() {
    uint64_t efd_init = 0;
    if (unlikely(::write(efd_, &efd_init, sizeof(efd_init)) < 0)) {
        LOG4CXX_ERROR(logger, "Failed to clear eventfd");
    }

    std::unique_lock<std::shared_mutex> lock(event_filter_mtx_);

    LOG4CXX_DEBUG(logger, "Attempting OS detection...");

    // SECTEPE: clear any prior KPTI kernel-CR3 hint; repopulated below from the
    // first CR3-WRITE event whose written value maps the kernel.
    detect_cr3_hint_ = 0;

    pause();

    // Save the previous state
    std::vector<bool> vcpu_syscall_intercept;
    std::vector<bool> vcpu_cr3_intercept;
    for (uint32_t i = 0; i < vcpu_count(); ++i) {
        vcpu_syscall_intercept.push_back(vcpu(i).intercept_system_calls());
        vcpu_cr3_intercept.push_back(vcpu(i).intercept_cr_writes(3));
        vcpu(i).intercept_system_calls(false);
        vcpu(i).intercept_cr_writes(3, false);
    }
    // SECTEPE (KPTI): intercept CR3 writes on EVERY vcpu (not just vcpu0). Under
    // KPTI the guest loads the kernel CR3 on every syscall/interrupt entry
    // (SWITCH_TO_KERNEL_CR3); intercepting all vcpus maximises the chance of
    // catching such a write during the busy boot window when no vcpu is observed
    // already in kernel mode.
    for (uint32_t i = 0; i < vcpu_count(); ++i)
        vcpu(i).intercept_cr_writes(3, true);

    resume();

    bool result = false;

    try {
        for (int tries = 15; tries > 0; --tries) {
            // Poll for an event
            if (::poll(pollfds_.data(), pollfds_.size(), 5000) > 0) {

                // Check if we're interrupted
                if (pollfds_[pollfds_.size() - 1].revents & POLLIN) {
                    // Interrupted!
                    return false;
                }

                // An event is ready.
                // Determine which vcpu is ready
                for (uint32_t i = 0; i < pollfds_.size(); ++i) {
                    struct pollfd& fd_entry = pollfds_[i];
                    if (fd_entry.revents & POLLIN) {
                        // This vcpu has an active event
                        auto& v = static_cast<VcpuImpl&>(vcpu(i));
                        auto event = reinterpret_cast<VcpuImpl&>(v).event();
                        if (!event)
                            continue;

                        // SECTEPE (KPTI): if this woke us on a CR3 write, the value
                        // being loaded maps the kernel whenever the guest just ran
                        // SWITCH_TO_KERNEL_CR3 (syscall/interrupt entry). Capture it
                        // so NtKernelImpl can scan the kernel base through a
                        // kernel-mapping CR3 even when every vcpu is in user mode.
                        // registers().cr3() here is still the OLD (user) value -- the
                        // CR-write VM-exit fires before the write commits.
                        if (event->type() == EventType::EVENT_CR_WRITE &&
                            event->control_register() == 3) {
                            detect_cr3_hint_ = event->control_register_value();
                        }

                        const bool is64bit = v.registers().efer().lme();
                        page_directory_.reconfigure(v);

                        // Try a Windows guest
                        try {
                            using namespace windows;

                            if (is64bit)
                                guest_ = std::make_unique<WindowsGuestImpl<uint64_t>>(*this);
                            else
                                guest_ = std::make_unique<WindowsGuestImpl<uint32_t>>(*this);

                            result = true;
                            goto done;
                        } catch (GuestDetectionException& ex) {
                            LOG4CXX_DEBUG(logger, "Failed to detect WindowsGuest: " << ex);
                        }

                        // Try a Linux guest (x86_64 only for now). This only
                        // succeeds when a matching SecTepe Linux profile is
                        // configured ($INTROVIRT_LINUX_PROFILE) and its
                        // linux_banner verifies against the live kernel — so it
                        // is a no-op for Windows guests and for hosts without a
                        // Linux profile.
                        if (is64bit) {
                            try {
                                guest_ = std::make_unique<linux_guest::LinuxGuestImpl>(*this);
                                result = true;
                                goto done;
                            } catch (GuestDetectionException& ex) {
                                LOG4CXX_DEBUG(logger, "Failed to detect LinuxGuest: " << ex);
                            }
                        }

                        // SECTEPE (KPTI): both guest constructions failed for THIS
                        // event. Complete it so the vcpu RESUMES and runs on to its
                        // next CR3 write -- otherwise it stays halted in-event and the
                        // remaining poll retries see no new events (they only ever
                        // sampled this one CR3 write, so a user-CR3 first event failed
                        // the whole window). Completing lets detection walk through
                        // successive CR3 writes until a SWITCH_TO_KERNEL_CR3 supplies a
                        // kernel-mapping CR3 (captured into detect_cr3_hint_) even when
                        // every vcpu is in user mode for the entire detection window.
                        v.complete_event();
                    }
                }
            }
        }
    } catch (TraceableException& ex) {
        LOG4CXX_ERROR(logger, "Failed to detect OS: " << ex);
    }

done:

    // Restore the original state
    for (uint32_t i = 0; i < vcpu_count(); ++i) {
        vcpu(i).intercept_system_calls(vcpu_syscall_intercept[i]);
        vcpu(i).intercept_cr_writes(3, vcpu_cr3_intercept[i]);
    }

    return result;
}

Guest* DomainImpl::guest() { return guest_.get(); }
const Guest* DomainImpl::guest() const { return guest_.get(); }

GuestImpl* DomainImpl::page_fault_guest() const {
    // During detect_guest() the under-construction WindowsGuestImpl registers itself
    // here (guest_ is not assigned until construction succeeds); prefer it so
    // PageDirectory::translate can resolve transition/standby PTEs during detection.
    if (detection_pf_guest_)
        return detection_pf_guest_;
    return guest_ ? &guest_->impl() : nullptr;
}

void DomainImpl::intercept_system_calls(bool enabled) {
    for (unsigned int i = 0; i < vcpu_count(); ++i) {
        vcpu(i).intercept_system_calls(enabled);
    }
}

void DomainImpl::intercept_cr_writes(int cr, bool enabled) {
    for (unsigned int i = 0; i < vcpu_count(); ++i) {
        vcpu(i).intercept_cr_writes(cr, enabled);
    }
}

void DomainImpl::interrupt() {
    LOG4CXX_DEBUG(logger,
                  "Domain " << id() << " interrupted - Injection Count: " << injection_.count_);

    // Wait for no injection threads to be active
    std::unique_lock lock(injection_.mtx_);
    injection_.cv_.wait(lock, [this] { return injection_.count_ == 0; });

    // Notify managers
    breakpoint_manager_.interrupt();
    watchpoint_manager_.interrupt();
    single_step_manager_.interrupt();

    // Interrupt all of our threads
    interrupted_ = true;
    const uint64_t value = vcpu_count();
    if (unlikely(::write(efd_, &value, sizeof(value)) < 0)) {
        LOG4CXX_ERROR(logger, "Failed to notify eventfd");
    }
}

inline bool DomainImpl::matches_syscall_filters(const Vcpu& vcpu) const {
    /*
     * The correct operation here is to check the vcpu syscall filter first.
     * If that matches, just return true. Otherwise check the domain filter.
     */

    if (!vcpu.system_call_filter().enabled() || !vcpu.system_call_filter().matches(vcpu)) {
        if (system_call_filter().enabled() && !system_call_filter().matches(vcpu)) {
            return false;
        }
    }
    return true;
}

struct worker_thread_info {
    std::thread thread;
    std::mutex mtx;
    std::unique_ptr<Event> event;
    std::atomic_bool completed = false;
};

void DomainImpl::event_deliverer(EventCallback* callback, struct worker_thread_info* worker_info) {
restart:
    DomainImpl::thread_local_domain(*this);
    Event* event = worker_info->event.get();
    ThreadLocalEvent::set(*event);

    try {
        switch (event->type()) {
        case EventType::EVENT_EXCEPTION:
            if (event->exception().vector() != x86::Exception::INT3)
                break;
        // Fall through
        case EventType::EVENT_MEM_ACCESS:
            handle_breakpoint(*event);
            goto done;
        case EventType::EVENT_SINGLE_STEP:
            /*
             * SECTEPE (W4.1 step trace): a Monitor Trap Flag exit while a
             * Domain::single_step() handle is live belongs to its callback. Until
             * now only the step a breakpoint takes over its own int3 reached the
             * SingleStepManager (via handle_breakpoint), so a SingleStep callback
             * fired once and the trap flag then fed bare EVENT_SINGLE_STEP events
             * to the tool. A step on a vcpu nobody steps still goes to the tool,
             * as before.
             */
            if (single_step_manager_.stepping(event->vcpu())) {
                single_step_manager_.handle_event(*event);
                goto done;
            }
            break;
        default:
            break;
        }

        if (event)
            callback->process_event(*event);

        if (event->type() == EventType::EVENT_FAST_SYSCALL) {

            if (event->impl().injection_performed()) {
                // If injection was performed, RIP was changed, so the instruction will not be
                // emulated automatically. We don't want to intercept the system call again, so we
                // need to inject a final system call to put the event back into the right state.
                switch (event->syscall().instruction()) {
                case FastCallType::FASTCALL_SYSCALL:
                    static_cast<VcpuImpl&>(event->vcpu()).inject_syscall();
                    /*
                     * This is necessary because SYSCALL can be either
                     * two or three bytes (REX prefix optional). By saving it and manually,
                     * loading it into RCX after the system call, we don't have to care about
                     * how the original instruction was executed.
                     */
                    event->vcpu().registers().rcx(event->syscall().return_address());
                    break;
                case FastCallType::FASTCALL_SYSENTER:
                    static_cast<VcpuImpl&>(event->vcpu()).inject_sysenter();
                    /*
                     * The return address for SYSENTER is held on the stack, so
                     * we don't have to do any trickery to fix it up here.
                     */
                    break;
                default:
                    LOG4CXX_WARN(logger,
                                 "Unknown system call type, unable to perform final injection");
                }
            }

            if (event->syscall().hook_return()) {
                if (event->syscall().handler() && event->syscall().handler()->will_return()) {

                    // Bad naming here, but we want to prevent system calls from being turned off
                    static_cast<VcpuImpl&>(event->vcpu()).syscall_injection_start();

                    const uint64_t return_rsp = event->vcpu().registers().rsp();
                    const uint64_t tid = event->task().tid();

                    // Wait for a return for this thread
                    auto return_event = event->impl().suspend(
                        [&event, return_rsp, tid](const introvirt::Event& new_event) {
                            if (new_event.type() == EventType::EVENT_FAST_SYSCALL_RET &&
                                new_event.vcpu().registers().rsp() == return_rsp) {
                                return WakeAction::ACCEPT;
                            }
                            // This is not necessarily a bug, but can happen when the kernel
                            // runs stuff in the context of the thread that is suspended.
                            LOG4CXX_TRACE(logger, "TID " << tid << " Incorrect return rsp: 0x"
                                                         << std::hex
                                                         << new_event.vcpu().registers().rsp()
                                                         << " Wanted 0x" << return_rsp);
                            return WakeAction::PASS;
                        });
                    event->impl().discard(true);
                    return_event->impl().discard(false);

                    // It's okay for system calls to be disabled now
                    static_cast<VcpuImpl&>(event->vcpu()).syscall_injection_end();

                    // If we see a system call event, we somehow missed the return.
                    // Check if it matches the filter and deliver it.
                    if (return_event->type() == EventType::EVENT_FAST_SYSCALL) {
                        LOG4CXX_DEBUG(logger, "Missed a system call return for "
                                                  << event->syscall().name());

                        event->impl().discard(true);
                        worker_info->event = std::move(return_event);

                        auto& vcpu = event->vcpu();
                        if (!vcpu.intercept_system_calls())
                            goto done;

                        /*
                         * The correct operation here is to check the vcpu syscall filter first.
                         * If that matches, just return true. Otherwise check the domain filter.
                         */
                        if (matches_syscall_filters(vcpu))
                            goto restart;

                        goto done;
                    }

                    // Set the system call index from the original call
                    return_event->syscall().impl().raw_index(event->syscall().raw_index());

                    // Take the handler out of the original event
                    auto handler = event->syscall().impl().release_handler();

                    // Give it the new data
                    handler->handle_return_event(*return_event);

                    // Pass it in to the new event
                    return_event->syscall().impl().handler(std::move(handler));

                    // Deliver the event
                    ThreadLocalEvent::set(*return_event);
                    callback->process_event(*return_event);
                }
            }
        }

    } catch (InterruptedException& ex) {
        LOG4CXX_DEBUG(logger,
                      "Vcpu " << event->vcpu().id() << " thread interrupted while suspended");
    } catch (TraceableException& ex) {
        LOG4CXX_WARN(logger, "Vcpu " << event->vcpu().id()
                                     << " poller threw an exception during delivery: " << ex);
        interrupt();
    }

done:
    std::lock_guard lock(worker_info->mtx);
    worker_info->event.reset();
    worker_info->completed = true;
}

void DomainImpl::vcpu_poller_thread(Vcpu* ivcpu, EventCallback* callback, int efd) {
    VcpuImpl& vcpu = reinterpret_cast<VcpuImpl&>(*ivcpu);
    DomainImpl::thread_local_domain(*this);

    struct pollfd fd_entries[2];
    std::list<worker_thread_info> threads;

    /*
     * SECTEPE: count consecutive un-buildable events skipped below. A single
     * transient skip (the expected case for the injection race) stays quiet at
     * DEBUG, but a vcpu that keeps failing to build events is escalated to a
     * throttled WARN so a non-transient bad state is visible even when DEBUG
     * logging is disabled, instead of silently spinning. Reset on the first
     * successfully built event. This counter is private to this poller thread
     * (one per vcpu), so no synchronization is needed.
     */
    uint64_t consecutive_skips = 0;
    static constexpr uint64_t kSkipWarnEvery = 1000;

    fd_entries[0].fd = vcpu.event_fd();
    fd_entries[0].events = POLLIN;

    fd_entries[1].fd = efd;
    fd_entries[1].events = POLLIN;

    while (true) {
        try {
            if (poll_fds(fd_entries, 2, -1, vcpu.id()) > 0) {

                // Check if the interrupt fd has been triggered
                if (unlikely(fd_entries[1].revents & POLLIN)) {
                    // Interrupted!
                    LOG4CXX_DEBUG(logger, "Thread " << std::hex << std::this_thread::get_id()
                                                    << ": Interrupted by eventfd");

                    // Interrupt all suspended threads
                    for (auto& entry : threads) {
                        std::lock_guard lock(entry.mtx);
                        if (!entry.completed) {
                            entry.event->impl().interrupt();
                            LOG4CXX_DEBUG(logger, "Interrupted suspended thread");
                        }
                    }

                    break;
                }

                // Check if the vcpu has an event
                if (likely(fd_entries[0].revents & POLLIN)) {
                    std::unique_ptr<HypervisorEvent> hypervisor_event = vcpu.event();

                    if (unlikely(hypervisor_event == nullptr))
                        continue;

                    /*
                     * SECTEPE: poller-skip for racy bad reads while building the
                     * next event.
                     *
                     * filter_event() eagerly materializes the current THREAD for
                     * THIS vcpu (WindowsEventTaskInformation ctor -> KPCR::reset()
                     * -> kernel_.thread(current_thread_ptr)). If this vcpu is
                     * mid-context-switch, or in user mode under KPTI where
                     * KernelDirectoryTableBase is absent and reset() falls back to
                     * the user CR3, current_thread_address() can yield a
                     * garbage/non-canonical pointer. Reading a THREAD/OBJECT_HEADER
                     * through it throws IncorrectTypeException (bad type index) or a
                     * MemoryException (e.g. VirtualAddressNotPresentException on a
                     * non-canonical VA). This race is observable on an idle/other
                     * vcpu while we inject a syscall (e.g. NtCreateUserProcess) on a
                     * different vcpu; left uncaught it escapes the poller loop and
                     * std::terminate()s the whole session.
                     *
                     * Such an event is, by definition, un-buildable: there is no
                     * Event to deliver. Skip ONLY this event and keep polling.
                     *
                     * Scope is deliberately narrow: KPCRs are per-vcpu
                     * (NtKernelImpl::kpcr indexes by vcpu.id()), so a failed reset()
                     * here only touches THIS vcpu's KPCR/os_data and never the
                     * injecting vcpu's state. The injector waits on its own
                     * condition variable (EventImplTpl::suspend) and is woken by the
                     * suspended-thread fast path in DomainImpl::filter_event for ITS
                     * OWN thread; at syscall-return the injecting vcpu is in the
                     * kernel with a valid current-thread, so that delivery does not
                     * hit this path. Dropping a racy event on another vcpu therefore
                     * never drops an event the injector or the tool needs to
                     * progress.
                     *
                     * We catch only MemoryException and IncorrectTypeException (the
                     * confirmed bad-guest-read families) rather than the whole
                     * TraceableException hierarchy, so genuinely fatal control-flow
                     * exceptions (GuestDetectionException, EventPollException, etc.)
                     * are NOT swallowed and cannot make the loop spin silently.
                     */
                    std::unique_ptr<Event> event;
                    try {
                        event = filter_event(std::move(hypervisor_event));
                    } catch (const MemoryException& ex) {
                        if (unlikely(++consecutive_skips % kSkipWarnEvery == 0)) {
                            LOG4CXX_WARN(logger,
                                         "Vcpu " << vcpu.id() << " skipped " << consecutive_skips
                                                 << " consecutive un-buildable events; latest (bad "
                                                    "guest read): "
                                                 << ex);
                        } else {
                            LOG4CXX_DEBUG(logger, "Vcpu " << vcpu.id()
                                                          << " skipping un-buildable event (bad "
                                                             "guest read): "
                                                          << ex);
                        }
                        continue;
                    } catch (const windows::IncorrectTypeException& ex) {
                        if (unlikely(++consecutive_skips % kSkipWarnEvery == 0)) {
                            LOG4CXX_WARN(logger,
                                         "Vcpu " << vcpu.id() << " skipped " << consecutive_skips
                                                 << " consecutive un-buildable events; latest (bad "
                                                    "type index): "
                                                 << ex);
                        } else {
                            LOG4CXX_DEBUG(logger, "Vcpu " << vcpu.id()
                                                          << " skipping un-buildable event (bad "
                                                             "type index): "
                                                          << ex);
                        }
                        continue;
                    }

                    // Built an event successfully: clear the skip streak.
                    consecutive_skips = 0;

                    if (!event)
                        continue;

                    try {
                        worker_thread_info& entry = threads.emplace_back();
                        entry.event = std::move(event);
                        entry.thread =
                            std::thread(&DomainImpl::event_deliverer, this, callback, &entry);

                    } catch (TraceableException& ex) {
                        LOG4CXX_WARN(logger, "Domain " << name() << " Vcpu " << vcpu.id()
                                                       << " poller threw an exception: " << ex);
                        break;
                    }
                }
            }

            // Expire dead threads
            for (auto iter = threads.begin(); iter != threads.end();) {
                auto& entry = *iter;

                std::unique_lock lock(entry.mtx, std::try_to_lock);
                if (lock.owns_lock() && entry.completed) {
                    if (entry.thread.joinable())
                        entry.thread.join();

                    lock.unlock();
                    iter = threads.erase(iter);
                } else {
                    ++iter;
                }
            }
        } catch (EventPollException& ex) {
            LOG4CXX_WARN(logger, "Vcpu " << vcpu.id() << " poll exception");
            vcpu.domain().interrupt();
            break;
        }
    }

    // Wait for all threads to exit
    for (auto& entry : threads) {
        if (entry.thread.joinable())
            entry.thread.join();
    }
}

void DomainImpl::poll(EventCallback& callback) {
    uint64_t efd_init = 0;
    if (unlikely(::write(efd_, &efd_init, sizeof(efd_init)) < 0)) {
        LOG4CXX_ERROR(logger, "Failed to clear eventfd");
    }
    interrupted_ = false;

    // Block all signals for our threads
    sigset_t oldset;
    sigset_t set = {};
    sigfillset(&set);
    pthread_sigmask(SIG_SETMASK, &set, &oldset);

    // Create a thread for each Vcpu
    std::vector<std::thread> pollers_threads;
    for (uint32_t i = 0; i < vcpu_count(); ++i) {
        VcpuImpl& v = static_cast<VcpuImpl&>(vcpu(i));
        pollers_threads.emplace_back(&DomainImpl::vcpu_poller_thread, this, &v, &callback, efd_);
        LOG4CXX_DEBUG(logger, "Domain " << id() << ": Started event poller thread 0x" << std::hex
                                        << pollers_threads.back().native_handle());
    }

    // Restore signals for this thread
    pthread_sigmask(SIG_SETMASK, &oldset, nullptr);

    // Wait for all of the threads to finish
    for (std::thread& thread : pollers_threads) {
        thread.join();
    }
}

void DomainImpl::initialize() {
    {
        auto& vcpu0 = vcpu(0);
        vcpu0.pause();
        page_directory_.reconfigure(vcpu0);
        vcpu0.resume();
    }

    try {
        for (uint32_t i = 0; i < vcpu_count(); ++i) {
            struct pollfd fd_entry;
            fd_entry.fd = static_cast<VcpuImpl&>(vcpu(i)).event_fd();
            fd_entry.events = POLLIN;
            fd_entry.revents = 0;
            pollfds_.push_back(fd_entry);

            stepping_events_.by_vcpu_.push_back(nullptr);
        }
        // Add the eventfd descriptor
        struct pollfd fd_entry;
        fd_entry.fd = efd_;
        fd_entry.events = POLLIN;
        fd_entry.revents = 0;
        pollfds_.push_back(fd_entry);
    } catch (NotImplementedException& ex) {
        // The base class should be overriding poll() if this happens
        LOG4CXX_ERROR(logger, "Domain " << id() << " does not support VCPU level polling");
        throw;
    }
}

TaskFilter& DomainImpl::task_filter() { return task_filter_; }

SystemCallFilter& DomainImpl::system_call_filter() { return system_call_filter_; }
const SystemCallFilter& DomainImpl::system_call_filter() const { return system_call_filter_; }

void DomainImpl::pause_all_other_vcpus(const Vcpu& v) {
    for (uint32_t i = 0; i < vcpu_count(); ++i) {
        if (i != v.id())
            vcpu(i).pause();
    }
}
void DomainImpl::resume_all_other_vcpus(const Vcpu& v) {
    for (uint32_t i = 0; i < vcpu_count(); ++i) {
        if (i != v.id())
            vcpu(i).resume();
    }
}

std::shared_ptr<Breakpoint> DomainImpl::create_breakpoint(const guest_ptr<void>& address,
                                                          std::function<void(Event&)> callback) {

    auto result = std::make_shared<BreakpointImpl>(address, callback);
    breakpoint_manager_.add_ref(result);
    return result;
}

std::unique_ptr<Watchpoint> DomainImpl::create_watchpoint(const guest_ptr<void>& address,
                                                          uint64_t length, bool read, bool write,
                                                          bool execute,
                                                          std::function<void(Event&)> callback) {
    auto result = std::make_unique<WatchpointImpl>(address, length, read, write, execute, callback);
    watchpoint_manager_.add_ref(*result);
    return result;
}

std::unique_ptr<SingleStep> DomainImpl::single_step(Vcpu& vcpu,
                                                    std::function<void(Event&)> callback) {
    auto result = std::make_unique<SingleStepImpl>(vcpu, callback);
    single_step_manager_.add_ref(*result);
    return result;
}

BreakpointManager& DomainImpl::breakpoint_manager() { return breakpoint_manager_; }
SingleStepManager& DomainImpl::single_step_manager() { return single_step_manager_; }
WatchpointManager& DomainImpl::watchpoint_manager() { return watchpoint_manager_; }

void DomainImpl::start_injection(Event& event) {
    if (unlikely(interrupted_)) {
        throw InterruptedException();
    }

    {
        std::lock_guard lock(injection_tids_.mtx_);
        auto [iter, inserted] = injection_tids_.set_.insert(event.task().tid());
        introvirt_assert(inserted, "");
    }

    LOG4CXX_DEBUG(logger, "Starting injection on TID " << event.task().tid()
                                                       << " Event Type: " << event.type());

    std::lock_guard lock(injection_.mtx_);
    if (unlikely(interrupted_))
        throw InterruptedException();
    injection_.count_++;

    breakpoint_manager_.start_injection();

    switch (event.type()) {
    case EventType::EVENT_EXCEPTION:
        if (event.exception().vector() != x86::Exception::INT3)
            break;
        // Fall through
    case EventType::EVENT_MEM_ACCESS:
        resume_all_other_vcpus(event.vcpu());
        bp_mutex_.unlock();
        break;
    default:
        break;
    }
}

void DomainImpl::end_injection(Event& event) {
    {
        std::lock_guard lock(injection_tids_.mtx_);
        LOG4CXX_DEBUG(logger, "Searching for injection on TID " << event.task().tid());
        auto iter = injection_tids_.set_.find(event.task().tid());
        introvirt_assert(iter != injection_tids_.set_.end(), "");
        injection_tids_.set_.erase(iter);
    }

    LOG4CXX_DEBUG(logger, "Ending injection on TID " << event.task().tid()
                                                     << " Event Type: " << event.type());

    switch (event.type()) {
    case EventType::EVENT_EXCEPTION:
        if (event.exception().vector() != x86::Exception::INT3)
            break;
        // Fall through
    case EventType::EVENT_MEM_ACCESS:
        bp_mutex_.lock();
        pause_all_other_vcpus(event.vcpu());
        break;
    default:
        break;
    }

    std::lock_guard lock(injection_.mtx_);
    breakpoint_manager_.end_injection();

    injection_.count_--;
    introvirt_assert(injection_.count_ >= 0, "");
    if (injection_.count_ == 0) {
        injection_.cv_.notify_all();
    }
}

void DomainImpl::suspend_event(Event& event) {
    std::lock_guard lock(suspended_events_.mtx_);
    suspended_events_.map_.insert(std::make_pair(event.impl().thread_id(), &event));
    LOG4CXX_TRACE(logger,
                  "Added thread 0x" << std::hex << event.impl().thread_id() << " to suspend map");
}

void DomainImpl::suspend_event_step(Event& event) {
    std::lock_guard lock(stepping_events_.mtx_);
    stepping_events_.by_vcpu_[event.vcpu().id()] = &event;
    LOG4CXX_TRACE(logger, "Added VCPU " << event.vcpu().id() << " to step suspend map");
}

const x86::PageDirectory& DomainImpl::page_directory() const { return page_directory_; }

const PageTableWalker& DomainImpl::page_table_walker() const { return page_directory_; }

DomainImpl::DomainImpl()
    : watchpoint_manager_(), breakpoint_manager_(), page_directory_(*this),
      efd_(eventfd(0, EFD_SEMAPHORE)) {}

DomainImpl::~DomainImpl() { close(efd_); }

inline static int poll_fds(struct pollfd* fds, int nfds, int timeout, uint32_t domain_id) {
    // Poll for an event
    int result = ::poll(fds, nfds, timeout);
    switch (result) {
    case 0: // Poll timeout
        return 0;
    case -1: // Error
        // Check if we were interrupted by a signal or something
        if (errno == EINTR) {
            LOG4CXX_DEBUG(logger, "poll() interrupted for Domain " << domain_id);
        } else {
            LOG4CXX_WARN(logger, "poll() error on Domain " << domain_id << ": " << strerror(errno));
        }
        throw EventPollException(errno);
    }
    return result;
}

static thread_local Domain* thread_local_domain_;

Domain& DomainImpl::thread_local_domain() { return *thread_local_domain_; }
void DomainImpl::thread_local_domain(Domain& d) { thread_local_domain_ = &d; }
void DomainImpl::clear_thread_local_domain() { thread_local_domain_ = nullptr; }
Domain& Domain::thread_local_domain() { return DomainImpl::thread_local_domain(); }

} // namespace introvirt