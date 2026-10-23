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

#include "core/breakpoint/BreakpointManager.hh"
#include "core/breakpoint/SingleStepManager.hh"
#include "core/breakpoint/WatchpointManager.hh"

#include "core/event/HypervisorEvent.hh"

#include <introvirt/core/arch/arch.hh>
#include <introvirt/core/domain/Domain.hh>
#include <introvirt/core/domain/Guest.hh>
#include <introvirt/core/filter/TaskFilter.hh>
#include <introvirt/core/fwd.hh>
#include <introvirt/core/memory/GuestMemoryMapping.hh>
#include <introvirt/core/memory/guest_ptr.hh>
#include <introvirt/core/syscall/SystemCallFilter.hh>
#include <introvirt/util/compiler.hh>

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <list>
#include <memory>
#include <mutex>
#include <poll.h>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace introvirt {

class BreakpointManager;
class GuestImpl;
struct worker_thread_info;

/**
 * @brief Common base class code for domains
 *
 * A Domain object is the mechanism for interacting with a virtual machine.
 * It is subclassed for specific hypervisors, such as the KvmDomain and the
 * XenDomain.
 */
class DomainImpl : public Domain {
  public:
    void pause_all_other_vcpus(const Vcpu& vcpu);
    void resume_all_other_vcpus(const Vcpu& vcpu);

    std::shared_ptr<Breakpoint> create_breakpoint(const guest_ptr<void>& address,
                                                  std::function<void(Event&)> callback) override;

    std::unique_ptr<Watchpoint> create_watchpoint(const guest_ptr<void>& address, uint64_t length,
                                                  bool read, bool write, bool execute,
                                                  std::function<void(Event&)> callback) override;

    std::unique_ptr<SingleStep> single_step(Vcpu& vcpu,
                                            std::function<void(Event&)> callback) override;

    BreakpointManager& breakpoint_manager();
    SingleStepManager& single_step_manager();
    WatchpointManager& watchpoint_manager();

    void poll(EventCallback& callback) override;

    void interrupt() override;

    void pause() override;
    void resume() override;

    TaskFilter& task_filter() override;

    SystemCallFilter& system_call_filter() override;
    const SystemCallFilter& system_call_filter() const override;

    bool detect_guest() override;

    /**
     * @brief A kernel-mapping CR3 captured from a CR3-WRITE event during
     * detect_guest() (the guest's SWITCH_TO_KERNEL_CR3 on a syscall/interrupt
     * entry under KPTI). NtKernelImpl uses it to bootstrap the kernel-base scan
     * when every vcpu is in user mode and the live vcpu CR3 does not map the
     * kernel. 0 if none was captured. Internal (not on the Domain interface).
     */
    uint64_t detect_cr3_hint() const { return detect_cr3_hint_; }

    /**
     * @brief Set/clear the transient page-fault handler used during guest detection.
     *
     * detect_guest() does not assign guest_ until the WindowsGuestImpl is fully
     * constructed, so the under-construction guest registers itself here to let
     * PageDirectory::translate resolve transition/standby PTEs (e.g. cold Object
     * Manager pool pages on a busy fresh boot) during construction. nullptr otherwise.
     */
    void set_detection_pf_guest(GuestImpl* g) { detection_pf_guest_ = g; }

    /**
     * @brief The active page-fault handler: the detection guest if one is currently
     * being constructed, otherwise the established guest (or nullptr).
     */
    GuestImpl* page_fault_guest() const;

    Guest* guest() override;
    const Guest* guest() const override;

    void intercept_system_calls(bool enabled) override;
    void intercept_cr_writes(int cr, bool enabled) override;

    void suspend_event(Event& event) override;
    void suspend_event_step(Event& event) override;

    const x86::PageDirectory& page_directory() const override;
    const PageTableWalker& page_table_walker() const override;

    /**
     * @brief Intercept memory access for a guest frame number
     *
     * When a faulting access occurs, IntroVirt will deliver an EVENT_MEM_ACCESS event.
     * Note that if some action is not taken, the fauling instruction will simply try agains and
     * will cause another EVENT_MEM_ACCESS to occur.
     *
     * @param gfn The guest frame number to intercept access to
     * @param on_read If set, reads will intercepted
     * @param on_write If set, writes will be intercepted
     * @param on_execute If set, executes will be intercepted
     * @throws NotImplementedException if memory access interception is not supported
     */
    virtual void intercept_mem_access(uint64_t gfn, bool on_read, bool on_write,
                                      bool on_execute) = 0;

    /**
     * @brief Clear all memory access intercepts
     *
     * This removes all memory access intercepts that are configured.
     *
     * @throws NotImplementedException if memory access interception is not supported
     */
    virtual void clear_mem_access_intercepts() = 0;

    /**
     * @brief Toggle interception of the given exception vector
     *
     * When enabled, events of type EVENT_EXCEPTION will be delivered for the given vector.
     *
     * @param vector The exception vector to intercept
     * @param enabled If set to true, when the exception occurs it will be intercepted
     * @throws NotImplementedException if the exception vector cannot be intercepted
     * @throws CommandFailedException If the hypervisor reports an error
     */
    virtual void intercept_exception(x86::Exception vector, bool enabled) = 0;

    /**
     * @brief Check if the given exception vector is being intercepted
     *
     * @param vector The exception vector to check
     * @return true If the exception vector is being intercepted
     * @return false If the exception vector is not being intercepted
     */
    virtual bool intercept_exception(x86::Exception vector) const = 0;

    static Domain& thread_local_domain();
    static void thread_local_domain(Domain& d);
    static void clear_thread_local_domain();

    void start_injection(Event& event);
    void end_injection(Event& event);
    void step_breakpoints(Event& event);

    void event_deliverer(EventCallback* callback, struct worker_thread_info* worker_info);

    /**
     * @brief Destroy the instance
     */
    ~DomainImpl() override;

  protected:
    /**
     * @brief Construct a new Domain object
     */
    DomainImpl();

    /**
     * @brief Called by subclasses to initialize the base class
     */
    void initialize();

    /**
     * @brief Release the Guest before destroying vCPUs (for shutdown order).
     * Subclass destructors should call this before clearing vcpus_ so that
     * Guest/PDB teardown runs while the domain and vCPUs are still valid.
     */
    void reset_guest() { guest_.reset(); }

  private:
    void handle_breakpoint(Event& event);

    std::unique_ptr<Event> filter_event(std::unique_ptr<HypervisorEvent>&& event) HOT;
    std::unique_ptr<Event> get_guest_event(std::unique_ptr<HypervisorEvent>&& event) HOT;

    void vcpu_poller_thread(Vcpu* vcpu, EventCallback* callback, int efd);

    bool matches_syscall_filters(const Vcpu& vcpu) const;

  private:
    std::unique_ptr<Guest> guest_;

    std::shared_mutex event_filter_mtx_;

    SystemCallFilter system_call_filter_;
    std::vector<struct pollfd> pollfds_;

    TaskFilter task_filter_;

    std::recursive_mutex bp_mutex_;
    SingleStepManager single_step_manager_;
    WatchpointManager watchpoint_manager_;
    BreakpointManager breakpoint_manager_;

    x86::PageDirectory page_directory_;

    // SECTEPE: kernel-mapping CR3 captured from a CR3-WRITE event during
    // detect_guest() (see detect_cr3_hint()). 0 when none captured.
    uint64_t detect_cr3_hint_ = 0;

    // SECTEPE: transient page-fault handler active only during guest detection
    // (the under-construction WindowsGuestImpl), so transition/standby PTEs resolve
    // before guest_ is assigned. nullptr otherwise. See page_fault_guest().
    GuestImpl* detection_pf_guest_ = nullptr;

    // The event fd for interrupting the threads
    const int efd_;
    bool interrupted_ = false;

    struct {
        std::mutex mtx_;
        std::vector<Event*> by_vcpu_;
    } stepping_events_;

    struct {
        std::mutex mtx_;
        std::unordered_multimap<uint64_t, Event*> map_;
    } suspended_events_;

    struct {
        std::mutex mtx_;
        std::condition_variable cv_;
        int count_ = 0;
    } injection_;

    struct {
        std::mutex mtx_;
        std::unordered_set<uint64_t> set_;
    } injection_tids_;
};

} // namespace introvirt
