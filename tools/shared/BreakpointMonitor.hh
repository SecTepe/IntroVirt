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
 * Out-of-VM breakpoints for a Windows guest process.
 *
 * Runs inside ivsyscallmon: IntroVirt allows exactly one introspection session
 * per domain, so the breakpoints share the attach with the syscall trace instead
 * of taking a second one. The breakpoints are armed lazily, from the first
 * syscall event of the target process (`--bp-process`, matched on the 15
 * character ImageFileName like ivmemwatch/ivprocinfo do), because the vcpu of
 * that event runs in the process address space; the sample may start after the
 * attach. Targets that do not resolve yet (a module that is not loaded) are
 * retried once a second for two minutes.
 *
 * Nothing is written into the guest except the int3 / EPT trap IntroVirt itself
 * installs; the sample cannot see a debugger.
 *
 * Output (stdout, one line each, under the syscall monitor's output mutex):
 *
 *   SECTEPE-BP {"target":...,"address":"0x...","pid":N,"tid":N,"process":"...",
 *               "hit_count":1,"hit_no":N,"action":"...","access":"...","rip":"0x...",
 *               "rsp":"0x...","mode":"x64|x86","ret":"0x..."|null,
 *               "args":["0x..",..first 4 arguments..],"ts":S}
 *   SECTEPE-BP-STATUS {"target":...,"state":"armed|pending|failed|removed|
 *                      unsupported","reason":...,"address":...,"pid":N}
 *   SECTEPE-BP-STEP {"target":...,"pid":N,"tid":N,"hit_no":N,"step":N,"rip":"0x...",
 *                    "rsp":"0x...","depth":N,"kind":"other|call|ret|syscall",
 *                    "bytes":"<hex>"[,"over":true]}
 *   SECTEPE-BP-STEP-END {"target":...,"pid":N,"tid":N,"hit_no":N,"steps":N,
 *                        "reason":"..."}
 *
 * One line per hit: `hit_count` is what the line stands for (always 1),
 * `hit_no` the running number of the hit for that target. `args` follow the
 * calling convention of the code that hit (HitArgs.hh): RCX/RDX/R8/R9 in
 * 64-bit code, the 32-bit stack words at ESP+4.. in 32-bit (WOW64) code;
 * `ret` is the return address at [RSP] (null when the stack was not readable).
 * A hit is only reported for the target's pid: a system DLL page is shared
 * between processes, so the trap fires for all of them.
 *
 * `action=step` records the hit and then single-steps the hitting thread from
 * there (Monitor Trap Flag, Domain::single_step): one SECTEPE-BP-STEP line per
 * instruction - address, the raw bytes, its kind (StepTrace.hh) - until the hit
 * function returns or `steps` instructions are recorded. Calls more than
 * `depth` levels below the hit function and every system call are stepped OVER
 * with a temporary breakpoint on the return address, so the trace stays in the
 * code the analyst asked about. An interrupt or page fault in the middle (the
 * vcpu lands in the kernel) is not traced: stepping pauses and resumes from a
 * breakpoint on the interrupted instruction. One trace runs at a time; a step
 * hit during it is reported with SECTEPE-BP-STEP-END "another step trace is
 * running" ("thread is already being traced" for the traced thread itself).
 * Each trace ends with exactly one SECTEPE-BP-STEP-END.
 *
 * Not implemented: a per-hit process dump (`action=dump` is recorded; the
 * runner's end-of-run guest memory dump is the dump).
 */

#include "BreakpointSpec.hh"
#include "HitArgs.hh"
#include "StepTrace.hh"

#include <introvirt/introvirt.hh>

#include <boost/algorithm/string.hpp>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <exception>
#include <iostream>
#include <memory>
#include <mutex>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace sectepe {

class BreakpointMonitor final {
  public:
    /**
     * @param specs        The breakpoints to arm
     * @param process_name Name of the target process (the sample)
     * @param out_mutex    The mutex the syscall monitor writes stdout under, so a
     *                     line here never lands inside one of its multi-line records
     * @param flush        Flush stdout after every line
     */
    BreakpointMonitor(std::vector<BreakpointSpec> specs, const std::string& process_name,
                      std::mutex& out_mutex, bool flush)
        : process_name_(short_name(process_name)), out_mtx_(out_mutex), flush_(flush) {
        targets_.reserve(specs.size());
        for (auto& spec : specs) {
            targets_.emplace_back();
            targets_.back().spec = std::move(spec);
        }
        pending_ = targets_.size();
    }

    /** Called by the syscall monitor for every event; cheap once nothing is left to arm. */
    void on_event(introvirt::Event& event) {
        if (finished_.load(std::memory_order_relaxed))
            return;
        if (event.type() != introvirt::EventType::EVENT_FAST_SYSCALL)
            return;
        if (short_name(event.task().process_name()) != process_name_)
            return;

        // Arming is serialised, but never waits: another vcpu thread that is
        // busy arming does the work, and holding an event here while it does so
        // could stall the hypervisor's own wait for all vcpus.
        std::unique_lock<std::mutex> arm_lock(arm_mtx_, std::try_to_lock);
        if (!arm_lock.owns_lock() || finished_.load(std::memory_order_relaxed))
            return;
        const auto now = std::chrono::steady_clock::now();
        if (attempts_ > 0 && now - last_attempt_ < RETRY_INTERVAL)
            return;
        last_attempt_ = now;
        ++attempts_;

        arm_all(event);

        if (pending_ == 0) {
            finished_ = true;
        } else if (attempts_ >= MAX_ATTEMPTS) {
            for (auto& t : targets_) {
                if (t.state == State::Pending) {
                    t.state = State::Failed;
                    status(t, "failed", t.reason.empty() ? "target never resolved" : t.reason);
                }
            }
            pending_ = 0;
            finished_ = true;
        }
    }

    ~BreakpointMonitor() {
        // A trace still waiting on a step-over that never came back (an
        // exception unwound past it, the sample exited).
        std::unique_ptr<introvirt::SingleStep> step;
        std::shared_ptr<introvirt::Breakpoint> resume;
        std::string line;
        {
            std::lock_guard<std::mutex> lock(trace_mtx_);
            if (trace_.active)
                line = finish_trace("monitor stopped", step, resume);
        }
        if (!line.empty())
            emit("SECTEPE-BP-STEP-END ", line);
    }

    /** Report that breakpoints cannot be used with this guest (nothing was armed). */
    void unsupported(const std::string& reason) {
        for (auto& t : targets_)
            status(t, "unsupported", reason);
        finished_ = true;
    }

  private:
    enum class State { Pending, Armed, Failed };

    struct Target {
        BreakpointSpec spec;
        State state = State::Pending;
        std::string reason;
        uint64_t address = 0;
        uint32_t hit_count = 0;
        bool removed = false;
        std::shared_ptr<introvirt::Breakpoint> breakpoint;
        std::unique_ptr<introvirt::Watchpoint> watchpoint;
    };

    static constexpr std::chrono::seconds RETRY_INTERVAL{1};
    static constexpr unsigned MAX_ATTEMPTS = 120;

    // Windows keeps only the first 15 characters of the image name (EPROCESS
    // ImageFileName), so both sides are compared at that length.
    static std::string short_name(const std::string& name) {
        return boost::to_lower_copy(name.substr(0, 15));
    }

    // First line, bounded: a reason ends up in one JSON line of the trace.
    static std::string short_reason(const char* what) {
        std::string text = what ? what : "";
        text = text.substr(0, text.find('\n'));
        return text.size() > 200 ? text.substr(0, 200) : text;
    }

    static std::string hex(uint64_t value) {
        char buf[24];
        std::snprintf(buf, sizeof(buf), "0x%llx", static_cast<unsigned long long>(value));
        return buf;
    }

    static double now_seconds() {
        return std::chrono::duration<double>(std::chrono::system_clock::now().time_since_epoch())
            .count();
    }

    void emit(const char* prefix, const std::string& json) {
        std::lock_guard<std::mutex> lock(out_mtx_);
        std::cout << prefix << json << '\n';
        if (flush_)
            std::cout.flush();
    }

    // Caller must not hold state_mtx_ (this takes it briefly, then the output mutex).
    void status(const Target& t, const char* state, const std::string& reason) {
        uint64_t address, pid;
        {
            std::lock_guard<std::mutex> lock(state_mtx_);
            address = t.address;
            pid = pid_;
        }
        std::ostringstream json;
        json << "{\"target\":\"" << json_escape(t.spec.target) << "\",\"state\":\"" << state
             << "\"";
        if (!reason.empty())
            json << ",\"reason\":\"" << json_escape(reason) << "\"";
        if (address)
            json << ",\"address\":\"" << hex(address) << "\"";
        if (pid)
            json << ",\"pid\":" << pid;
        json << '}';
        emit("SECTEPE-BP-STATUS ", json.str());
    }

    void arm_all(introvirt::Event& event) {
        introvirt::windows::nt::PROCESS* process = nullptr;
        try {
            process = &static_cast<introvirt::windows::WindowsEvent&>(event)
                           .task()
                           .pcr()
                           .CurrentThread()
                           .Process();
        } catch (const std::exception&) {
            return; // idle thread or a transient read failure: try again on a later event
        }
        {
            // The first process of that name is the one: a hit is filtered on
            // this pid, and every trap lives in this process' address space, so
            // a second process of the same name must not take over half way.
            std::lock_guard<std::mutex> lock(state_mtx_);
            const uint64_t pid = event.task().pid();
            if (pid_ == 0)
                pid_ = pid;
            else if (pid_ != pid)
                return;
        }

        for (size_t i = 0; i < targets_.size(); ++i) {
            Target& t = targets_[i];
            if (t.state != State::Pending)
                continue;
            try {
                arm_one(i, event, *process);
                t.state = State::Armed;
                --pending_;
                status(t, "armed", "");
            } catch (const std::exception& ex) {
                t.reason = short_reason(ex.what());
                // Reported once, then quietly retried: a module that is not loaded yet.
                if (attempts_ == 1)
                    status(t, "pending", t.reason);
            }
        }
    }

    void arm_one(size_t index, introvirt::Event& event, introvirt::windows::nt::PROCESS& process) {
        Target& t = targets_[index];
        introvirt::guest_ptr<void> address = resolve(event, process, t.spec);
        if (!address)
            throw std::runtime_error("target resolved to a null address");
        {
            // Before the trap exists: a hit may arrive as soon as it does.
            std::lock_guard<std::mutex> lock(state_mtx_);
            t.address = address.address();
        }

        introvirt::Domain& domain = event.domain();
        auto callback = [this, index](introvirt::Event& e) { this->on_hit(index, e); };
        std::shared_ptr<introvirt::Breakpoint> breakpoint;
        std::unique_ptr<introvirt::Watchpoint> watchpoint;
        if (t.spec.access == "exec") {
            breakpoint = domain.create_breakpoint(address, callback);
        } else {
            watchpoint = domain.create_watchpoint(address, WATCH_LENGTH, t.spec.read(),
                                                  t.spec.write(), false, callback);
        }

        std::lock_guard<std::mutex> lock(state_mtx_);
        if (!t.removed) { // false if the hit limit was reached before we got here
            t.breakpoint = std::move(breakpoint);
            t.watchpoint = std::move(watchpoint);
        }
    }

    introvirt::guest_ptr<void> resolve(introvirt::Event& event,
                                       introvirt::windows::nt::PROCESS& process,
                                       const BreakpointSpec& spec) {
        using Kind = BreakpointSpec::TargetKind;
        switch (spec.kind) {
        case Kind::Address:
            return introvirt::guest_ptr<void>(event.vcpu(), spec.address);
        case Kind::EntryPoint: {
            auto* peb = process.Peb();
            if (peb == nullptr)
                throw std::runtime_error("process has no PEB");
            auto pe = introvirt::windows::pe::PE::make_unique(peb->ImageBaseAddress());
            introvirt::guest_ptr<void> entry = pe->optional_header().AddressOfEntryPoint();
            return spec.negative ? entry - spec.address : entry + spec.address;
        }
        case Kind::Export:
            return find_export(event, process, spec.module, spec.symbol);
        }
        throw std::runtime_error("unknown target kind");
    }

    static std::string base_name(const std::string& path) {
        const auto pos = path.find_last_of("\\/");
        return pos == std::string::npos ? path : path.substr(pos + 1);
    }

    // Walk the process' mapped images (the same VAD walk ivcallmon uses to find
    // ntdll) and look the export up in the PE export directory.
    introvirt::guest_ptr<void> find_export(introvirt::Event& event,
                                           introvirt::windows::nt::PROCESS& process,
                                           const std::string& module, const std::string& symbol) {
        std::string wanted = boost::to_lower_copy(module);
        if (wanted.find('.') == std::string::npos)
            wanted += ".dll";

        auto vadroot = process.VadRoot();
        if (!vadroot)
            throw std::runtime_error("process has no VAD tree");

        bool module_seen = false;
        for (const auto& entry : vadroot->VadTreeInOrder()) {
            if (!entry->Protection().isExecutable())
                continue;
            const auto* file_object = entry->FileObject();
            if (file_object == nullptr)
                continue;
            if (boost::to_lower_copy(base_name(file_object->FileName())) != wanted)
                continue;
            module_seen = true;

            auto pe = introvirt::windows::pe::PE::make_unique(
                introvirt::guest_ptr<void>(event.vcpu(), entry->StartingAddress()));
            const auto* exports = pe->export_directory();
            if (exports == nullptr)
                continue;
            const auto* found = exports->find(symbol);
            if (found == nullptr || found->exportType != introvirt::windows::pe::EXPORT_TYPE_CODE)
                continue;
            return found->address;
        }
        throw std::runtime_error(module_seen ? "export '" + symbol + "' not found in " + module
                                             : "module '" + module + "' is not loaded");
    }

    void on_hit(size_t index, introvirt::Event& event) {
        Target& t = targets_[index];
        std::string line;
        bool limit_reached = false;
        uint32_t hit_no = 0;
        {
            std::lock_guard<std::mutex> lock(state_mtx_);
            if (t.removed || event.task().pid() != pid_)
                return;
            ++t.hit_count;
            hit_no = t.hit_count;

            const auto& regs = event.vcpu().registers();
            const sectepe::HitArgs args = read_args(event);
            std::ostringstream json;
            json << "{\"target\":\"" << json_escape(t.spec.target) << "\",\"address\":\""
                 << hex(t.address) << "\",\"pid\":" << event.task().pid()
                 << ",\"tid\":" << event.task().tid() << ",\"process\":\""
                 << json_escape(event.task().process_name())
                 << "\",\"hit_count\":1,\"hit_no\":" << t.hit_count << ",\"action\":\""
                 << t.spec.action << "\",\"access\":\"" << t.spec.access << "\",\"rip\":\""
                 << hex(regs.rip()) << "\",\"rsp\":\"" << hex(regs.rsp()) << '"'
                 << sectepe::hit_args_json(args) << ",\"ts\":";
            char ts[32];
            std::snprintf(ts, sizeof(ts), "%.3f", now_seconds());
            json << ts << '}';
            line = json.str();

            if (t.spec.hits != 0 && t.hit_count >= t.spec.hits) {
                // Dropping the handle clears the trap (ivcallmon does the same
                // from inside a breakpoint callback).
                t.removed = true;
                t.breakpoint.reset();
                t.watchpoint.reset();
                limit_reached = true;
            }
        }
        emit("SECTEPE-BP ", line);
        if (limit_reached)
            status(t, "removed", "hit limit reached");
        if (t.spec.action == "step")
            start_trace(index, event, hit_no);
    }

    // ---- step trace (action=step) --------------------------------------
    //
    // trace_mtx_ guards trace_. As with the traps above, it is never held while
    // IntroVirt creates or drops a step or a breakpoint: those take the
    // hypervisor's own locks, which a callback on another vcpu may hold while
    // it waits for trace_mtx_. Callbacks carry the generation of the trace they
    // were made for and do nothing once it has moved on.

    struct Trace {
        bool active = false;
        uint64_t generation = 0;
        size_t target = 0;
        uint64_t pid = 0;
        uint64_t tid = 0;
        uint32_t hit_no = 0;
        unsigned depth = 0;
        unsigned recorded = 0;
        unsigned detours = 0;
        StepPolicy policy;
        uint64_t pending_rip = 0;    // the instruction the thread executes next
        uint64_t page_directory = 0; // the process address space, for resume breakpoints
        bool resume_records = false; // resume address is a new instruction (step-over), not a detour
        std::chrono::steady_clock::time_point started;
        std::unique_ptr<introvirt::SingleStep> step;
        std::shared_ptr<introvirt::Breakpoint> resume;
    };

    // A trace whose step-over never came back (exception, thread exit) does not
    // block the next step hit forever.
    static constexpr std::chrono::seconds TRACE_STALE{30};
    // Interrupts / faults during one trace; a thread that keeps getting
    // interrupted is not worth a breakpoint round trip each time.
    static constexpr unsigned MAX_DETOURS = 64;
    // Canonical upper half: kernel addresses.
    static constexpr uint64_t KERNEL_BASE = 0xffff800000000000ULL;

    // The END line for the current trace; marks it inactive and hands its
    // handles to the caller to drop after trace_mtx_ is released.
    std::string finish_trace(const char* reason, std::unique_ptr<introvirt::SingleStep>& step,
                             std::shared_ptr<introvirt::Breakpoint>& resume) {
        trace_.active = false;
        step = std::move(trace_.step);
        resume = std::move(trace_.resume);
        return end_json(targets_[trace_.target].spec.target, trace_.pid, trace_.tid, trace_.hit_no,
                        trace_.recorded, reason);
    }

    static std::string end_json(const std::string& target, uint64_t pid, uint64_t tid,
                                uint32_t hit_no, unsigned steps, const std::string& reason) {
        std::ostringstream json;
        json << "{\"target\":\"" << json_escape(target) << "\",\"pid\":" << pid
             << ",\"tid\":" << tid << ",\"hit_no\":" << hit_no << ",\"steps\":" << steps
             << ",\"reason\":\"" << json_escape(reason) << "\"}";
        return json.str();
    }

    // Up to 15 bytes at @p rip; fewer if the next page is not mapped.
    // 64-bit code segment in long mode; otherwise 32-bit code (a WOW64
    // process, or a 32-bit guest). The decision WindowsFunctionCall makes.
    static bool is_64bit_code(const introvirt::Vcpu& vcpu) {
        return vcpu.long_mode() && !vcpu.long_compatibility_mode();
    }

    // The hit's arguments by the calling convention of the code that hit:
    // 64-bit code passes them in registers, 32-bit (WOW64) code on the stack
    // (the decision WindowsFunctionCall makes). A stack read that crosses into
    // an unreadable page keeps the words before it.
    static sectepe::HitArgs read_args(introvirt::Event& event) {
        auto& vcpu = event.vcpu();
        const auto& regs = vcpu.registers();
        const uint64_t rsp = regs.rsp();
        if (is_64bit_code(vcpu)) {
            try {
                const uint64_t ret = *introvirt::guest_ptr<uint64_t>(vcpu, rsp);
                return sectepe::hit_args_x64(regs.rcx(), regs.rdx(), regs.r8(), regs.r9(), &ret);
            } catch (const std::exception&) {
                return sectepe::hit_args_x64(regs.rcx(), regs.rdx(), regs.r8(), regs.r9(),
                                             nullptr);
            }
        }
        const uint64_t esp = rsp & 0xffffffffULL;
        uint32_t words[sectepe::kHitStackWords32] = {};
        size_t count = sectepe::kHitStackWords32;
        const size_t to_page = (0x1000 - (esp & 0xfff)) / sizeof(uint32_t);
        for (int attempt = 0; attempt < 2 && count > 0; ++attempt) {
            try {
                introvirt::guest_ptr<uint32_t[]> stack(vcpu, esp, count);
                for (size_t i = 0; i < count; ++i)
                    words[i] = stack[i];
                return sectepe::hit_args_x86(words, count);
            } catch (const std::exception&) {
                if (to_page >= count)
                    break;
                count = to_page; // the next page is not present: keep this one's words
            }
        }
        return sectepe::hit_args_x86(nullptr, 0);
    }

    static size_t read_insn(introvirt::Event& event, uint64_t rip, uint8_t (&buf)[15]) {
        size_t len = sizeof(buf);
        for (int attempt = 0; attempt < 2; ++attempt) {
            try {
                introvirt::guest_ptr<uint8_t[]> bytes(event.vcpu(), rip, len);
                std::memcpy(buf, bytes.get(), len);
                return len;
            } catch (const std::exception&) {
                const size_t to_page = 0x1000 - (rip & 0xfff);
                if (to_page >= len)
                    return 0;
                len = to_page;
            }
        }
        return 0;
    }

    void start_trace(size_t index, introvirt::Event& event, uint32_t hit_no) {
        const Target& t = targets_[index];
        const uint64_t pid = event.task().pid(); // on_hit already matched it to pid_
        const uint64_t tid = event.task().tid();
        std::unique_ptr<introvirt::SingleStep> old_step;
        std::shared_ptr<introvirt::Breakpoint> old_resume;
        std::string abandoned, busy;
        const uint64_t rip = event.vcpu().registers().rip();
        const uint64_t page_directory = introvirt::guest_ptr<void>(event.vcpu(), rip).page_directory();
        uint64_t generation = 0;
        {
            std::lock_guard<std::mutex> lock(trace_mtx_);
            const auto now = std::chrono::steady_clock::now();
            if (trace_.active && now - trace_.started >= TRACE_STALE)
                abandoned = finish_trace("abandoned: step-over did not return", old_step,
                                         old_resume);
            if (trace_.active) {
                // The traced thread itself: recursion into the target, or IntroVirt
                // re-hitting the int3 after an interrupt during its own step-over.
                busy = end_json(t.spec.target, pid, tid, hit_no, 0,
                                tid == trace_.tid ? "thread is already being traced"
                                                  : "another step trace is running");
            } else {
                trace_.active = true;
                generation = ++trace_.generation;
                trace_.target = index;
                trace_.pid = pid;
                trace_.tid = tid;
                trace_.hit_no = hit_no;
                trace_.depth = 0;
                trace_.recorded = 0;
                trace_.detours = 0;
                trace_.policy.depth = t.spec.depth;
                trace_.policy.budget = t.spec.steps;
                trace_.pending_rip = rip;
                trace_.page_directory = page_directory;
                trace_.resume_records = false;
                trace_.started = now;
            }
        }
        old_step.reset();
        old_resume.reset();
        if (!abandoned.empty())
            emit("SECTEPE-BP-STEP-END ", abandoned);
        if (!busy.empty()) {
            emit("SECTEPE-BP-STEP-END ", busy);
            return;
        }
        step_at(event, generation, true);
    }

    // Single-step callback: the vcpu executed one instruction.
    void on_step(introvirt::Event& event, uint64_t generation) {
        const uint64_t rip = event.vcpu().registers().rip();
        uint64_t tid = 0;
        try {
            tid = event.task().tid();
        } catch (const std::exception&) {
            // no thread to read (kernel transition): handled as a detour below
        }
        uint64_t resume_at = 0;
        std::unique_ptr<introvirt::SingleStep> step;
        std::shared_ptr<introvirt::Breakpoint> resume;
        std::string end;
        {
            std::lock_guard<std::mutex> lock(trace_mtx_);
            if (!trace_.active || trace_.generation != generation)
                return;
            if (tid == trace_.tid && rip < KERNEL_BASE) {
                // still the traced thread in user mode: the normal case, below
            } else if (++trace_.detours > MAX_DETOURS) {
                end = finish_trace("too many interruptions", step, resume);
            } else {
                // An interrupt, a fault or a thread switch: the instruction at
                // pending_rip has not run yet. Continue when the thread gets there.
                step = std::move(trace_.step);
                resume_at = trace_.pending_rip;
                trace_.resume_records = false;
            }
        }
        if (!end.empty() || resume_at != 0) {
            step.reset(); // inside its own callback: IntroVirt defers the removal
            resume.reset();
            if (!end.empty())
                emit("SECTEPE-BP-STEP-END ", end);
            else
                arm_resume(event.domain(), resume_at, generation);
            return;
        }
        step_at(event, generation, true);
    }

    // Resume-breakpoint callback: the stepped-over call / syscall returned, or
    // the interrupted thread is back at its instruction.
    void on_resume(introvirt::Event& event, uint64_t generation) {
        std::shared_ptr<introvirt::Breakpoint> resume;
        bool record;
        {
            std::lock_guard<std::mutex> lock(trace_mtx_);
            if (!trace_.active || trace_.generation != generation)
                return;
            uint64_t tid = 0;
            try {
                tid = event.task().tid();
            } catch (const std::exception&) {
                return;
            }
            if (tid != trace_.tid)
                return; // another thread in the same code
            resume = std::move(trace_.resume);
            record = trace_.resume_records;
        }
        resume.reset(); // dropped from inside its callback, as on_hit does
        step_at(event, generation, record);
    }

    // Record the instruction at RIP (unless @p record is false: a detour came
    // back to one already recorded), decide, and keep the thread stepping,
    // step over or end the trace.
    void step_at(introvirt::Event& event, uint64_t generation, bool record) {
        const auto& regs = event.vcpu().registers();
        const uint64_t rip = regs.rip(), rsp = regs.rsp();
        uint8_t bytes[15];
        const size_t length = read_insn(event, rip, bytes);
        const Insn insn = classify(bytes, length, is_64bit_code(event.vcpu()));

        std::string line, end;
        bool need_step = false;
        uint64_t resume_at = 0;
        std::unique_ptr<introvirt::SingleStep> step;
        std::shared_ptr<introvirt::Breakpoint> resume;
        {
            std::lock_guard<std::mutex> lock(trace_mtx_);
            if (!trace_.active || trace_.generation != generation)
                return;
            StepDecision d;
            d.depth = trace_.depth;
            if (record) {
                ++trace_.recorded;
                d = decide(insn, rip, trace_.depth, trace_.recorded, trace_.policy);
                std::ostringstream json;
                json << "{\"target\":\"" << json_escape(targets_[trace_.target].spec.target)
                     << "\",\"pid\":" << trace_.pid << ",\"tid\":" << trace_.tid
                     << ",\"hit_no\":" << trace_.hit_no << ",\"step\":" << trace_.recorded
                     << ",\"rip\":\"" << hex(rip) << "\",\"rsp\":\"" << hex(rsp)
                     << "\",\"depth\":" << trace_.depth << ",\"kind\":\""
                     << insn_kind_name(insn.kind) << "\",\"bytes\":\"" << hex_bytes(bytes, length)
                     << '"';
                if (d.action == StepAction::StepOver)
                    json << ",\"over\":true";
                json << '}';
                line = json.str();
                trace_.depth = d.depth;
            }
            trace_.pending_rip = rip;
            switch (d.action) {
            case StepAction::Continue:
                need_step = !trace_.step;
                break;
            case StepAction::StepOver:
                step = std::move(trace_.step);
                resume_at = d.resume_at;
                trace_.resume_records = true;
                break;
            case StepAction::Stop:
                end = finish_trace(d.reason, step, resume);
                break;
            }
        }
        if (!line.empty())
            emit("SECTEPE-BP-STEP ", line);
        step.reset();
        resume.reset();
        if (!end.empty()) {
            emit("SECTEPE-BP-STEP-END ", end);
            return;
        }
        if (resume_at != 0) {
            arm_resume(event.domain(), resume_at, generation);
        } else if (need_step) {
            std::unique_ptr<introvirt::SingleStep> created;
            std::string failed;
            try {
                created = event.domain().single_step(
                    event.vcpu(),
                    [this, generation](introvirt::Event& e) { this->on_step(e, generation); });
            } catch (const std::exception& ex) {
                failed = std::string("single-step failed: ") + short_reason(ex.what());
            }
            std::unique_ptr<introvirt::SingleStep> stale;
            {
                std::lock_guard<std::mutex> lock(trace_mtx_);
                if (!trace_.active || trace_.generation != generation) {
                    stale = std::move(created);
                } else if (!failed.empty()) {
                    end = finish_trace(failed.c_str(), stale, resume);
                } else {
                    trace_.step = std::move(created);
                }
            }
            stale.reset();
            resume.reset();
            if (!end.empty())
                emit("SECTEPE-BP-STEP-END ", end);
        }
    }

    // Temporary breakpoint at @p address in the traced process; the trace
    // continues from on_resume when the traced thread reaches it.
    void arm_resume(introvirt::Domain& domain, uint64_t address, uint64_t generation) {
        uint64_t page_directory;
        {
            std::lock_guard<std::mutex> lock(trace_mtx_);
            if (!trace_.active || trace_.generation != generation)
                return;
            page_directory = trace_.page_directory;
        }
        std::shared_ptr<introvirt::Breakpoint> created;
        std::string failed;
        try {
            created = domain.create_breakpoint(
                introvirt::guest_ptr<void>(domain, address, page_directory),
                [this, generation](introvirt::Event& e) { this->on_resume(e, generation); });
        } catch (const std::exception& ex) {
            failed = std::string("step-over failed: ") + short_reason(ex.what());
        }
        std::shared_ptr<introvirt::Breakpoint> stale;
        std::unique_ptr<introvirt::SingleStep> step;
        std::string end;
        {
            std::lock_guard<std::mutex> lock(trace_mtx_);
            if (!trace_.active || trace_.generation != generation) {
                stale = std::move(created);
            } else if (!failed.empty()) {
                end = finish_trace(failed.c_str(), step, stale);
            } else {
                trace_.resume = std::move(created);
            }
        }
        stale.reset();
        step.reset();
        if (!end.empty())
            emit("SECTEPE-BP-STEP-END ", end);
    }

    // A write/read watch is page-granular in the hypervisor; the length only
    // bounds what IntroVirt reports.
    static constexpr uint64_t WATCH_LENGTH = 8;

    const std::string process_name_;
    std::mutex& out_mtx_;
    const bool flush_;

    // arm_mtx_ serialises arming and guards the fields only on_event touches
    // (attempts_, last_attempt_, pending_, Target::state/reason). state_mtx_
    // guards what a hit callback shares with it (pid_, Target::address,
    // hit_count, removed and the trap handles). Output is written after
    // state_mtx_ is released, and no lock is held while a trap is created.
    std::mutex arm_mtx_;
    std::mutex state_mtx_;
    std::vector<Target> targets_;
    size_t pending_ = 0;
    unsigned attempts_ = 0;
    std::chrono::steady_clock::time_point last_attempt_;
    uint64_t pid_ = 0;
    std::atomic<bool> finished_{false};

    std::mutex trace_mtx_;
    Trace trace_;
};

} // namespace sectepe
