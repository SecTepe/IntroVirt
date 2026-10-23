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

/*
 * Unit tests for the architecture-neutral "seam" added by the arm64 Phase 1
 * port (docs/introvirt-arm64.md): the Linux syscall name tables, the
 * Architecture enum helper, and the x86 syscall-ABI mapping on the neutral
 * RegisterContext interface. These exercise pure logic only — no hypervisor,
 * domain or guest memory is required — so they run in CI via ctest. Anything
 * that needs a live VM (PageTableWalker, KvmRegisters, Domain/Vcpu) is
 * deliberately left to the integration tools (gdt/idt/readmem/readvcpu).
 *
 * Dependency-free harness on purpose: there is no GoogleTest in the build image
 * and no precedent for it in the tree. main() returns non-zero if any check
 * fails, which is what ctest needs.
 */

#include "../tools/shared/BreakpointSpec.hh"
#include "../tools/shared/HitArgs.hh"
#include "../tools/shared/StepTrace.hh"
#include "linux/kernel/LinuxSyscalls.hh"
#include "linux/kernel/LinuxSyscallsArm64.hh"

#include <introvirt/core/arch/Architecture.hh>
#include <introvirt/core/arch/x86/Registers.hh>

#include <cstdint>
#include <initializer_list>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

using namespace introvirt;

namespace {

int g_checks = 0;
int g_failures = 0;

#define CHECK(cond)                                                                                 \
    do {                                                                                            \
        ++g_checks;                                                                                 \
        if (!(cond)) {                                                                              \
            ++g_failures;                                                                           \
            std::cerr << "FAIL " << __FILE__ << ":" << __LINE__ << ": CHECK(" #cond ")\n";          \
        }                                                                                           \
    } while (0)

#define CHECK_EQ(actual, expected)                                                                  \
    do {                                                                                            \
        ++g_checks;                                                                                 \
        const auto a_ = (actual);                                                                   \
        const auto e_ = (expected);                                                                 \
        if (!(a_ == e_)) {                                                                          \
            ++g_failures;                                                                           \
            std::cerr << "FAIL " << __FILE__ << ":" << __LINE__ << ": " #actual " == " #expected    \
                      << " (got '" << a_ << "' vs '" << e_ << "')\n";                               \
        }                                                                                           \
    } while (0)

/*
 * Minimal concrete x86::Registers for testing the syscall-ABI mapping. The 17
 * general-purpose registers are backed by members; the remaining x86-only
 * accessors are stubbed (they are not exercised by these tests). The neutral
 * syscall_*()/pc()/sp() methods are inherited `final` from x86::Registers, so
 * this mock validates the real mapping code.
 */
class MockRegisters final : public x86::Registers {
  public:
    uint64_t rax() const override { return rax_; }
    void rax(uint64_t v) override { rax_ = v; }
    uint64_t rbx() const override { return rbx_; }
    void rbx(uint64_t v) override { rbx_ = v; }
    uint64_t rcx() const override { return rcx_; }
    void rcx(uint64_t v) override { rcx_ = v; }
    uint64_t rdx() const override { return rdx_; }
    void rdx(uint64_t v) override { rdx_ = v; }
    uint64_t r15() const override { return r15_; }
    void r15(uint64_t v) override { r15_ = v; }
    uint64_t r14() const override { return r14_; }
    void r14(uint64_t v) override { r14_ = v; }
    uint64_t r13() const override { return r13_; }
    void r13(uint64_t v) override { r13_ = v; }
    uint64_t r12() const override { return r12_; }
    void r12(uint64_t v) override { r12_ = v; }
    uint64_t r11() const override { return r11_; }
    void r11(uint64_t v) override { r11_ = v; }
    uint64_t r10() const override { return r10_; }
    void r10(uint64_t v) override { r10_ = v; }
    uint64_t r9() const override { return r9_; }
    void r9(uint64_t v) override { r9_ = v; }
    uint64_t r8() const override { return r8_; }
    void r8(uint64_t v) override { r8_ = v; }
    uint64_t rsi() const override { return rsi_; }
    void rsi(uint64_t v) override { rsi_ = v; }
    uint64_t rdi() const override { return rdi_; }
    void rdi(uint64_t v) override { rdi_ = v; }
    uint64_t rsp() const override { return rsp_; }
    void rsp(uint64_t v) override { rsp_ = v; }
    uint64_t rbp() const override { return rbp_; }
    void rbp(uint64_t v) override { rbp_ = v; }
    uint64_t rip() const override { return rip_; }
    void rip(uint64_t v) override { rip_ = v; }

    x86::Flags& rflags() override { return flags_; }
    const x86::Flags& rflags() const override { return flags_; }
    void rflags(const x86::Flags&) override {}
    x86::Efer efer() const override { return x86::Efer(0); }
    uint64_t msr(x86::Msr) const override { return 0; }
    void msr(x86::Msr, uint64_t) override {}
    x86::Segment cs() const override { return null_segment(); }
    void cs(x86::Segment) override {}
    bool cs_long_mode() const override { return false; }
    x86::Segment ds() const override { return null_segment(); }
    x86::Segment es() const override { return null_segment(); }
    x86::Segment fs() const override { return null_segment(); }
    x86::Segment gs() const override { return null_segment(); }
    x86::Segment ss() const override { return null_segment(); }
    x86::Segment tr() const override { return null_segment(); }
    x86::Segment ldt() const override { return null_segment(); }
    x86::Cr0 cr0() const override { return x86::Cr0(0); }
    uint64_t cr2() const override { return 0; }
    uint64_t cr3() const override { return 0; }
    x86::Cr4 cr4() const override { return x86::Cr4(0); }
    uint64_t cr8() const override { return 0; }
    uint64_t gdtr_base() const override { return 0; }
    uint32_t gdtr_limit() const override { return 0; }
    uint64_t idtr_base() const override { return 0; }
    uint32_t idtr_limit() const override { return 0; }

  private:
    static x86::Segment null_segment() {
        return x86::Segment(x86::SegmentSelector(0), 0, 0, 0, false, 0, false, false, false, false,
                            false);
    }

    uint64_t rax_ = 0, rbx_ = 0, rcx_ = 0, rdx_ = 0, r15_ = 0, r14_ = 0, r13_ = 0, r12_ = 0,
             r11_ = 0, r10_ = 0, r9_ = 0, r8_ = 0, rsi_ = 0, rdi_ = 0, rsp_ = 0, rbp_ = 0, rip_ = 0;
    x86::Flags flags_{};
};

void test_linux_syscalls_x86_64() {
    // Spot-check curated x86_64 numbers (asm/unistd_64.h).
    CHECK_EQ(linux_guest::LinuxSyscalls::name(0), std::string("read"));
    CHECK_EQ(linux_guest::LinuxSyscalls::name(1), std::string("write"));
    CHECK_EQ(linux_guest::LinuxSyscalls::name(2), std::string("open"));
    CHECK_EQ(linux_guest::LinuxSyscalls::name(59), std::string("execve"));
    CHECK_EQ(linux_guest::LinuxSyscalls::name(257), std::string("openat"));
    CHECK_EQ(linux_guest::LinuxSyscalls::name(435), std::string("clone3"));
    // Unknown numbers fall back to sys_<nr>.
    CHECK_EQ(linux_guest::LinuxSyscalls::name(999999), std::string("sys_999999"));
}

void test_linux_syscalls_arm64() {
    // arm64 uses the asm-generic numbering, which differs from x86_64.
    CHECK_EQ(linux_guest::LinuxSyscallsArm64::name(63), std::string("read"));
    CHECK_EQ(linux_guest::LinuxSyscallsArm64::name(64), std::string("write"));
    CHECK_EQ(linux_guest::LinuxSyscallsArm64::name(56), std::string("openat"));
    CHECK_EQ(linux_guest::LinuxSyscallsArm64::name(221), std::string("execve"));
    CHECK_EQ(linux_guest::LinuxSyscallsArm64::name(435), std::string("clone3"));
    CHECK_EQ(linux_guest::LinuxSyscallsArm64::name(999999), std::string("sys_999999"));

    // The two tables must NOT be the same numbering — this is exactly why the
    // decoder picks the table by architecture (#528). Number 0 is "read" on
    // x86_64 but not on arm64 (where read is 63).
    CHECK_EQ(linux_guest::LinuxSyscalls::name(0), std::string("read"));
    CHECK(linux_guest::LinuxSyscallsArm64::name(0) != "read");
    CHECK(linux_guest::LinuxSyscalls::name(0) != linux_guest::LinuxSyscallsArm64::name(0));
}

void test_architecture_to_string() {
    CHECK_EQ(to_string(Architecture::x86_64), std::string("x86_64"));
    CHECK_EQ(to_string(Architecture::aarch64), std::string("aarch64"));
    CHECK_EQ(to_string(Architecture::Unknown), std::string("Unknown"));

    std::ostringstream oss;
    oss << Architecture::aarch64;
    CHECK_EQ(oss.str(), std::string("aarch64"));
}

void test_x86_syscall_abi_mapping() {
    MockRegisters regs;
    regs.rax(59);  // execve
    regs.rdi(0x11);
    regs.rsi(0x22);
    regs.rdx(0x33);
    regs.r10(0x44);
    regs.r8(0x55);
    regs.r9(0x66);

    // System V AMD64 syscall ABI: nr in rax; args in rdi,rsi,rdx,r10,r8,r9.
    CHECK_EQ(regs.syscall_number(), static_cast<uint64_t>(59));
    CHECK_EQ(regs.syscall_argument(0), static_cast<uint64_t>(0x11));
    CHECK_EQ(regs.syscall_argument(1), static_cast<uint64_t>(0x22));
    CHECK_EQ(regs.syscall_argument(2), static_cast<uint64_t>(0x33));
    CHECK_EQ(regs.syscall_argument(3), static_cast<uint64_t>(0x44));
    CHECK_EQ(regs.syscall_argument(4), static_cast<uint64_t>(0x55));
    CHECK_EQ(regs.syscall_argument(5), static_cast<uint64_t>(0x66));
    // Out-of-range argument index yields 0.
    CHECK_EQ(regs.syscall_argument(6), static_cast<uint64_t>(0));

    regs.rax(0x7f);  // return value lives in rax too
    CHECK_EQ(regs.syscall_return_value(), static_cast<uint64_t>(0x7f));

    // The same mapping must be reachable through the neutral base interface.
    const RegisterContext& ctx = regs;
    CHECK_EQ(ctx.architecture(), Architecture::x86_64);
    CHECK_EQ(ctx.syscall_argument(3), static_cast<uint64_t>(0x44));
    CHECK_EQ(ctx.syscall_number(), static_cast<uint64_t>(0x7f));
}

} // namespace

/*
 * The out-of-VM debugger's --bp spec (tools/shared/BreakpointSpec.hh). The rules
 * mirror api/sandbox-controller/connectors/debug_options.py, whose accepted and
 * rejected specs tests/unit/test_vmi_breakpoints.py checks with the same table.
 */
void test_breakpoint_spec_parsing() {
    using sectepe::BreakpointSpec;
    using Kind = BreakpointSpec::TargetKind;
    BreakpointSpec spec;
    std::string error;

    // defaults
    CHECK(sectepe::parse_breakpoint_spec("target=0x401000", spec, error));
    CHECK(spec.kind == Kind::Address);
    CHECK_EQ(spec.address, 0x401000ULL);
    CHECK_EQ(spec.action, std::string("trace"));
    CHECK_EQ(spec.access, std::string("exec"));
    CHECK_EQ(spec.hits, 0u);
    CHECK(!spec.read() && !spec.write());

    // module!export with every field, in any order
    CHECK(sectepe::parse_breakpoint_spec("hits=3,access=readwrite,action=dump,target=kernel32!CreateFileW",
                                         spec, error));
    CHECK(spec.kind == Kind::Export);
    CHECK_EQ(spec.module, std::string("kernel32"));
    CHECK_EQ(spec.symbol, std::string("CreateFileW"));
    CHECK_EQ(spec.action, std::string("dump"));
    CHECK_EQ(spec.hits, 3u);
    CHECK(spec.read() && spec.write());

    CHECK(sectepe::parse_breakpoint_spec("target=ws2_32.dll!WSAStartup,access=write", spec, error));
    CHECK_EQ(spec.module, std::string("ws2_32.dll"));
    CHECK(!spec.read() && spec.write());

    // entry point relative, both directions
    CHECK(sectepe::parse_breakpoint_spec("target=ep+0x2a,action=step", spec, error));
    CHECK(spec.kind == Kind::EntryPoint && !spec.negative);
    CHECK_EQ(spec.address, 0x2aULL);
    CHECK(sectepe::parse_breakpoint_spec("target=ep-0x10", spec, error));
    CHECK(spec.kind == Kind::EntryPoint && spec.negative);
    CHECK_EQ(spec.address, 0x10ULL);

    // limits: 16 hex digits / 65535 hits are accepted, one more is not
    CHECK(sectepe::parse_breakpoint_spec("target=0xffffffffffffffff,hits=65535", spec, error));
    CHECK_EQ(spec.address, 0xffffffffffffffffULL);
    CHECK_EQ(spec.hits, 65535u);

    // step trace depth / budget: defaults, then the limits
    CHECK_EQ(spec.depth, 0u);
    CHECK_EQ(spec.steps, 256u);
    CHECK(sectepe::parse_breakpoint_spec("target=ep+0x0,action=step,depth=64,steps=4096", spec,
                                         error));
    CHECK_EQ(spec.depth, 64u);
    CHECK_EQ(spec.steps, 4096u);
    CHECK(sectepe::parse_breakpoint_spec("target=0x1,depth=0,steps=1", spec, error));
    CHECK_EQ(spec.depth, 0u);
    CHECK_EQ(spec.steps, 1u);

    const char* rejected[] = {
        "",                                          // nothing
        "action=trace",                              // no target
        "target=",                                   // empty target
        "target=0x",                                 // no digits
        "target=0x12345678901234567",                // 17 digits
        "target=401000",                             // not hex-prefixed
        "target=ep+0x123456789",                     // 9 offset digits
        "target=ep0x10",                             // no sign
        "target=kernel32!",                          // empty export
        "target=!CreateFileW",                       // empty module
        "target=ker nel32!CreateFileW",              // space in module
        "target=kernel32!Create File",               // space in export
        "target=kernel32!Create\"File",             // quote in export
        "target=0x401000,action=explode",            // unknown action
        "target=0x401000,access=read",               // read-only is not offered
        "target=0x401000,hits=65536",                // out of range
        "target=0x401000,hits=-1",                   // negative
        "target=0x401000,hits=",                     // empty
        "target=0x401000,hits=1,hits=2",             // duplicate key
        "target=0x401000,target=0x401004",           // duplicate target
        "target=0x401000,color=red",                 // unknown key
        "target=0x401000,depth=65",                  // depth out of range
        "target=0x401000,depth=1,depth=2",           // duplicate depth
        "target=0x401000,steps=0",                   // empty budget
        "target=0x401000,steps=4097",                // budget out of range
        "target=0x401000,steps=1e3",                 // not decimal
        "target=0x401000,",                          // trailing comma
        "target=0x401000,,action=trace",             // empty field
        "0x401000",                                  // no key
    };
    for (const char* text : rejected) {
        BreakpointSpec untouched;
        std::string why;
        ++g_checks;
        if (sectepe::parse_breakpoint_spec(text, untouched, why) || why.empty()) {
            ++g_failures;
            std::cerr << "FAIL " << __FILE__ << ":" << __LINE__ << ": spec '" << text
                      << "' should be rejected with a reason\n";
        }
    }

    // a rejected spec leaves the output untouched
    BreakpointSpec keep;
    keep.target = "kept";
    CHECK(!sectepe::parse_breakpoint_spec("target=0x1,action=explode", keep, error));
    CHECK_EQ(keep.target, std::string("kept"));
}

void test_breakpoint_json_escape() {
    CHECK_EQ(sectepe::json_escape("sample.exe"), std::string("sample.exe"));
    CHECK_EQ(sectepe::json_escape("a\"b\\c"), std::string("a\\\"b\\\\c"));
    CHECK_EQ(sectepe::json_escape("l1\nl2\t\r"), std::string("l1\\nl2\\t\\r"));
    CHECK_EQ(sectepe::json_escape(std::string("x\x01y", 3)), std::string("x\\u0001y"));
}

void test_step_classify() {
    using sectepe::classify;
    using sectepe::InsnKind;
    auto kind = [](std::initializer_list<uint8_t> bytes) {
        const std::vector<uint8_t> b(bytes);
        return classify(b.empty() ? nullptr : b.data(), b.size());
    };

    // call rel32, with and without a REX/operand-size prefix
    CHECK(kind({0xE8, 1, 2, 3, 4}).kind == InsnKind::Call);
    CHECK_EQ(kind({0xE8, 1, 2, 3, 4}).length, size_t(5));
    CHECK(kind({0xE8, 1, 2}).kind == InsnKind::Other); // truncated
    // call qword ptr [rip+disp32] (FF 15) - the usual import call
    CHECK_EQ(kind({0xFF, 0x15, 0, 0, 0, 0}).length, size_t(6));
    // call rax (FF D0), call r11 (41 FF D3)
    CHECK_EQ(kind({0xFF, 0xD0}).length, size_t(2));
    CHECK_EQ(kind({0x41, 0xFF, 0xD3}).length, size_t(3));
    // call [rax+rcx*8+0x10] (FF 54 C8 10): ModRM + SIB + disp8
    CHECK_EQ(kind({0xFF, 0x54, 0xC8, 0x10}).length, size_t(4));
    // call [rsp+disp32] (FF 94 24 xx xx xx xx)
    CHECK_EQ(kind({0xFF, 0x94, 0x24, 1, 2, 3, 4}).length, size_t(7));
    // call [disp32] via SIB without base (FF 14 25 xx xx xx xx)
    CHECK_EQ(kind({0xFF, 0x14, 0x25, 1, 2, 3, 4}).length, size_t(7));
    // cs-prefixed call (2E FF 15 ...)
    CHECK_EQ(kind({0x2E, 0xFF, 0x15, 0, 0, 0, 0}).length, size_t(7));
    // jmp [rip+x] (FF 25) and inc [rax] (FF 00) are not calls
    CHECK(kind({0xFF, 0x25, 0, 0, 0, 0}).kind == InsnKind::Other);
    CHECK(kind({0xFF, 0x00}).kind == InsnKind::Other);

    CHECK(kind({0xC3}).kind == InsnKind::Ret);
    CHECK(kind({0xF3, 0xC3}).kind == InsnKind::Ret); // rep ret
    CHECK_EQ(kind({0xC2, 0x08, 0x00}).length, size_t(3));
    CHECK(kind({0xC2, 0x08}).kind == InsnKind::Other);

    CHECK(kind({0x0F, 0x05}).kind == InsnKind::Syscall);
    CHECK(kind({0x0F, 0x34}).kind == InsnKind::Syscall);
    CHECK(kind({0xCD, 0x2E}).kind == InsnKind::Syscall);
    CHECK(kind({0xCD, 0x03}).kind == InsnKind::Other);
    CHECK(kind({0x0F, 0x1F, 0x00}).kind == InsnKind::Other); // nop

    CHECK(kind({0x48, 0x89, 0xE5}).kind == InsnKind::Other); // mov rbp, rsp
    CHECK(classify(nullptr, 0).kind == InsnKind::Other);
    CHECK_EQ(std::string(sectepe::insn_kind_name(InsnKind::Syscall)), std::string("syscall"));
    CHECK_EQ(sectepe::hex_bytes(std::vector<uint8_t>{0x0F, 0xAB}.data(), 2),
             std::string("0fab"));
}

// 32-bit code (WOW64): no REX, 0x40-0x4F are inc/dec; 66 and 67 change call
// lengths; call far ptr16:32 exists. classify(..., false).
void test_step_classify_x86() {
    using sectepe::classify;
    using sectepe::InsnKind;
    auto kind = [](std::initializer_list<uint8_t> bytes) {
        const std::vector<uint8_t> b(bytes);
        return classify(b.empty() ? nullptr : b.data(), b.size(), false);
    };

    // inc eax; ret -- in long mode 40 C3 is a REX-prefixed ret
    CHECK(kind({0x40, 0xC3}).kind == InsnKind::Other);
    CHECK(classify(std::vector<uint8_t>{0x40, 0xC3}.data(), 2).kind == InsnKind::Ret);
    // dec ecx; call ... is the dec, not a call
    CHECK(kind({0x49, 0xE8, 1, 2, 3, 4}).kind == InsnKind::Other);
    // call rel32, call dword ptr [disp32] (FF 15, the usual import call), call eax
    CHECK_EQ(kind({0xE8, 1, 2, 3, 4}).length, size_t(5));
    CHECK_EQ(kind({0xFF, 0x15, 0, 0x30, 0x40, 0}).length, size_t(6));
    CHECK_EQ(kind({0xFF, 0xD0}).length, size_t(2));
    // call rel16 (66 E8 xx xx): 4 bytes in 32-bit code, rel32 in long mode
    CHECK_EQ(kind({0x66, 0xE8, 1, 2}).length, size_t(4));
    CHECK_EQ(classify(std::vector<uint8_t>{0x66, 0xE8, 1, 2, 3, 4}.data(), 6).length,
             size_t(6));
    // 16-bit addressing (67): call word [bx+si+disp16] = 67 FF 90 xx xx
    CHECK_EQ(kind({0x67, 0xFF, 0x90, 1, 2}).length, size_t(5));
    // call [disp16] (67 FF 16 xx xx), call [bx+si] (67 FF 10)
    CHECK_EQ(kind({0x67, 0xFF, 0x16, 1, 2}).length, size_t(5));
    CHECK_EQ(kind({0x67, 0xFF, 0x10}).length, size_t(3));
    // call far ptr16:32 (9A, 7 bytes), with 66: ptr16:16 (6 bytes); invalid in long mode
    CHECK_EQ(kind({0x9A, 1, 2, 3, 4, 0x23, 0}).length, size_t(7));
    CHECK_EQ(kind({0x66, 0x9A, 1, 2, 0x23, 0}).length, size_t(6));
    CHECK(classify(std::vector<uint8_t>{0x9A, 1, 2, 3, 4, 0x23, 0}.data(), 7).kind ==
          InsnKind::Other);
    // ret, sysenter and int 0x2e as in long mode
    CHECK(kind({0xC3}).kind == InsnKind::Ret);
    CHECK_EQ(kind({0xC2, 0x10, 0x00}).length, size_t(3));
    CHECK(kind({0x0F, 0x34}).kind == InsnKind::Syscall);
    CHECK(kind({0xCD, 0x2E}).kind == InsnKind::Syscall);
}

void test_step_decide() {
    using sectepe::decide;
    using sectepe::Insn;
    using sectepe::InsnKind;
    using sectepe::StepAction;
    sectepe::StepPolicy flat; // depth 0, budget 256
    sectepe::StepPolicy deep;
    deep.depth = 1;

    const Insn call{InsnKind::Call, 5}, ret{InsnKind::Ret, 1}, sys{InsnKind::Syscall, 2},
        other{};

    // depth 0: calls are stepped over to the return address
    auto d = decide(call, 0x1000, 0, 1, flat);
    CHECK(d.action == StepAction::StepOver);
    CHECK_EQ(d.resume_at, 0x1005ULL);
    CHECK_EQ(d.depth, 0u);

    // depth 1: the first call is stepped into, the one below it over
    d = decide(call, 0x1000, 0, 1, deep);
    CHECK(d.action == StepAction::Continue);
    CHECK_EQ(d.depth, 1u);
    d = decide(call, 0x2000, 1, 2, deep);
    CHECK(d.action == StepAction::StepOver);

    // returning from a stepped-into call goes back up, from the hit function ends
    d = decide(ret, 0x2010, 1, 3, deep);
    CHECK(d.action == StepAction::Continue);
    CHECK_EQ(d.depth, 0u);
    d = decide(ret, 0x1010, 0, 4, deep);
    CHECK(d.action == StepAction::Stop);
    CHECK_EQ(std::string(d.reason), std::string("returned"));

    // system calls are always stepped over
    d = decide(sys, 0x3000, 0, 1, deep);
    CHECK(d.action == StepAction::StepOver);
    CHECK_EQ(d.resume_at, 0x3002ULL);

    CHECK(decide(other, 0x1, 0, 1, flat).action == StepAction::Continue);

    // the budget stops the trace, also instead of a step-over
    sectepe::StepPolicy small;
    small.budget = 2;
    CHECK(decide(other, 0x1, 0, 1, small).action == StepAction::Continue);
    d = decide(call, 0x1, 0, 2, small);
    CHECK(d.action == StepAction::Stop);
    CHECK_EQ(d.resume_at, 0ULL);
    CHECK_EQ(std::string(d.reason), std::string("step budget reached"));
}

void test_hit_args() {
    using sectepe::hit_args_json;
    using sectepe::hit_args_x64;
    using sectepe::hit_args_x86;

    // 64-bit code: the four argument registers, return address from [RSP].
    const uint64_t ret64 = 0x7ff6000012abULL;
    auto a = hit_args_x64(0x1, 0x2, 0x3, 0x4, &ret64);
    CHECK_EQ(hit_args_json(a),
             std::string(",\"mode\":\"x64\",\"ret\":\"0x7ff6000012ab\","
                         "\"args\":[\"0x1\",\"0x2\",\"0x3\",\"0x4\"]"));
    a = hit_args_x64(0x1, 0x2, 0x3, 0x4, nullptr);
    CHECK(!a.ret_known);
    CHECK(hit_args_json(a).find("\"ret\":null") != std::string::npos);

    // 32-bit (WOW64) CreateFileW: [ESP] = return address into the sample,
    // ESP+4.. = lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes.
    const uint32_t stack[] = {0x00401234, 0x0019f000, 0x40000000, 0x1, 0x0};
    a = hit_args_x86(stack, 5);
    CHECK(!a.x64);
    CHECK_EQ(a.ret, 0x401234ULL);
    CHECK_EQ(a.count, size_t(4));
    CHECK_EQ(hit_args_json(a),
             std::string(",\"mode\":\"x86\",\"ret\":\"0x401234\","
                         "\"args\":[\"0x19f000\",\"0x40000000\",\"0x1\",\"0x0\"]"));

    // Stack ends at an unreadable page after two words: what was read counts.
    a = hit_args_x86(stack, 2);
    CHECK_EQ(a.count, size_t(1));
    CHECK_EQ(a.args[0], 0x19f000ULL);
    // Nothing readable: no return address, no arguments -- never x64 registers.
    a = hit_args_x86(nullptr, 0);
    CHECK_EQ(hit_args_json(a), std::string(",\"mode\":\"x86\",\"ret\":null,\"args\":[]"));
}

int main() {
    test_linux_syscalls_x86_64();
    test_linux_syscalls_arm64();
    test_architecture_to_string();
    test_x86_syscall_abi_mapping();
    test_breakpoint_spec_parsing();
    test_breakpoint_json_escape();
    test_step_classify();
    test_step_classify_x86();
    test_step_decide();
    test_hit_args();

    std::cout << (g_failures == 0 ? "PASS" : "FAIL") << ": " << (g_checks - g_failures) << "/"
              << g_checks << " checks passed\n";
    return g_failures == 0 ? 0 : 1;
}
