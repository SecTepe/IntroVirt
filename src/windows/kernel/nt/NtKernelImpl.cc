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
#include "NtKernelImpl.hh"

#include "core/domain/DomainImpl.hh"
#include "core/injection/VcpuPauseGuard.hh"
#include "windows/WindowsGuestImpl.hh"
#include "windows/kernel/nt/types/HANDLE_TABLE_IMPL.hh"
#include "windows/kernel/nt/types/LDR_DATA_TABLE_ENTRY_IMPL.hh"

#include <introvirt/windows/WindowsGuest.hh>
#include <introvirt/windows/exception/SymbolNotFoundException.hh>
#include <introvirt/windows/kernel/ServiceDescriptorTable.hh>
#include <introvirt/windows/kernel/nt/types/CLIENT_ID.hh>
#include <introvirt/windows/kernel/nt/types/HANDLE_TABLE.hh>
#include <introvirt/windows/kernel/nt/types/HANDLE_TABLE_ENTRY.hh>
#include <introvirt/windows/kernel/nt/types/objects/DEVICE_OBJECT.hh>
#include <introvirt/windows/kernel/nt/types/objects/DRIVER_OBJECT.hh>
#include <introvirt/windows/kernel/nt/types/objects/OBJECT_DIRECTORY.hh>
#include <introvirt/windows/kernel/nt/types/objects/OBJECT_HEADER.hh>
#include <introvirt/windows/kernel/nt/types/objects/OBJECT_HEADER_NAME_INFO.hh>
#include <introvirt/windows/kernel/nt/types/objects/OBJECT_SYMBOLIC_LINK.hh>
#include <introvirt/windows/kernel/nt/types/objects/PROCESS.hh>
#include <introvirt/windows/kernel/nt/types/objects/THREAD.hh>

#include <introvirt/core/domain/Domain.hh>
#include <introvirt/core/domain/Vcpu.hh>
#include <introvirt/core/exception/GuestDetectionException.hh>
#include <introvirt/core/exception/VirtualAddressNotPresentException.hh>

#include <introvirt/util/compiler.hh>

#include "windows/kernel/nt/util/ListParser.hh"

#include <mspdb/PDB.hh>
#include <mspdb/pdb_exception.hh>

#include <optional>
#include <vector>

#include <boost/algorithm/string.hpp>
#include <log4cxx/logger.h>

#if __GNUC__ >= 8
#include <filesystem>
namespace filesystem = std::filesystem;
#else
#include <experimental/filesystem>
namespace filesystem = std::experimental::filesystem;
#endif

namespace introvirt {
namespace windows {
namespace nt {

static log4cxx::LoggerPtr
    logger(log4cxx::Logger::getLogger("introvirt.windows.kernel.nt.NtKernel"));

template <typename PtrType>
guest_ptr<void> NtKernelImpl<PtrType>::symbol(const std::string& name) const {
    const auto* symbol = pe_->pdb().name_to_symbol(name);
    if (!symbol)
        throw SymbolNotFoundException(name);
    return ptr_ + symbol->image_offset();
}

template <typename PtrType>
uint64_t NtKernelImpl<PtrType>::page_directory() const {
    return kernel_cr3_;
}

template <typename PtrType>
std::unique_ptr<HANDLE_TABLE> NtKernelImpl<PtrType>::CidTable() {
    const auto* const_this = this;
    auto const_result = const_this->CidTable();
    return std::unique_ptr<HANDLE_TABLE>(const_cast<HANDLE_TABLE*>(const_result.release()));
}

template <typename PtrType>
std::unique_ptr<const HANDLE_TABLE> NtKernelImpl<PtrType>::CidTable() const {
    guest_ptr<PtrType*, PtrType> ppPspCidTable(symbol("PspCidTable"));
    return std::make_unique<const HANDLE_TABLE_IMPL<PtrType>>(*this, *ppPspCidTable, true);
}

template <typename PtrType>
std::shared_ptr<OBJECT_DIRECTORY> NtKernelImpl<PtrType>::RootDirectoryObject() const {
    guest_ptr<PtrType*, PtrType> ppObpRootDirectoryObject(symbol("ObpRootDirectoryObject"));
    return OBJECT_DIRECTORY::make_shared(*this, *ppObpRootDirectoryObject);
}

template <typename PtrType>
std::vector<std::shared_ptr<const LDR_DATA_TABLE_ENTRY>>
NtKernelImpl<PtrType>::PsLoadedModuleList() const {
    const auto* offsets = LoadOffsets<structs::LDR_DATA_TABLE_ENTRY>(*this);
    const uint16_t list_offset = offsets->InLoadOrderLinks.offset();

    auto pPsLoadedModuleList = symbol("PsLoadedModuleList");

    std::vector<std::shared_ptr<const LDR_DATA_TABLE_ENTRY>> result;

    std::vector<guest_ptr<void>> addresses;

    // Parse all of the structure addresses
    if constexpr (is64Bit()) {
        addresses = parse_list_ptrtype<uint64_t>(pPsLoadedModuleList, list_offset);
    } else {
        addresses = parse_list_ptrtype<uint32_t>(pPsLoadedModuleList, list_offset);
    }

    // Create the entries
    for (const guest_ptr<void>& addr : addresses) {
        result.emplace_back(std::make_shared<LDR_DATA_TABLE_ENTRY_IMPL<PtrType>>(addr));
    }
    return result;
}

template <typename PtrType>
void NtKernelImpl<PtrType>::reparse_drive_letters() {
    drive_letters_.clear();

    // Holds our search result
    std::string result;

    auto globalDir = OBJECT_DIRECTORY::make_shared(*this, global_directory_address_);
    for (const std::shared_ptr<OBJECT>& object : globalDir->objects()) {
        try {
            const OBJECT_HEADER& hdr = object->header();
            if (hdr.type() != ObjectType::SymbolicLink)
                continue; // We only care about symbolic links

            // Object has to be named
            if (!hdr.has_name_info())
                continue;

            std::string name(hdr.NameInfo().Name());
            if (name.length() != 2 || name[1] != ':')
                continue; // Doesn't look like a drive letter

            boost::to_upper(name);
            if (!(name[0] >= 'A' && name[0] <= 'Z'))
                continue; // First character isnt a letter

            // Check to see if this is our result
            const auto* symLink = dynamic_cast<const OBJECT_SYMBOLIC_LINK*>(object.get());
            std::string target = boost::to_lower_copy(symLink->LinkTarget());
            LOG4CXX_DEBUG(logger, "Found drive " << name << " -> " << target);
            drive_letters_[target] = symLink->ptr();
        } catch (VirtualAddressNotPresentException& ex) {
            LOG4CXX_DEBUG(logger, ex.what());
        }
    }
}

template <typename PtrType>
std::string NtKernelImpl<PtrType>::get_device_drive_letter(const nt::DEVICE_OBJECT& device) const {
    switch (device.DeviceType()) {
    case DeviceType::FILE_DEVICE_DISK:
    case DeviceType::FILE_DEVICE_CD_ROM:
        break;
    default:
        // Not a device that will have a drive letter
        return "";
    }

    std::lock_guard lock(drive_letters_mtx_);

    const std::string device_path("\\device\\" + boost::to_lower_copy(device.DeviceName()));

    auto iter = drive_letters_.find(device_path);
    if (iter != drive_letters_.end()) {
        // Possible match
        const guest_ptr<void>& pSymbolicLink = iter->second;
        try {
            auto symbolicLink = OBJECT_SYMBOLIC_LINK::make_shared(*this, pSymbolicLink);
            return symbolicLink->header().NameInfo().Name();
        } catch (...) {
        }
    }

    // Didn't exist in our table, or the data was no longer valid
    // Update the entire table
    LOG4CXX_DEBUG(logger, "Reparsing drive letters for " << device_path);
    const_cast<NtKernelImpl<PtrType>*>(this)->reparse_drive_letters();

    // Look again
    iter = drive_letters_.find(device_path);
    if (iter != drive_letters_.end()) {
        // Possible match
        const guest_ptr<void>& pSymbolicLink = iter->second;
        try {
            auto symbolicLink = OBJECT_SYMBOLIC_LINK::make_shared(*this, pSymbolicLink);
            return symbolicLink->header().NameInfo().Name();
        } catch (...) {
        }
    }

    return "";
}

template <typename PtrType>
const ServiceDescriptorTable& NtKernelImpl<PtrType>::KeServiceDescriptorTable() const {
    return *KeServiceDescriptorTable_;
}

template <typename PtrType>
const ServiceDescriptorTable& NtKernelImpl<PtrType>::KeServiceDescriptorTableShadow() const {
    return *KeServiceDescriptorTableShadow_;
}

template <typename PtrType>
unsigned int NtKernelImpl<PtrType>::cpu_count() const {
    return cpu_count_;
}

template <typename PtrType>
const TypeTable& NtKernelImpl<PtrType>::types() const {
    return *type_table_;
}

template <typename PtrType>
bool NtKernelImpl<PtrType>::hasObHeaderCookie() const {
    return hasObHeaderCookie_;
}

template <typename PtrType>
uint8_t NtKernelImpl<PtrType>::ObHeaderCookie() const {
    return ObHeaderCookie_;
}

template <typename PtrType>
const WindowsGuest& NtKernelImpl<PtrType>::guest() const {
    return guest_;
}

template <typename PtrType>
KPCR& NtKernelImpl<PtrType>::kpcr(const Vcpu& vcpu) {
    return kpcrs_[vcpu.id()];
}

template <typename PtrType>
const KPCR& NtKernelImpl<PtrType>::kpcr(const Vcpu& vcpu) const {
    return kpcrs_[vcpu.id()];
}

template <typename PtrType>
const nt::NtBuildLab& NtKernelImpl<PtrType>::NtBuildLab() const {
    return *NtBuildLab_;
}

template <typename PtrType>
uint16_t NtKernelImpl<PtrType>::NtBuildNumber() const {
    return NtBuildNumber_;
}

template <typename PtrType>
uint16_t NtKernelImpl<PtrType>::MajorVersion() const {
    return MajorVersion_;
}

template <typename PtrType>
uint16_t NtKernelImpl<PtrType>::MinorVersion() const {
    return MinorVersion_;
}

template <typename PtrType>
bool NtKernelImpl<PtrType>::x64() const {
    return is64Bit();
}

template <typename PtrType>
const pe::PE& NtKernelImpl<PtrType>::pe() const {
    return *pe_;
}

template <typename PtrType>
const mspdb::PDB& NtKernelImpl<PtrType>::pdb() const {
    return pe().pdb();
}

template <typename PtrType>
const guest_ptr<void>& NtKernelImpl<PtrType>::ptr() const {
    return ptr_;
}

template <typename PtrType>
const DBGKD_GET_VERSION64& NtKernelImpl<PtrType>::KdVersionBlock() const {

    return *KdVersionBlock_;
}

template <typename PtrType>
const KDDEBUGGER_DATA64& NtKernelImpl<PtrType>::KdDebuggerDataBlock() const {
    return *KdDebuggerDataBlock_;
}

template <typename PtrType>
uint64_t NtKernelImpl<PtrType>::InvalidPteMask() const {
    return InvalidPteMask_;
}

template <typename PtrType>
std::shared_ptr<nt::THREAD> NtKernelImpl<PtrType>::thread(const guest_ptr<void>& ptr) const {
    std::lock_guard lock(threads_.mtx_);

    // TODO (papes): Need a way of expiring invalid weak pointers

    // Check if we already have an entry in the map
    auto iter = threads_.map_.find(ptr.address());
    if (iter != threads_.map_.end()) {
        // Yep, check if it's valid
        auto [tid, thread] = iter->second;
        if (thread->Cid().UniqueThread() == tid)
            return thread;
    }

    // Nope, create one
    auto result = nt::THREAD::make_shared(*this, ptr);
    threads_.map_[ptr.address()] = std::make_pair(result->Cid().UniqueThread(), result);

    return result;
}

template <typename PtrType>
std::shared_ptr<nt::PROCESS> NtKernelImpl<PtrType>::process(const guest_ptr<void>& ptr) const {
    std::lock_guard<decltype(procs_.mtx_)> lock(procs_.mtx_);

    // TODO (papes): Need a way of expiring invalid weak pointers

    // Check if we already have an entry in the map
    auto iter = procs_.map_.find(ptr.address());
    if (iter != procs_.map_.end()) {
        // Yep, check if it's valid
        auto [pid, proc] = iter->second;
        if (proc->UniqueProcessId() == pid)
            return proc;
    }

    // Nope, create one
    auto result = nt::PROCESS::make_shared(*this, ptr);
    procs_.map_[ptr.address()] = std::make_pair(result->UniqueProcessId(), result);
    return result;
}

template <typename PtrType>
std::string NtKernelImpl<PtrType>::profile_path() const {
    const auto* debug_directory = pe_->optional_header().debug_directory();
    introvirt_assert(debug_directory->Type() == pe::ImageDebugType::IMAGE_DEBUG_TYPE_CODEVIEW, "");
    const auto* cv_data = debug_directory->codeview_data();

    std::string pdb_identifier = boost::to_upper_copy(cv_data->PdbIdentifier());
    return "/var/lib/introvirt/profiles/windows/" + cv_data->PdbFileName() + "/" + pdb_identifier +
           "/";
}

template <typename PtrType>
NtKernelImpl<PtrType>::NtKernelImpl(WindowsGuest& guest) : guest_(guest) {
    Domain& domain = guest.domain();

    /*
     * SECTEPE (KPTI detect fix, measured 2026-06-16): the kernel-base MZ search
     * reads the kernel image through a vcpu's CR3. Under KPTI a vcpu caught at the
     * syscall entry trampoline has a kernel RIP but the *user* CR3 still loaded
     * (KiSystemCall64 swaps to the kernel CR3 a few instructions in), so the kernel
     * image is NOT mapped and the search finds no MZ -> GuestDetectionException ->
     * "Failed to detect guest operating system" for a boot-variable window.
     * Instrumentation showed vcpu0 repeatedly parked at LSTAR with the user-PCID
     * CR3 while another vcpu held a kernel-PCID CR3. So try EACH vcpu's CR3 (an
     * event vcpu first) until one maps the kernel, instead of relying on vcpu(0).
     */
    std::vector<Vcpu*> candidates;
    for (uint32_t i = 0; i < domain.vcpu_count(); ++i) // event vcpus first (index order)
        if (domain.vcpu(i).handling_event())
            candidates.push_back(&domain.vcpu(i));
    for (uint32_t i = 0; i < domain.vcpu_count(); ++i)
        if (!domain.vcpu(i).handling_event())
            candidates.push_back(&domain.vcpu(i));
    if (candidates.empty())
        throw GuestDetectionException(domain, "Guest has no vcpus to detect on");

    // Scan backward from a page-aligned kernel-code address `kbase` through an
    // explicit `cr3` looking for the ntoskrnl MZ/PE header; on success emplace pe_,
    // set kernel_base_addr, and return true. Shared by the CR3-WRITE hint path and
    // the live-vcpu fallback so both scan identically. Translation masks the CR3's
    // PCID bits internally, so `cr3` is passed raw (as registers().cr3() was).
    static const uint64_t MaxRange = 0x1000000;
    uint64_t kernel_base_addr = 0;
    auto try_scan = [&](uint64_t cr3, uint64_t kbase) -> bool {
        if (!kbase)
            return false;
        guest_ptr<uint16_t> search_ptr(domain, kbase, cr3);
        const uint64_t search_bottom = search_ptr.address() - MaxRange;
        while (search_ptr.address() > search_bottom) {
            try {
                if (unlikely(*search_ptr == 0x5a4D)) { // "MZ"
                    try {
                        static const std::set<std::string> ValidKernelNames{
                            "ntkrnlmp.pdb", "ntkrnlpa.pdb", "ntoskrnl.pdb", "ntkrpamp.pdb"};
                        pe_.emplace(search_ptr);
                        const auto* debug_directory = pe_->optional_header().debug_directory();
                        if (!debug_directory || debug_directory->Type() !=
                                                    pe::ImageDebugType::IMAGE_DEBUG_TYPE_CODEVIEW) {
                            search_ptr -= PageDirectory::PAGE_SIZE / sizeof(uint16_t);
                            continue;
                        }
                        const std::string pdb_filename =
                            debug_directory->codeview_data()->PdbFileName();
                        if (ValidKernelNames.count(pdb_filename) == 0) {
                            search_ptr -= PageDirectory::PAGE_SIZE / sizeof(uint16_t);
                            continue;
                        }
                        LOG4CXX_DEBUG(logger, "Found NT kernel (" << pdb_filename << ") at "
                                                                  << search_ptr);
                        kernel_base_addr = search_ptr.address();
                        return true;
                    } catch (pe::PeException& ex) {
                        LOG4CXX_DEBUG(logger, "Failed to parse PE at " + to_string(search_ptr));
                    } catch (VirtualAddressNotPresentException& ex) {
                        LOG4CXX_DEBUG(logger, ex.what());
                    }
                }
                search_ptr -= PageDirectory::PAGE_SIZE / sizeof(uint16_t);
            } catch (VirtualAddressNotPresentException& ex) {
                LOG4CXX_DEBUG(logger, ex.what());
            }
        }
        pe_.reset(); // clear any partial PE so the failure is unambiguous
        return false;
    };

    // MSR_LSTAR/SYSENTER (the syscall entry, in the kernel image) are per-CPU
    // identical; use any vcpu to get the page-aligned scan start.
    auto kbase_of = [](const Vcpu& v) -> uint64_t {
        const auto& r = v.registers();
        return std::max(r.msr(x86::Msr::MSR_LSTAR), r.msr(x86::Msr::MSR_IA32_SYSENTER_EIP)) &
               PageDirectory::PAGE_MASK;
    };

    bool detected = false;
    uint64_t chosen_cr3 = 0;
    std::optional<introvirt::inject::VcpuPauseGuard> guard;

    /*
     * PRIMARY (KPTI): detect_guest() captured the kernel CR3 from the guest's own
     * SWITCH_TO_KERNEL_CR3 on a syscall/interrupt entry (a CR3-WRITE event). Scan
     * the kernel base through it first. This is robust even when EVERY vcpu is in
     * user mode for the whole detection window -- the case that defeats sampling a
     * live vcpu CR3 -- because the guest itself was forced to load this kernel CR3.
     */
    const uint64_t hint = static_cast<DomainImpl&>(domain).detect_cr3_hint();
    if (hint) {
        Vcpu& ev = *candidates.front(); // event/first vcpu (registers readable)
        guard.emplace(ev);
        if (try_scan(hint, kbase_of(ev))) {
            chosen_cr3 = hint;
            detected = true;
            LOG4CXX_DEBUG(logger, "NT kernel detected via CR3-WRITE hint");
        } else {
            guard.reset();
        }
    }

    /*
     * FALLBACK: try each vcpu's live CR3 (the previous behaviour). Covers Win10 /
     * non-KPTI and the early window where a vcpu already holds a kernel CR3, plus
     * the case where no usable CR3-WRITE hint was captured. The guard holds the
     * winning vcpu paused for the rest of construction.
     */
    if (!detected) {
        for (Vcpu* cand : candidates) {
            guard.emplace(*cand);
            const uint64_t cand_cr3 = cand->registers().cr3();
            if (try_scan(cand_cr3, kbase_of(*cand))) {
                chosen_cr3 = cand_cr3;
                detected = true;
                break;
            }
            guard.reset();
        }
    }

    if (!detected)
        throw GuestDetectionException(domain, "Failed to find NT kernel base address");

    // Bind the kernel base through whichever CR3 mapped it (hint or live vcpu CR3).
    ptr_.reset(domain, kernel_base_addr, chosen_cr3);

    // SECTEPE: seed the stable kernel CR3 from the CR3 that mapped the kernel. The
    // KPCR stage below refines this to KernelDirectoryTableBase when available.
    kernel_cr3_ = chosen_cr3;

    filesystem::create_directories(profile_path());

    /*
     * Parse debugging structures
     */

    KdVersionBlock_.emplace(*this);
    KdDebuggerDataBlock_.emplace(*this);

    // Sanity check to make sure both structures agree
    if (KdVersionBlock().PsLoadedModuleList() != KdDebuggerDataBlock().PsLoadedModuleList()) {
        throw GuestDetectionException(domain, "PsLoadedModuleList mismatch");
    }

    /*
     * Parse the NtBuildLab and the NtBuildNumber
     */
    NtBuildLab_.emplace(KdDebuggerDataBlock().NtBuildLab());
    try {
        NtBuildNumber_ = *guest_ptr<uint16_t>(symbol("NtBuildNumber"));
        if (NtBuildLab().MajorBuildNumber() != NtBuildNumber()) {
            LOG4CXX_WARN(logger, "NtBuildLab disagrees with NtBuildNumber");
        }
    } catch (SymbolNotFoundException& ex) {
        LOG4CXX_WARN(logger, "Failed to read NtBuildNumber");
        NtBuildNumber_ = NtBuildLab().MajorBuildNumber();
    }

    MajorVersion_ = pe().optional_header().MajorImageVersion();
    MinorVersion_ = pe().optional_header().MinorImageVersion();

    if (MajorVersion() >= 10) {
        // Windows 10 has this ObHeaderCookie for "security".
        // It's easy to figure out with XOR, but we can just read the symbols.
        /* obHeaderCookie = ((pObjectHeader >> 8) & 0xFF) ^ hdr.getTypeIndex() ^ OBJECT_INDEX::Type;
         */
        try {
            ObHeaderCookie_ = *guest_ptr<uint8_t>(symbol("ObHeaderCookie"));
            hasObHeaderCookie_ = true;
            LOG4CXX_DEBUG(logger, "ObHeaderCookie: 0x"
                                      << std::hex << (static_cast<int>(ObHeaderCookie_) & 0xFF));
        } catch (SymbolNotFoundException& ex) {
            LOG4CXX_WARN(logger, "Failed to read ObHeaderCookie");
        }
    }

    // SECTEPE (KPTI detect window): read InvalidPteMask (the PTE swizzle mask) BEFORE
    // the type-table build so transition-PTE resolution can un-swizzle standby pages
    // during that build (and the GLOBAL??/KPCR/CidTable reads below). Previously this
    // ran after type_table_.emplace().
    try {
        // TODO: Move MI_SYSTEM_INFORMATION into it's own class
        const auto* MiState = LoadOffsets<structs::MI_SYSTEM_INFORMATION>(*this);
        if (MiState->InvalidPteMask.exists()) {
            guest_ptr<const char[]> MiStateBuffer(symbol("MiState"), MiState->size());
            if (MiState->InvalidPteMask.size() == 8) {
                InvalidPteMask_ = MiState->InvalidPteMask.template get<uint64_t>(MiStateBuffer);
            } else if (MiState->InvalidPteMask.size() == 4) {
                // Not 100% sure this can ever happen. Maybe on x32 with PAE disabled?
                InvalidPteMask_ = MiState->InvalidPteMask.template get<uint32_t>(MiStateBuffer);
            } else {
                LOG4CXX_WARN(logger, "Bad InvalidPteMask Size: " << MiState->InvalidPteMask.size());
            }
        }
    } catch (TypeInformationException& ex) {
        LOG4CXX_DEBUG(logger, ex.what());
    }

    // SECTEPE (KPTI detect window): the pool reads below (type table, object manager,
    // KPCR, CidTable) can hit standby/transition pages on a busy fresh boot.
    // detect_guest() has not yet assigned domain.guest(), so register this
    // under-construction guest and load the MM PTE offsets now; PageDirectory::translate
    // then resolves transition PTEs via WindowsGuestImpl::handle_page_fault. The RAII
    // scope tears the registration down on every ctor exit (normal return or throw).
    auto& wguest = static_cast<WindowsGuestImpl<PtrType>&>(guest);
    wguest.begin_detection_pte_resolution(*this);
    // Torn down at the end of this ctor on success, or in the WindowsGuestImpl ctor's
    // catch on failure (end_detection_pte_resolution() is a no-op if begin never ran).

    // Parse object types
    type_table_.emplace(*this);

    // Find the GLOBAL?? directory for drive letter mappings
    auto RootDirectory = RootDirectoryObject();
    const auto& objects = RootDirectory->objects();
    for (const std::shared_ptr<OBJECT>& object : objects) {
        if (object->header().type() == ObjectType::Directory) {
            if (object->header().has_name_info() &&
                object->header().NameInfo().Name() == "GLOBAL??") {
                // Found it
                global_directory_address_ = object->ptr();
                LOG4CXX_DEBUG(logger, "Found \\GLOBAL?? : " << global_directory_address_);
                LOG4CXX_DEBUG(logger, "Parsing drive letters");
                reparse_drive_letters();
            }
        }
    }
    if (unlikely(!global_directory_address_)) {
        throw GuestDetectionException(guest.domain(), "Failed to find GLOBAL?? directory");
    }

    // Detect the number of CPUs that Windows is using
    // This is because for licensing reasons, Windows will sometimes refuse to use a CPU,
    // leaving its PCR as null.
    cpu_count_ = *guest_ptr<uint32_t>(symbol("KeNumberProcessors"));

    if (unlikely(cpu_count() > domain.vcpu_count())) {
        throw GuestDetectionException(domain, "Guest reporting too many CPUs");
    }

    // Initialize the KPCRs
    /*
     * We do this in two stages, so that we can use the KernelDirectoryTableBase
     * from one to map in the others.
     *
     * This is to help with Spectre/Meltdown mitigations, where the CR3 value isn't
     * enough to let us map in the kernel address table.
     */
    const uint32_t vcpu_count = cpu_count();
    uint64_t KernelDirectoryTableBase = 0;
    kpcrs_.reserve(vcpu_count);

    // Stage one
    for (uint32_t i = 0; i < vcpu_count; ++i) {
        try {
            Vcpu& vcpu = guest.domain().vcpu(i);
            kpcrs_.emplace_back(*this, vcpu);
            if (!KernelDirectoryTableBase) {
                KernelDirectoryTableBase = kpcrs_.back().KernelDirectoryTableBase();
                if (!KernelDirectoryTableBase) {
                    // Meltdown/Spectre protection disabled. Use the CR3 value instead.
                    KernelDirectoryTableBase = vcpu.registers().cr3();
                }
            }
        } catch (TraceableException& ex) {
        }
    }

    // Stage two
    for (uint32_t i = kpcrs_.size(); i < vcpu_count; ++i) {
        Vcpu& vcpu = guest.domain().vcpu(i);
        kpcrs_.emplace_back(*this, vcpu, KernelDirectoryTableBase);
    }

    /*
     * SECTEPE (KPTI read-path fix): KernelDirectoryTableBase is the KPCR's stable
     * kernel-mapping CR3 (or, when Meltdown/Spectre mitigations are off, the live
     * CR3, which already maps the kernel). Adopt it as kernel_cr3_, the CR3 we hand
     * out via page_directory() for kernel-structure reads -- chiefly the runtime
     * KPCR_IMPL::reset() event path (see KPCR_IMPL.cc), which is where the live vcpu
     * CR3 can genuinely be the USER CR3 under KPTI.
     *
     * The ptr_ RE-POINT below is defensive: in THIS ctor the two CR3s are equal in
     * every reachable path, because the kernel-base MZ search above has no CR3
     * fallback and runs through the same bootstrap CR3 -- so a user-only CR3 would
     * have already thrown GuestDetectionException before we got here. Reaching this
     * line therefore implies ptr_ already maps the kernel, so ptr_.page_directory()
     * == kernel_cr3_ and the reset() is a no-op (downstream reads byte-for-byte
     * unchanged). Keep it as cheap insurance that future-proofs against a kernel-base
     * scan that ever gains a user-CR3 fallback.
     */
    if (KernelDirectoryTableBase) {
        kernel_cr3_ = KernelDirectoryTableBase;
        if (ptr_.page_directory() != kernel_cr3_) {
            LOG4CXX_DEBUG(logger, "Re-pointing kernel base from CR3 "
                                      << n2hexstr(ptr_.page_directory()) << " to kernel CR3 "
                                      << n2hexstr(kernel_cr3_));
            ptr_.reset(domain, ptr_.address(), kernel_cr3_);
        }
    }

    // Service tables
    KeServiceDescriptorTable_.emplace(symbol("KeServiceDescriptorTable"));
    LOG4CXX_DEBUG(logger, "Parsed KeServiceDescriptorTable with "
                              << KeServiceDescriptorTable().count() << " entries");

    guest_ptr<void> pKeServiceDescriptorTableShadow(symbol("KeServiceDescriptorTableShadow"));

    // The shadow service table isn't present in all processes
    // Try it with a bunch of them
    auto cid_table = CidTable();
    for (auto& entry : cid_table->open_handles()) {
        auto header = entry->ObjectHeader();
        if (header->type() == ObjectType::Process) {
            try {
                auto process = PROCESS::make_shared(*this, std::move(header));
                pKeServiceDescriptorTableShadow.reset(domain,
                                                      pKeServiceDescriptorTableShadow.address(),
                                                      process->DirectoryTableBase());
                KeServiceDescriptorTableShadow_.emplace(pKeServiceDescriptorTableShadow);
                break;
            } catch (VirtualAddressNotPresentException& ex) {
            }
        }
    }

    if (KeServiceDescriptorTableShadow_) {
        LOG4CXX_DEBUG(logger, "Parsed KeServiceDescriptorTableShadow with "
                                  << KeServiceDescriptorTableShadow().count() << " entries");
    } else {
        throw GuestDetectionException(domain, "Failed to parse KeServiceDescriptorTableShadow");
    }

    LOG4CXX_INFO(logger, "Detected Windows " << MajorVersion() << '.' << MinorVersion() << ' '
                                             << (is64Bit() ? "x64" : "x86") << " Build "
                                             << NtBuildNumber() << " Processors: " << cpu_count());

    // SECTEPE: detection complete -- stop resolving transition PTEs through the
    // under-construction guest. The WindowsGuestImpl ctor's catch does the same on
    // the failure path.
    wguest.end_detection_pte_resolution();
}

template <typename PtrType>
NtKernelImpl<PtrType>::~NtKernelImpl() = default;

template class NtKernelImpl<uint32_t>;
template class NtKernelImpl<uint64_t>;

} // namespace nt
} // namespace windows
} // namespace introvirt
