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

class Vcpu;

/**
 * @brief Architecture-neutral guest virtual -> guest-physical translator.
 *
 * Abstracts the per-architecture page-table walk so callers can translate a
 * guest VA without assuming x86. The x86 walker (@ref x86::PageDirectory)
 * derives from this and keeps its existing behaviour and call sites unchanged;
 * the AArch64 walker (`TTBR0/1_EL1`, `TCR_EL1` granule/levels) lands in Phase 3
 * of the arm64 port (see docs/introvirt-arm64.md).
 *
 * This is the page-table-walk sibling of @ref RegisterContext: an arch-neutral
 * base that is host-arch-independent (no `__x86_64__` guard) so it is available
 * regardless of the build target.
 *
 * Note: page geometry (page size / shift) is intentionally NOT exposed here yet.
 * x86 uses fixed 4 KiB pages via the compile-time `x86::PageDirectory::PAGE_*`
 * constants on the concrete class; generalising those to a runtime granule
 * (AArch64 4K/16K/64K) is Phase 3 work, tied to making `guest_ptr` arch-aware.
 */
class PageTableWalker {
  public:
    /**
     * @brief The architecture of this walker.
     */
    virtual Architecture architecture() const = 0;

    /**
     * @brief Convert a guest virtual address to a guest-physical address.
     *
     * @param virtual_address The guest virtual address to translate
     * @param page_table_base The page-table base to walk from (x86: CR3;
     *        AArch64: TTBR0_EL1 / TTBR1_EL1)
     * @return The translated guest-physical address
     * @throws VirtualAddressNotPresentException If the VA is not present
     */
    virtual uint64_t translate(uint64_t virtual_address, uint64_t page_table_base) const = 0;

    /**
     * @brief Re-read mode-dependent geometry from the vcpu.
     *
     * x86 derives the level count from `EFER.LMA` / `CR4.PAE` (2/3/4 levels);
     * AArch64 will read `TCR_EL1` (granule, T0SZ/T1SZ) in Phase 3.
     */
    virtual void reconfigure(const Vcpu& vcpu) = 0;

    /**
     * @brief Destroy the instance
     */
    virtual ~PageTableWalker() = default;
};

} // namespace introvirt
