/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2024  codelabs GmbH
 *
 *  GRUB is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  GRUB is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with GRUB.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <grub/types.h>
#include <grub/misc.h>
#include <grub/mm.h>
#include <grub/i386/relocator.h>

#include "pae.h"

typedef unsigned long uintptr_t;

#define PDPTE_PRES	(1ULL << 0)

#define PDE_PRES	(1ULL << 0)
#define PDE_RW		(1ULL << 1)
#define PDE_PS		(1ULL << 7)

#define PDE_IDX_SHIFT 21

#define CR0_PG	(1 << 31)
#define CR4_PAE	(1 <<  5)

#ifdef __x86_64__
#define CRx_TYPE grub_uint64_t
#else
#define CRx_TYPE grub_uint32_t
#endif

static const grub_size_t MiB = (1<<20);
static const grub_size_t s2MiB = 2 * MiB;

struct pde {
	grub_uint32_t addr_lo;
	grub_uint32_t addr_hi;
} __attribute__ ((packed));

struct pg_table {
	struct pde pd[2048];
	struct pde pdp[4];
} __attribute__ ((packed, aligned (4096)));

/* Page table instance. */
static struct pg_table pgtbl;
static unsigned int pgtbl_initialized = 0;

/* Relocator chunk for 2 MiB window */
static grub_relocator_chunk_t chunk;
static bool chunk_allocated = false;

static inline CRx_TYPE read_cr0 (void) __attribute__((always_inline));
static inline CRx_TYPE read_cr4 (void) __attribute__((always_inline));
static inline void write_cr0 (CRx_TYPE data) __attribute__((always_inline));
static inline void write_cr3 (CRx_TYPE data) __attribute__((always_inline));
static inline void write_cr4 (CRx_TYPE data) __attribute__((always_inline));

static inline CRx_TYPE read_cr0 (void)
{
	CRx_TYPE value;
	asm volatile (
		"mov %%cr0, %0"
		: "=r"(value)
		:
		: "memory"
	);
	return value;
}

static inline CRx_TYPE read_cr4 (void)
{
	CRx_TYPE value;
	asm volatile (
		"mov %%cr4, %0"
		: "=r"(value)
		:
		: "memory"
	);
	return value;
}

static inline void write_cr0 (CRx_TYPE data)
{
	asm volatile (
		"mov %0, %%cr0"
		:
		: "r"(data)
		: "memory"
	);
}

static inline void write_cr3 (CRx_TYPE data)
{
	asm volatile (
		"mov %0, %%cr3"
		:
		: "r"(data)
		: "memory"
	);
}

static inline void write_cr4 (CRx_TYPE data)
{
	asm volatile (
		"mov %0, %%cr4"
		:
		: "r"(data)
		: "memory"
	);
}

static void paging_enable_pae (void)
{
	CRx_TYPE cr0;
	CRx_TYPE cr4;

	/* Enable PAE */
	cr4 = read_cr4 ();

	cr4 |= CR4_PAE;
	write_cr4 (cr4);

	/* Enable Paging */
	cr0 = read_cr0 ();
	cr0 |= CR0_PG;
	write_cr0 (cr0);
}

static void paging_enable_pae_cr3 (uintptr_t cr3)
{
	/* Load the page table address */
	write_cr3 (cr3);
	paging_enable_pae ();
}

static void paging_disable_pae (void)
{
	CRx_TYPE cr0;
	CRx_TYPE cr4;

	/* Disable Paging */
	cr0 = read_cr0 ();
	cr0 &= ~(CRx_TYPE)CR0_PG;
	write_cr0 (cr0);

	/* Disable PAE */
	cr4 = read_cr4 ();
	cr4 &= ~(CRx_TYPE)CR4_PAE;
	write_cr4 (cr4);
}

/*
 * Initialize page table instance pgtbl with an identity map of the 32-bit
 * address space.
 */
static void identity_paging_init (void)
{
	struct pde *pd = (struct pde *)&pgtbl.pd, *pdp = (struct pde *)&pgtbl.pdp;
	/* Point the page directory pointers at the page directories. */
	grub_memset (&pgtbl.pdp, 0, sizeof (pgtbl.pdp));

	pdp[0].addr_lo = ((uintptr_t)&pd[512*0]) | PDPTE_PRES;
	pdp[1].addr_lo = ((uintptr_t)&pd[512*1]) | PDPTE_PRES;
	pdp[2].addr_lo = ((uintptr_t)&pd[512*2]) | PDPTE_PRES;
	pdp[3].addr_lo = ((uintptr_t)&pd[512*3]) | PDPTE_PRES;

	for (grub_size_t i = 0; i < 2048; i++)
	{
		pd[i].addr_lo = (i << PDE_IDX_SHIFT) | PDE_PS | PDE_PRES | PDE_RW;
		pd[i].addr_hi = 0;
	}
}

/*
 * Use relocator to allocate a 2 MiB chunk for PAE window.
 *
 * Required to avoid overlap with regions allocated by GRUB, and to fulfill the
 * 2 MiB alignment constraint. Returns error if the chunk could not be
 * allocated.
 *
 * Note: The 2 MiB chunk is not freed explicitly, because grub_relocator_unload
 *       is just too problematic. If you wonder why, just look at the
 *       free_subchunk() code.
 */
static grub_err_t get_vmem (void)
{
	grub_err_t err;
	struct grub_relocator *rel;

	if (chunk_allocated)
	{
		return GRUB_ERR_NONE;
	}

	rel = grub_relocator_new ();
	if (!rel)
	{
		grub_fatal ("%s: Unable to create relocator\n", __func__);
		return grub_errno;
	}

	err = grub_relocator_alloc_chunk_align_safe (rel, &chunk, 0,
												 UP_TO_TOP32 (s2MiB),
												 s2MiB, s2MiB,
												 GRUB_RELOCATOR_PREFERENCE_NONE, 1);
	if (err)
		return err;

	chunk_allocated = true;
	return GRUB_ERR_NONE;
}

/*
 * Add mapping for given phys address to specified page directory entry pd.
 *
 * Note 1: No invalidation of a virtual address is performed!
 * Note 2: If a mapping is not identity, make sure to restore it to the initial
 *         value after memory operations, otherwise GRUB's mm code breaks.
 */
static void map_page (struct pde *const pd, grub_uint64_t phys)
{
	pd->addr_lo = phys | PDE_PS | PDE_RW | PDE_PRES;
	pd->addr_hi = phys >> 32;
}

void memset_pae (grub_uint64_t dest, unsigned char pat, grub_uint64_t length)
{
	grub_ssize_t offset;

	if (get_vmem ())
	{
	    grub_fatal ("%s: Unable to allocate 2 MiB chunk for PAE window", __func__);
	    return;
	}
	const uintptr_t vmem_addr = (uintptr_t)get_virtual_current_address (chunk);

	if (!pgtbl_initialized)
	{
		identity_paging_init ();
		pgtbl_initialized = 1;
	}
	struct pde *const pd = &pgtbl.pd[vmem_addr >> PDE_IDX_SHIFT];
	const grub_uint32_t orig_addr_lo = pd->addr_lo;
	const grub_uint32_t orig_addr_hi = pd->addr_hi;

	offset = dest - ALIGN_DOWN (dest, s2MiB);
	dest = ALIGN_DOWN (dest, s2MiB);

	do
	{
		const grub_size_t len = grub_min (length, s2MiB - offset);

		map_page (pd, dest);
		grub_printf ("%s: Mapped 0x%" PRIxGRUB_UINT64_T "[0x%lx] - 0x%"
					 PRIxGRUB_SIZE "\n", __func__, dest + offset,
					 vmem_addr + offset, len);

		/*
		 * Note: No VGA-based logging is possible after PAE enablement, as it
		 * requires BIOS services (realmode).
		 */
		paging_enable_pae_cr3 ((uintptr_t)&pgtbl.pdp);
		grub_memset ((void *)(vmem_addr + offset), pat, len);
		paging_disable_pae ();
		/* VGA-logging works again */

		dest += s2MiB;
		length -= len;
		offset = 0;
	} while (length > 0);

	pd->addr_lo = orig_addr_lo;
	pd->addr_hi = orig_addr_hi;
}

grub_int64_t
read_pae (grub_file_t file, grub_uint64_t dest, grub_uint64_t length,
		grub_ssize_t (*read_func)(grub_file_t file, void *buf, grub_size_t len))
{
	grub_int64_t ret = length;
	grub_ssize_t offset;
	char *tmp_buf = NULL;

	if (read_func == NULL)
		return -1;

	if (get_vmem ())
	{
	    grub_fatal ("%s: Unable to allocate 2 MiB chunk for PAE window", __func__);
	    return -1;
	}
	const uintptr_t vmem_addr = (uintptr_t)get_virtual_current_address (chunk);

	if (!pgtbl_initialized)
	{
		identity_paging_init ();
		pgtbl_initialized = 1;
	}
	struct pde *const pd = &pgtbl.pd[vmem_addr >> PDE_IDX_SHIFT];
	const grub_uint32_t orig_addr_lo = pd->addr_lo;
	const grub_uint32_t orig_addr_hi = pd->addr_hi;

	/*
	 * In contrast to memset_pae, a temporary buffer is required here because
	 * grub_file_read, depending on the boot media, might switch to realmode
	 * to actually read the data, i.e. for biosdisk it uses int 13 via
	 * grub_bios_interrupt. See also PROT_TO_REAL, REAL_TO_PROT in
	 * i386/realmode.S.
	 *
	 * As this breaks PAE, use a temporary buffer with PAE disabled and copy the
	 * data to the destination in a second step.
	 */
	tmp_buf = grub_malloc (s2MiB);
	if (!tmp_buf)
	{
		grub_fatal ("%s: Unable to allocate temporary buffer\n", __func__);
		return grub_errno;
	}

	offset = dest - ALIGN_DOWN (dest, s2MiB);
	dest = ALIGN_DOWN (dest, s2MiB);

	do {
		const grub_size_t len = grub_min (length, s2MiB - offset);

		const int err = read_func (file, tmp_buf, len);
		if (err < 0)
		{
			ret = err;
			goto _free_ret;
		}
		else if (err != (int)len)
		{
			ret -= length - (grub_size_t)err;
			goto _free_ret;
		}

		map_page (pd, dest);
		grub_printf ("%s: Mapped 0x%" PRIxGRUB_UINT64_T "[0x%lx] - 0x%"
					 PRIxGRUB_SIZE "\n", __func__, dest + offset,
					 vmem_addr + offset, len);

		/*
		 * Note: No VGA-based logging is possible after PAE enablement, as it
		 * requires BIOS services (realmode).
		 */
		paging_enable_pae_cr3 ((uintptr_t)&pgtbl.pdp);
		/* Copy data to actual destination */
		grub_memcpy ((void *)(vmem_addr + offset), tmp_buf, len);
		paging_disable_pae ();
		/* VGA-logging works again */

		dest += s2MiB;
		length -= len;
		offset = 0;
	} while (length > 0);

_free_ret:
	grub_free (tmp_buf);
	tmp_buf = NULL;

	paging_disable_pae ();
	pd->addr_lo = orig_addr_lo;
	pd->addr_hi = orig_addr_hi;

	return ret;
}
