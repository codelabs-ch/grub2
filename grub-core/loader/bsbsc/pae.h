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

#ifndef PAE_H
#define PAE_H

#include <grub/file.h>

/* Fill memory specified by physical address and length with a constant byte. */
void memset_pae (grub_uint64_t dest, unsigned char pat, grub_uint64_t length);

/*
 * Use given function read_func to read length bytes from file to physical
 * address destination.
 */
grub_int64_t
read_pae (grub_file_t file, grub_uint64_t dest, grub_uint64_t length,
		grub_ssize_t (*read_func) (grub_file_t file, void *buf, grub_size_t len));

#endif /* PAE_H  */
