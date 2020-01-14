/* shc.c - Signed Hash Chain (SHC) implementation */
/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2019  codelabs GmbH
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
#include <grub/mm.h>
#include <grub/misc.h>
#include <grub/extcmd.h>
#include <grub/dl.h>

#include "csl.h"
#include "shc.h"

GRUB_MOD_LICENSE ("GPLv3+");

static struct shc_header_type header;

static grub_off_t encoded_file_size = 0;

struct reader_state_type {
	grub_file_t fd;
	grub_uint64_t bytes_in_block;
	grub_uint64_t bytes_read;
	unsigned int shc_valid;
	grub_uint8_t *next_hash;
};

static struct reader_state_type state = {
	.fd             = 0,
	.bytes_in_block = 0,
	.bytes_read     = 0,
	.shc_valid      = 0,
	.next_hash      = NULL,
};

static unsigned
block_data_len (void)
{
	return header.block_size - header.hashsum_len;
}

#define bdl block_data_len()

static unsigned prepare_first_block (void);

/* Invalidate global state and cleanup */
static void
invalidate (void)
{
	state.shc_valid = 0;
	if (state.next_hash)
	{
		grub_free (state.next_hash);
		state.next_hash = NULL;
	}
	grub_file_close (state.fd);
}

/*
 * Verify header signature, returns 1 and sets shc_valid to 1 if verification
 * succeeds, 0 otherwise.
 */
static unsigned
verify (void)
{
	// TODO check signature
	state.shc_valid = 1;
	return 1;
}

static unsigned
read_hash (void)
{
	if (grub_file_read (state.fd, state.next_hash, header.hashsum_len)
			!= header.hashsum_len)
	{
		grub_printf ("SHC - unable to read block hash value\n");
		return 0;
	}
	return 1;
}

static unsigned
prepare_first_block (void)
{
	grub_uint8_t byte;
	unsigned int i;

	/* validate if first block data matches root hash */
	// TODO

	/* store hash of next block in global state */
	if (! read_hash ())
		return 0;

	/* skip initial padding bytes */
	for (i = 1; i <= header.padding_len; i++)
		grub_file_read (state.fd, &byte, 1);

	state.bytes_in_block = bdl - header.padding_len;
	return 1;
}

static unsigned
prepare_next_block (void)
{
	/* check if hash value is correct */
	//TODO

	/* store next hash in global state */
	if (! read_hash ())
		return 0;

	state.bytes_in_block = bdl;
	return 1;
}

static grub_file_t
shc_open (const char *name,
		enum grub_file_type type __attribute__ ((unused)))
{
	state.fd = grub_file_open (name, GRUB_FILE_TYPE_NONE);
	if (! state.fd) {
		grub_printf ("SHC - unable to open '%s'\n", name);
		return NULL;
	}

	if (grub_file_read (state.fd, &header, SHC_HEADER_SIZE) != SHC_HEADER_SIZE) {
		grub_printf ("SHC - unable to read header data, not a chain?\n");
		grub_file_close (state.fd);
		return NULL;
	}

	if (header.version_magic != SHC_VERMAGIC) {
		grub_printf ("SHC - version magic mismatch [got: 0x%x, expected: 0x%x]\n",
				header.version_magic, SHC_VERMAGIC);
		grub_file_close (state.fd);
		return NULL;
	}

	grub_printf ("SHC - block count       : %u\n", header.block_count);
	grub_printf ("SHC - initial padding   : %u\n", header.padding_len);
	grub_printf ("SHC - block size        : %u\n", header.block_size);
	grub_printf ("SHC - hashsum length    : %u\n", header.hashsum_len);
	grub_printf ("SHC - block data length : %u\n", bdl);

	encoded_file_size = header.block_count * bdl - header.padding_len;
	grub_printf ("SHC - encoded file size : %llu\n", encoded_file_size);

	if (! verify ()) {
		grub_file_close (state.fd);
		return NULL;
	}

	state.next_hash = grub_malloc (header.hashsum_len);
	if (state.next_hash == NULL) {
		grub_printf ("SHC - error allocating storage for hashsum\n");
		invalidate ();
		return NULL;
	}
	if (! prepare_first_block ()) {
		invalidate ();
		return NULL;
	}

	//TODO: or should we return some dummy pointer?
	return state.fd;
}

static grub_off_t
shc_size (grub_file_t file __attribute__ ((unused)))
{
	if (!state.shc_valid)
		return 0;

	return encoded_file_size;
}

static grub_ssize_t
shc_read (grub_file_t file __attribute__ ((unused)),
		void *buf,
		grub_size_t len)
{
	grub_size_t to_read = len;
	void *ptr = buf;

	if (! state.shc_valid)
		return -1;

	if (state.bytes_read >= shc_size (state.fd))
		return 0;

	if (! state.bytes_in_block)
		if (! prepare_next_block ())
			goto invalid;

	while (to_read) {
		if (to_read >= state.bytes_in_block)
	   	{
			if (grub_file_read (state.fd, ptr, state.bytes_in_block) 
					!= (grub_ssize_t) state.bytes_in_block)
				goto invalid;
			ptr = (grub_uint8_t *) ptr + state.bytes_in_block;
			to_read -= state.bytes_in_block;
			if (to_read)
				if (! prepare_next_block ())
					goto invalid;
		} 
		else
	   	{
			state.bytes_in_block -= to_read;
			if (grub_file_read (state.fd, ptr, to_read)
					!= (grub_ssize_t) to_read)
				goto invalid;
			to_read = 0;
		}
	}

	state.bytes_read += len;
	return len;

invalid:
	grub_printf("SHC - error in block read\n");
	invalidate();
	return -1;
}

static grub_err_t
shc_close (grub_file_t file)
{
	if (!state.shc_valid)
		return GRUB_ERR_NONE;

	return grub_file_close(file);
}

static grub_err_t
shc_init (grub_extcmd_context_t ctxt __attribute__ ((unused)),
		int argc __attribute__ ((unused)),
		char **argv __attribute__ ((unused)))
{
	grub_printf("SHC - Overriding CSL file ops...\n");
	csl_fs_ops.open  = shc_open;
	csl_fs_ops.read  = shc_read;
	csl_fs_ops.size  = shc_size;
	csl_fs_ops.close = shc_close;

	return GRUB_ERR_NONE;
}

static grub_extcmd_t cmd;

GRUB_MOD_INIT(shc)
{
	cmd = grub_register_extcmd ("shc_init", shc_init, 0, 0,
			"Initialize Signed Hash Chain (SHC) processing.", 0);
}

GRUB_MOD_FINI(shc)
{
	grub_unregister_extcmd (cmd);
}
