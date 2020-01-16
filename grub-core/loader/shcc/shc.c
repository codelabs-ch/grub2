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
#include <grub/crypto.h>

#include "csl.h"
#include "shc.h"

GRUB_MOD_LICENSE ("GPLv3+");

#define SHA512_HASHSUM_LEN 64

static struct shc_header_t header = {
	.root_hash = NULL,
};

static grub_off_t encoded_file_size = 0;

struct reader_state_type {
	grub_file_t fd;
	grub_uint64_t total_bytes_read;
	unsigned int shc_valid;
	grub_uint8_t next_hash[SHA512_HASHSUM_LEN];
	grub_uint8_t *read_pos;
	grub_uint8_t *data;
};

static struct reader_state_type state = {
	.fd               = 0,
	.total_bytes_read = 0,
	.shc_valid        = 0,
	.read_pos         = NULL,
	.data             = NULL,
};

static const gcry_md_spec_t *hasher = NULL;
static void *hash_ctx = NULL;

static inline grub_uint32_t
block_data_len (void)
{
	return header.block_size - header.hashsum_len;
}
#define bdl block_data_len()

static inline grub_uint32_t
buffer_bytes (void)
{
	return bdl - (state.read_pos - state.data);
}

static inline unsigned
buffer_empty (void)
{
	return buffer_bytes() == 0;
}

/* Invalidate global state and cleanup */
static void
invalidate (void)
{
	state.shc_valid = 0;
	if (state.data)
	{
		grub_free (state.data);
		state.data = NULL;
	}
	if (header.root_hash)
	{
		grub_free (header.root_hash);
		header.root_hash = NULL;
	}

	// TODO hasher cleanup
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

static void
print_hash (const grub_uint8_t * const h)
{
	unsigned i;
	grub_printf ("0x");
	for (i = 0; i < SHA512_HASHSUM_LEN; i++)
		grub_printf ("%02x", h[i]);
}

static unsigned
read_block (void)
{
	if (grub_file_read (state.fd, state.next_hash, header.hashsum_len)
			!= header.hashsum_len)
	{
		grub_printf ("SHC - unable to read block hash value\n");
		return 0;
	}
	if (grub_file_read (state.fd, state.data, bdl) != (grub_ssize_t) bdl)
	{
		grub_printf ("SHC - unable to read block data\n");
		return 0;
	}
	return 1;
}

static unsigned
hash_valid (const grub_uint8_t * const h)
{
	unsigned res = 0;

	hasher->init (hash_ctx);

	// TODO:move to init, also cleanup.
	// TODO:check all results
	hasher->write (hash_ctx, state.next_hash, SHA512_HASHSUM_LEN);
	hasher->write (hash_ctx, state.data, bdl);

	hasher->final(hash_ctx);

	if (grub_crypto_memcmp (h, hasher->read (hash_ctx), hasher->mdlen) == 0)
	{
		res = 1;
	}
	else
	{
		grub_printf ("SHC - ERROR invalid hash detected\n");
		grub_printf ("SHC - computed hash ");
		print_hash (hasher->read (hash_ctx));
		grub_printf ("\n");
		grub_printf ("SHC - stored hash ");
		print_hash (h);
		grub_printf ("\n");
	}

	grub_memset (hash_ctx, 0, hasher->contextsize);
	return res;
}

static unsigned
load_next_block (const grub_uint32_t offset __attribute__ ((unused)))
{
	grub_uint8_t current_hash[SHA512_HASHSUM_LEN];

	// TODO check result
	grub_memcpy (current_hash, state.next_hash, SHA512_HASHSUM_LEN);

	if (! read_block())
		return 0;

	if (! hash_valid (current_hash))
		return 0;

	grub_printf ("state.data %p\n", state.data);
	grub_printf ("offset %u\n", offset);
	state.read_pos = state.data + offset;
	grub_printf ("state.read_pos %p\n", state.read_pos);
	return 1;
}

static unsigned
read_field (void *field,
		const grub_ssize_t width,
		const char * const err_msg)
{
	if (grub_file_read (state.fd, field, width) != width)
	{
		grub_printf ("SHC - %s\n", err_msg);
		goto header_invalid;
	}

	return 1;

header_invalid:
	grub_file_close (state.fd);
	return 0;
}

static unsigned
read_header (void)
{
	if (! read_field (&header.version_magic, 4, "unable to read version magic"))
		return 0;
	if (header.version_magic != SHC_VERMAGIC)
	{
		grub_printf ("SHC - version magic mismatch [got: 0x%x, expected: 0x%x]\n",
				header.version_magic, SHC_VERMAGIC);
		goto header_invalid;
	}

	if (! read_field (&header.block_count, 4, "unable to read block_count"))
		return 0;
	if (! read_field (&header.block_size, 4, "unable to read block size"))
		return 0;
	if (! read_field (&header.sig_len, 4, "unable to read signature length"))
		return 0;
	if (! read_field (&header.header_size, 2, "unable to read header size"))
		return 0;
	if (! read_field (&header.hashsum_len, 2, "unable to read hashsum length"))
		return 0;
	if (! read_field (&header.hash_algo_id_1, 2, "unable to read hash ID 1"))
		return 0;
	if (! read_field (&header.hash_algo_id_2, 2, "unable to read hash ID 2"))
		return 0;
	if (! read_field (&header.hash_algo_id_3, 2, "unable to read hash ID 3"))
		return 0;
	if (! read_field (&header.hash_algo_id_4, 2, "unable to read hash ID 4"))
		return 0;
	if (! read_field (&header.sig_algo_id, 2, "unable to read signature ID"))
		return 0;
	if (! read_field (&header.reserved, 2, "unable to read reserved field"))
		return 0;
	if (! read_field (&header.padding_len, 4, "unable to read padding length"))
		return 0;

	if (! (header.hash_algo_id_1 == SHC_HASH_ALGO_SHA2_512
				&& header.hash_algo_id_2 == SHC_HASH_ALGO_NONE
				&& header.hash_algo_id_3 == SHC_HASH_ALGO_NONE
				&& header.hash_algo_id_4 == SHC_HASH_ALGO_NONE))
	{
		grub_printf ("SHC - unsupported hash algorithm config "
				"(1: %u, 2: %u, 3: %u, 4: %u)\n",
				header.hash_algo_id_1, header.hash_algo_id_2,
				header.hash_algo_id_3, header.hash_algo_id_4);
		goto header_invalid;
	}
	if (header.hashsum_len != SHA512_HASHSUM_LEN) {
		grub_printf ("SHC - unexpected hashsum length %u, expected %u\n",
				header.hashsum_len, SHA512_HASHSUM_LEN);
		goto header_invalid;
	}

	header.root_hash = grub_malloc (header.hashsum_len);
	if (! header.root_hash) {
		grub_printf ("SHC - unable to allocate bytes for root hash\n");
		goto header_invalid;
	}
	if (! read_field (header.root_hash, header.hashsum_len,
				"unable to read root hash")) {
		grub_free (header.root_hash);
		return 0;
	}

	return 1;

header_invalid:
	grub_file_close (state.fd);
	return 0;
}

static grub_uint32_t
copy_buffer (void *ptr, grub_uint32_t len)
{
	if (buffer_bytes () < len)
		return 0;

	// TODO check result
	grub_memcpy (ptr, state.read_pos, len);
	state.read_pos += len;
	return len;
}

static grub_file_t
shc_open (const char *name,
		enum grub_file_type type __attribute__ ((unused)))
{
	state.fd = grub_file_open (name, GRUB_FILE_TYPE_NONE);

	if (! state.fd)
	{
		grub_printf ("SHC - unable to open '%s'\n", name);
		return NULL;
	}

	if (! read_header ())
		return NULL;

	if (! verify ()) {
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

	grub_printf ("SHC - root hash         : ");
	print_hash(header.root_hash);
	grub_printf ("\n");

	state.data = grub_malloc (bdl);
	if (state.data == NULL) {
		grub_printf ("SHC - error allocating data buffer\n");
		invalidate ();
		return NULL;
	}

	/* set root hash as next hash and load first block */
	// TODO check result?
	grub_memcpy (state.next_hash, header.root_hash, SHA512_HASHSUM_LEN);
	if (! load_next_block (header.padding_len)) {
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
		void *buf __attribute__ ((unused)),
		grub_size_t len)
{
	grub_size_t to_read = len;
	void *ptr = buf;
	grub_uint32_t copied;

	if (! state.shc_valid)
		return -1;

	if (state.total_bytes_read >= shc_size (state.fd))
		return 0;

	if (buffer_empty())
		if (! load_next_block (0))
			goto invalid;

	while (to_read) {
		if (to_read >= buffer_bytes ())
	   	{
			copied = copy_buffer (ptr, buffer_bytes ());
			if (! copied)
				goto invalid;
			ptr = (grub_uint8_t *) ptr + copied;
			to_read -= copied;
			if (to_read)
				if (! load_next_block (0))
					goto invalid;
		}
		else
	   	{
			copied = copy_buffer (ptr, to_read);
			if (! copied)
				goto invalid;
			to_read = 0;
		}
	}

	state.total_bytes_read += len;
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

	return grub_file_close (file);
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

	hasher = grub_crypto_lookup_md_by_name ("sha512");
	if (!hasher)
		return grub_error (GRUB_ERR_BAD_ARGUMENT, "hasher init failed");

	hash_ctx = grub_zalloc (hasher->contextsize);
	if (!hash_ctx)
		return grub_error (GRUB_ERR_BAD_ARGUMENT, "hasher ctx init failed");

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
	invalidate();
	grub_unregister_extcmd (cmd);
}
