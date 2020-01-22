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
#include <grub/file.h>
#include <grub/crypto.h>
#include <grub/pubkey.h>
#include <grub/kernel.h>

#include "csl.h"
#include "shc.h"

GRUB_MOD_LICENSE ("GPLv3+");

static struct shc_header_t header;

static grub_uint64_t encoded_file_size = 0;

struct reader_state_type
{
	grub_file_t fd;
	grub_uint64_t total_bytes_read;
	unsigned int shc_valid;
	grub_uint8_t next_hash[SHA512_HASHSUM_LEN];
	grub_uint8_t *read_pos;
	grub_uint8_t *data;
};

static struct reader_state_type state =
{
	.fd               = NULL,
	.total_bytes_read = 0,
	.shc_valid        = 0,
	.read_pos         = NULL,
	.data             = NULL
};

static const gcry_md_spec_t *hasher = NULL;
static void *hash_ctx = NULL;

/* --- TODO: factor out from pgp.c? --- */

static struct grub_public_key *grub_pk_trusted = NULL;

static grub_ssize_t
pseudo_read (struct grub_file *file, char *buf, grub_size_t len)
{
	grub_memcpy (buf, (grub_uint8_t *) file->data + file->offset, len);
	return len;
}

static grub_err_t
pseudo_close (struct grub_file *file __attribute__ ((unused)))
{
	return GRUB_ERR_NONE;
}

static struct grub_fs pseudo_fs =
{
	.name = "pseudo",
	.fs_read = pseudo_read,
	.fs_close = pseudo_close
};

/* --- */

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

/* Close fd if not already closed */
static void
close_fd (void)
{
	if (state.fd)
	{
		grub_file_close (state.fd);
		state.fd = NULL;
	}
}

/* Invalidate global state and cleanup */
static void
invalidate (void)
{
	state.shc_valid = 0;
	state.read_pos  = NULL;

	if (state.data)
	{
		grub_free (state.data);
		state.data = NULL;
	}
	if (hash_ctx)
	{
		grub_free (hash_ctx);
		hash_ctx = NULL;
	}
	close_fd ();
}

static void
print_buffer (const grub_uint8_t * const b, const unsigned len)
{
	unsigned i;
	grub_printf ("0x");
	for (i = 0; i < len; i++)
		grub_printf ("%02x", b[i]);
}

/*
 * Verify header signature, returns 1 and sets shc_valid to 1 if verification
 * succeeds, 0 otherwise.
 */
static unsigned verify (void)
{
	grub_file_t fd_hdr = NULL, fd_sig = NULL;

	grub_uint8_t signature[GPG_RSA4096_SIG_LEN];

	if (grub_file_read (state.fd, signature, header.sig_len)
			!= (grub_ssize_t) header.sig_len)
	{
		grub_printf ("SHC - unable to read signature\n");
		return 0;
	}

	/* must be heap since grub_file_close calls grub_free on it */
	fd_hdr = grub_malloc (sizeof (struct grub_file));
	fd_sig = grub_malloc (sizeof (struct grub_file));
	if (fd_hdr == NULL || fd_sig == NULL) {
		grub_printf ("SHC - unable to allocate pseudo fds\n");
		return 0;
	}

	grub_memset (fd_hdr, 0, sizeof (*fd_hdr));
	fd_hdr->fs = &pseudo_fs;
	fd_hdr->size = sizeof (struct shc_header_t);
	fd_hdr->data = (char *) &header;

	grub_memset (fd_sig, 0, sizeof (*fd_sig));
	fd_sig->fs = &pseudo_fs;
	fd_sig->size = header.sig_len;
	fd_sig->data = signature;

	if (grub_verify_signature2 (fd_hdr, fd_sig, grub_pk_trusted)
			!= GRUB_ERR_NONE)
	{
		grub_printf ("SHC - signature verification failed: %s\n", grub_errmsg);
		return 0;
	}

	grub_printf ("SHC - signature valid\n");
	state.shc_valid = 1;
	return 1;
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
	unsigned res;

	hasher->init (hash_ctx);
	hasher->write (hash_ctx, state.next_hash, SHA512_HASHSUM_LEN);
	hasher->write (hash_ctx, state.data, bdl);
	hasher->final(hash_ctx);

	if (grub_crypto_memcmp (h, hasher->read (hash_ctx), hasher->mdlen) == 0)
	{
		res = 1;
	}
	else
	{
		res = 0;

		grub_printf ("SHC - ERROR invalid hash detected\n");
		grub_printf ("SHC - computed hash ");
		print_buffer (hasher->read (hash_ctx), SHA512_HASHSUM_LEN);
		grub_printf ("\n");
		grub_printf ("SHC - stored hash ");
		print_buffer (h, SHA512_HASHSUM_LEN);
		grub_printf ("\n");
	}

	return res;
}

static unsigned
load_next_block (const grub_uint32_t offset)
{
	grub_uint8_t current_hash[SHA512_HASHSUM_LEN];

	grub_memcpy (current_hash, state.next_hash, SHA512_HASHSUM_LEN);

	if (! read_block())
		return 0;

	if (! hash_valid (current_hash))
		return 0;

	state.read_pos = state.data + offset;
	return 1;
}

static unsigned
read_field (void *field,
		const grub_size_t width,
		const char * const err_msg)
{
	if (grub_file_read (state.fd, field, width) != (grub_ssize_t) width)
	{
		grub_printf ("SHC - %s\n", err_msg);
		goto header_invalid;
	}

	return 1;

header_invalid:
	close_fd ();
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
	if (header.header_size != sizeof (struct shc_header_t))
	{
		grub_printf ("SHC - incorrect header size %u [expected: %u]\n",
				header.header_size, sizeof (struct shc_header_t));
		goto header_invalid;
	}

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

	if (header.sig_algo_id != SHC_SIG_ALGO_GPG)
	{
		grub_printf ("SHC - unsupported signature algorithm with ID %u\n",
				header.sig_algo_id);
		goto header_invalid;
	}
	if (header.sig_len != GPG_RSA4096_SIG_LEN) {
		grub_printf ("SHC - unexpected sginature length %u, expected %u\n",
				header.sig_len, GPG_RSA4096_SIG_LEN);
		goto header_invalid;
	}

	if (! read_field (header.root_hash, header.hashsum_len,
				"unable to read root hash")) {
		grub_free (header.root_hash);
		return 0;
	}

	return 1;

header_invalid:
	close_fd ();
	return 0;
}

static grub_uint32_t
copy_buffer (void *ptr, grub_uint32_t len)
{
	if (buffer_bytes () < len)
		return 0;

	grub_memcpy (ptr, state.read_pos, len);
	state.read_pos += len;
	return len;
}

static grub_file_t
shc_open (const char *name,
		enum grub_file_type type __attribute__ ((unused)))
{
	if (state.shc_valid)
		return NULL;

	state.fd = grub_file_open (name, GRUB_FILE_TYPE_SHC);

	if (! state.fd)
	{
		grub_printf ("SHC - unable to open '%s'\n", name);
		return NULL;
	}

	if (! read_header ())
		return NULL;

	if (! verify ()) {
		close_fd ();
		return NULL;
	}

	/* init hasher and associated context */
	hasher = grub_crypto_lookup_md_by_name ("sha512");
	if (!hasher) {
		grub_printf ("SHC - unable to init hasher\n");
		close_fd ();
		return NULL;
	}
	hash_ctx = grub_zalloc (hasher->contextsize);
	if (!hash_ctx) {
		grub_printf ("SHC - unable to init hasher ctx\n");
		close_fd ();
		return NULL;
	}

	grub_printf ("SHC - block count       : %u\n", header.block_count);
	grub_printf ("SHC - initial padding   : %u\n", header.padding_len);
	grub_printf ("SHC - block size        : %u\n", header.block_size);
	grub_printf ("SHC - hashsum length    : %u\n", header.hashsum_len);
	grub_printf ("SHC - block data length : %u\n", bdl);

	encoded_file_size = header.block_count * bdl - header.padding_len;
	grub_printf ("SHC - encoded file size : %" PRIuGRUB_UINT64_T "\n", encoded_file_size);

	grub_printf ("SHC - root hash         : ");
	print_buffer (header.root_hash, SHA512_HASHSUM_LEN);
	grub_printf ("\n");

	state.data = grub_malloc (bdl);
	if (state.data == NULL) {
		grub_printf ("SHC - error allocating data buffer\n");
		invalidate ();
		return NULL;
	}

	/* set root hash as next hash and load first block */
	grub_memcpy (state.next_hash, header.root_hash, SHA512_HASHSUM_LEN);
	if (! load_next_block (header.padding_len)) {
		invalidate ();
		return NULL;
	}

	/* indicate success via fake file */
	return (grub_file_t) GRUB_ULONG_MAX;
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
	invalidate ();
	return -1;
}

static grub_err_t
shc_close (grub_file_t file __attribute__ ((unused)))
{
	invalidate ();
	return GRUB_ERR_NONE;
}

static grub_err_t
shc_init (grub_extcmd_context_t ctxt __attribute__ ((unused)),
		int argc __attribute__ ((unused)),
		char **argv __attribute__ ((unused)))
{
	grub_printf ("SHC - overriding CSL file ops...\n");
	csl_fs_ops.open  = shc_open;
	csl_fs_ops.read  = shc_read;
	csl_fs_ops.size  = shc_size;
	csl_fs_ops.close = shc_close;

	return GRUB_ERR_NONE;
}

static grub_extcmd_t cmd;

GRUB_MOD_INIT(shc)
{
	struct grub_module_header *mod_header;

	/* We only look for one key. */
	// TODO: factor out from pgp.c?
	FOR_MODULES (mod_header)
	{
		struct grub_file pseudo_file;
		struct grub_public_key *pk = NULL;

		grub_memset (&pseudo_file, 0, sizeof (pseudo_file));

		/* Not a pubkey, skip.  */
		if (mod_header->type != OBJ_TYPE_PUBKEY)
			continue;

		pseudo_file.fs = &pseudo_fs;
		pseudo_file.size = (mod_header->size - sizeof (struct grub_module_header));
		pseudo_file.data = (char *) mod_header + sizeof (struct grub_module_header);

		pk = grub_load_public_key (&pseudo_file);
		if (!pk)
			grub_fatal ("SHC - error loading initial key: %s\n", grub_errmsg);

		grub_pk_trusted = pk;
		break;
	}
	if (! grub_pk_trusted)
		grub_fatal ("SHC - unable to init trusted pubkey\n");

	cmd = grub_register_extcmd ("shc_init", shc_init, 0, 0,
			"Initialize Signed Hash Chain (SHC) processing.", 0);
}

GRUB_MOD_FINI(shc)
{
	invalidate();
	grub_unregister_extcmd (cmd);
}
