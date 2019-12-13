/* csl.c - Command Stream Loader (CSL) */
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
#include <grub/err.h>
#include <grub/dl.h>
#include <grub/misc.h>
#include <grub/extcmd.h>
#include <grub/i18n.h>
#include <grub/file.h>
#include <grub/loader.h>
#include <grub/i386/relocator.h>
#include <grub/i386/cpuid.h>

#ifdef GRUB_MACHINE_EFI
#include <grub/efi/efi.h>
#endif

GRUB_MOD_LICENSE ("GPLv3+");

/* Protocol version magic */
const grub_uint64_t my_vermagic = 0x9ec6f414d638d232ULL;

enum
{
	CMD_CHECK_VERSION = 0,
	CMD_META_DATA = 1,
	CMD_WRITE = 2,
	CMD_FILL = 3,
	CMD_SET_ENTRY_POINT = 4,
	CMD_CHECK_CPUID = 5,
};

enum
{
	CPUID_RESULT_EAX = 0,
	CPUID_RESULT_EBX = 1,
	CPUID_RESULT_ECX = 2,
	CPUID_RESULT_EDX = 3,
};

#define CMD_CHECK_VERSION_DATA_LEN		8
#define CMD_SET_ENTRY_POINT_DATA_LEN	8
#define CMD_FILL_PATTERN_DATA_LEN		24
#define CMD_CHECK_CPUID_DATA_LEN		88

#define MAX_CHECK_STRING 64

#define CSL_INITIAL_STATE { \
	.eax = 0, \
	.ebx = 0, \
	.ecx = 0, \
	.edx = 0, \
	.esp = 0, \
	.ebp = 0, \
	.esi = 0, \
	.edi = 0, \
	.eip = 0, \
}

static struct grub_relocator *relocator = NULL;

static const char *cmd_names[] = {
	"CMD_CHECK_VERSION",
	"CMD_META_DATA",
	"CMD_WRITE",
	"CMD_FILL",
	"CMD_SET_ENTRY_POINT",
	"CMD_CHECK_CPUID",
};

static grub_addr_t entry_point = GRUB_ULONG_MAX;

static grub_err_t
csl_cmd_check_version (const grub_file_t file,
		const grub_size_t data_length)
{
	grub_uint64_t vermagic = 0;

	if (data_length != CMD_CHECK_VERSION_DATA_LEN)
		return grub_error (GRUB_ERR_FILE_READ_ERROR,
				"%s - unexpected data length %u",
				cmd_names[CMD_CHECK_VERSION], data_length);
	if (grub_file_read (file, &vermagic, CMD_CHECK_VERSION_DATA_LEN)
			!= CMD_CHECK_VERSION_DATA_LEN)
		return grub_error (GRUB_ERR_FILE_READ_ERROR,
				"%s - unable to read version magic",
				cmd_names[CMD_CHECK_VERSION]);
	if (vermagic != my_vermagic)
		return grub_error (GRUB_ERR_BAD_ARGUMENT,
				"%s - version magic mismatch (got: 0x%llx, expected: 0x%llx)",
				cmd_names[CMD_CHECK_VERSION],
				vermagic, my_vermagic);

	return GRUB_ERR_NONE;
}

static grub_err_t
csl_cmd_write (const grub_file_t file,
		const grub_size_t data_length)
{
	grub_uint64_t address = 0;
	grub_relocator_chunk_t ch;
	grub_err_t err;
	grub_size_t content_len;

	if (data_length % 8 != 0 || data_length < 16)
		return grub_error (GRUB_ERR_FILE_READ_ERROR,
				"%s - unexpected data length %u",
				cmd_names[CMD_WRITE], data_length);
	if (grub_file_read (file, &address, 8) != 8)
		return grub_error (GRUB_ERR_FILE_READ_ERROR,
				"%s - unable to read address",
				cmd_names[CMD_WRITE]);
	if (address > GRUB_ULONG_MAX)
		return grub_error (GRUB_ERR_OUT_OF_RANGE,
				"%s - address out of range 0x%llx",
				cmd_names[CMD_WRITE], address);

	content_len = data_length - 8;

	grub_dprintf ("csl", "%s - address 0x%llx, content length 0x%llx\n",
			cmd_names[CMD_WRITE],
			(unsigned long long) address,
			(unsigned long long) content_len);
	err = grub_relocator_alloc_chunk_addr (relocator, &ch,
			(grub_addr_t) address,
			content_len);
	if (err != GRUB_ERR_NONE)
		return err;

	if (grub_file_read (file, get_virtual_current_address (ch),
				content_len) != (grub_ssize_t) content_len)
		return grub_error (GRUB_ERR_FILE_READ_ERROR,
				"%s - unable to read 0x%x content data bytes",
				cmd_names[CMD_WRITE], content_len);

	return GRUB_ERR_NONE;
}

static grub_err_t
csl_cmd_fill (const grub_file_t file,
		const grub_size_t data_length)
{
	grub_uint64_t address = 0, fill_length = 0, pattern = 0;
	grub_relocator_chunk_t ch;
	grub_err_t err;

	if (data_length != CMD_FILL_PATTERN_DATA_LEN)
		return grub_error (GRUB_ERR_FILE_READ_ERROR,
				"%s - unexpected data length %u",
				cmd_names[CMD_FILL], data_length);
	if (grub_file_read (file, &address, 8) != 8)
		return grub_error (GRUB_ERR_FILE_READ_ERROR,
				"%s - unable to read address",
				cmd_names[CMD_FILL]);
	if (address > GRUB_ULONG_MAX)
		return grub_error (GRUB_ERR_OUT_OF_RANGE,
				"%s - address out of range 0x%llx",
				cmd_names[CMD_FILL], address);
	if (grub_file_read (file, &fill_length, 8) != 8)
		return grub_error (GRUB_ERR_FILE_READ_ERROR,
				"%s - unable to read fill length",
				cmd_names[CMD_FILL]);
	if (fill_length > GRUB_ULONG_MAX)
		return grub_error (GRUB_ERR_OUT_OF_RANGE,
				"%s - fill length is out of range - 0x%llx",
				cmd_names[CMD_FILL], fill_length);
	if (grub_file_read (file, &pattern, 8) != 8)
		return grub_error (GRUB_ERR_FILE_READ_ERROR,
				"%s - unable to read pattern",
				cmd_names[CMD_FILL]);

	grub_dprintf ("csl", "%s - address 0x%llx, fill length 0x%llx, pattern 0x%llx\n",
			cmd_names[CMD_FILL],
			(unsigned long long) address,
			(unsigned long long) fill_length,
			(unsigned long long) pattern);
	err = grub_relocator_alloc_chunk_addr (relocator, &ch,
			(grub_addr_t) address, (grub_size_t) fill_length);
	if (err != GRUB_ERR_NONE)
		return err;

	grub_memset (get_virtual_current_address (ch), (int) pattern & 0xff,
			(grub_size_t) fill_length);
	return GRUB_ERR_NONE;
}

static grub_err_t
csl_cmd_set_entry_point (const grub_file_t file,
		const grub_size_t data_length)
{
	grub_uint64_t ep = 0;

	if (data_length != CMD_SET_ENTRY_POINT_DATA_LEN)
		return grub_error (GRUB_ERR_FILE_READ_ERROR,
				"%s - unexpected data length %u",
				cmd_names[CMD_SET_ENTRY_POINT], data_length);
	if (grub_file_read (file, &ep, 8) != 8)
		return grub_error (GRUB_ERR_FILE_READ_ERROR,
				"%s - unable to read entry point",
				cmd_names[CMD_SET_ENTRY_POINT]);
	if (ep > GRUB_ULONG_MAX)
		return grub_error (GRUB_ERR_OUT_OF_RANGE,
				"%s - entry point 0x%llx not reachable", ep);
	entry_point = (grub_addr_t) ep;

	grub_dprintf ("csl", "%s - setting entry point to 0x%llx\n",
			cmd_names[CMD_SET_ENTRY_POINT], (unsigned long long) entry_point);
	return GRUB_ERR_NONE;
}

static grub_err_t
csl_cmd_check_cpuid (const grub_file_t file,
		const grub_size_t data_length)
{
	grub_uint64_t word = 0;
	grub_uint32_t leaf = 0, mask = 0, value = 0;
	grub_uint32_t eax, ebx, ecx = 0, edx, result;
	grub_uint8_t result_register;
	char msg[MAX_CHECK_STRING + 1];

	if (grub_cpu_is_cpuid_supported () == 0)
		return grub_error (GRUB_ERR_BAD_ARGUMENT,
				"CPUID instruction not supported");

	/* required by protocol, but to be sure */
	msg[MAX_CHECK_STRING] = '\0';

	if (data_length != CMD_CHECK_CPUID_DATA_LEN)
		return grub_error (GRUB_ERR_FILE_READ_ERROR,
				"%s - unexpected data length %u",
				cmd_names[CMD_CHECK_CPUID], data_length);

	/* ecx is not currently used as input to CPUID */
	if (grub_file_read (file, &ecx, 4) != 4)
		return grub_error (GRUB_ERR_FILE_READ_ERROR,
				"%s - unable to read ecx field",
				cmd_names[CMD_CHECK_CPUID]);
	if (grub_file_read (file, &leaf, 4) != 4)
		return grub_error (GRUB_ERR_FILE_READ_ERROR,
				"%s - unable to read eax field",
				cmd_names[CMD_CHECK_CPUID]);
	if (grub_file_read (file, &value, 4) != 4)
		return grub_error (GRUB_ERR_FILE_READ_ERROR,
				"%s - unable to read value field",
				cmd_names[CMD_CHECK_CPUID]);
	if (grub_file_read (file, &mask, 4) != 4)
		return grub_error (GRUB_ERR_FILE_READ_ERROR,
				"%s - unable to read mask field",
				cmd_names[CMD_CHECK_CPUID]);
	if (grub_file_read (file, &word, 8) != 8)
		return grub_error (GRUB_ERR_FILE_READ_ERROR,
				"%s - unable to read result register",
				cmd_names[CMD_CHECK_CPUID]);
	result_register = (grub_uint8_t) word & 0xff;

	if (grub_file_read (file, &msg, MAX_CHECK_STRING) != MAX_CHECK_STRING)
		return grub_error (GRUB_ERR_FILE_READ_ERROR,
				"%s - unable to read message",
				cmd_names[CMD_CHECK_CPUID]);

	grub_printf ("%s - %s\n", cmd_names[CMD_CHECK_CPUID], msg);
	grub_cpuid (leaf, eax, ebx, ecx, edx);
	grub_dprintf ("csl", "%s - leaf 0x%x => eax 0x%x, ebx 0x%x, ecx 0x%x, edx 0x%x\n",
			cmd_names[CMD_CHECK_CPUID], leaf, eax, ebx, ecx, edx);

	switch (result_register)
	{
		case CPUID_RESULT_EAX:
			result = eax;
			break;
		case CPUID_RESULT_EBX:
			result = ebx;
			break;
		case CPUID_RESULT_ECX:
			result = ecx;
			break;
		case CPUID_RESULT_EDX:
			result = edx;
			break;
		default:
			return grub_error (GRUB_ERR_FILE_READ_ERROR,
					"%s - unknown result register ID %u",
					cmd_names[CMD_CHECK_CPUID], result_register);
	}

	if ((result & mask) != value)
		return grub_error (GRUB_ERR_BAD_NUMBER,
				"%s - '%s' failed (expected 0x%x, got 0x%x)",
				cmd_names[CMD_CHECK_CPUID], msg, value, result);

	return GRUB_ERR_NONE;
}

static grub_err_t
csl_dispatch (const grub_file_t file,
		const grub_uint16_t cmd,
		const grub_uint64_t length)
{
	grub_dprintf ("csl", "Dispatching cmd %u, data length 0x%llx\n",
			cmd, (unsigned long long) length);

	/*
	 * grub_file_read can only read grub_ssize_t bytes,
	 * be conservative and assume the whole data is read via
	 * grub_file_read.
	 */
	if ((grub_ssize_t) length < 0)
		return grub_error (GRUB_ERR_OUT_OF_RANGE,
				"data length out of range - 0x%llx", length);

	switch (cmd)
	{
		case CMD_CHECK_VERSION:
			return csl_cmd_check_version (file, (grub_size_t) length);
		case CMD_WRITE:
			return csl_cmd_write (file, (grub_size_t) length);
		case CMD_FILL:
			return csl_cmd_fill (file, (grub_size_t) length);
		case CMD_SET_ENTRY_POINT:
			return csl_cmd_set_entry_point (file, (grub_size_t) length);
		case CMD_CHECK_CPUID:
			return csl_cmd_check_cpuid (file, (grub_size_t) length);
		case CMD_META_DATA:
			/* We do not care about stream meta data */
			return GRUB_ERR_NONE;
		default:
			return grub_error (GRUB_ERR_FILE_READ_ERROR, "unknown command ID %u",
					cmd);
	}
}

static grub_err_t
csl_boot (void)
{
	struct grub_relocator32_state state = CSL_INITIAL_STATE;

	if (entry_point == GRUB_ULONG_MAX)
		return grub_error (GRUB_ERR_INVALID_COMMAND,
				"no entry point set, ignoring boot command");

#ifdef GRUB_MACHINE_EFI
	grub_err_t err;

	err = grub_efi_finish_boot_services (NULL, NULL, NULL, NULL, NULL);
	if (err)
		return err;
#endif

	state.eip = entry_point;
	return grub_relocator32_boot (relocator, state, 0);
}

static grub_err_t
csl_unload (void)
{
	grub_relocator_unload (relocator);
	relocator = NULL;

	return GRUB_ERR_NONE;
}

static grub_err_t
csl_cmd (grub_extcmd_context_t ctxt __attribute__ ((unused)),
		int argc,
		char **argv)
{
	grub_file_t file = 0;
	grub_uint64_t cmd, length;
	grub_err_t err;

	grub_loader_unset ();

	relocator = grub_relocator_new ();
	if (! relocator)
		return grub_errno;

	if (argc != 1)
		return grub_error (GRUB_ERR_BAD_ARGUMENT, "filename expected");

	file = grub_file_open (argv[0], GRUB_FILE_TYPE_NONE);
	if (! file)
		return grub_errno;
	if (grub_file_size (file) % 8 != 0)
	{
		grub_file_close (file);
		return grub_error (GRUB_ERR_FILE_READ_ERROR,
				"'%s' - file size not a multiple of 8 bytes", argv[0]);
	}

	while (grub_file_read (file, &cmd, 8) == 8)
	{
		if (grub_file_read (file, &length, 8) != 8)
		{
			grub_file_close (file);
			return grub_error (GRUB_ERR_FILE_READ_ERROR,
					"'%s' - unable to read data length", argv[0]);
		}
		err = csl_dispatch (file, (grub_uint16_t) cmd & 0xffff, length);
		if (err != GRUB_ERR_NONE) {
			grub_file_close (file);
			return err;
		}
	}

	grub_file_close (file);

	grub_loader_set (csl_boot, csl_unload, 0);

	return GRUB_ERR_NONE;
}

static grub_extcmd_t cmd;

GRUB_MOD_INIT(csl)
{
	cmd = grub_register_extcmd ("csl", csl_cmd, 0, 0,
			"Load and execute TLV command stream.", 0);
}

GRUB_MOD_FINI(csl)
{
	grub_unregister_extcmd (cmd);
}
