/*
 * Copyright (C) 2016 IBM Corporation
 *
 * Authors:
 *      Nayna Jain <nayna@linux.vnet.ibm.com>
 *
 * Access to TPM 2.0 event log as written by Firmware.
 * It assumes that writer of event log has followed TCG Specification
 * for Family "2.0" and written the event data in little endian.
 * With that, it doesn't need any endian conversion for structure
 * content.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#include <linux/seq_file.h>
#include <linux/fs.h>
#include <linux/security.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/tpm_eventlog.h>

#include "../tpm.h"
#include "common.h"

static void *tpm2_bios_measurements_start(struct seq_file *m, loff_t *pos)
{
	struct tpm_chip *chip = m->private;
	struct tpm_bios_log *log = &chip->log;
	void *addr = log->bios_event_log;
	void *limit = log->bios_event_log_end;
	struct tcg_efi_specid_event *efispecid;
	struct tcg_pcr_event *event_header;
	struct tcg_pcr_event2 *event;
	ssize_t size;
	int i;

	event_header = addr;
	efispecid = (struct tcg_efi_specid_event *) event_header->event;
	size = sizeof(struct tcg_pcr_event) - sizeof(event_header->event)
		+ event_header->event_size;

	if (*pos == 0) {
		if (addr + size < limit) {
			if ((event_header->event_type == 0) &&
			    (event_header->event_size == 0))
				return NULL;
			return SEQ_START_TOKEN;
		}
	}

	if (*pos > 0) {
		addr += size;
		event = addr;
		size = calc_tpm2_event_size(event, efispecid);
		if ((addr + size >=  limit) || (size < 0))
			return NULL;
	}

	for (i = 0; i < (*pos - 1); i++) {
		event = addr;
		size = calc_tpm2_event_size(event, efispecid);

		if ((addr + size >= limit) || (size < 0))
			return NULL;
		addr += size;
	}

	return addr;
}

static void *tpm2_bios_measurements_next(struct seq_file *m, void *v,
					 loff_t *pos)
{
	struct tcg_efi_specid_event *efispecid;
	struct tcg_pcr_event *event_header;
	struct tcg_pcr_event2 *event;
	struct tpm_chip *chip = m->private;
	struct tpm_bios_log *log = &chip->log;
	void *limit = log->bios_event_log_end;
	size_t event_size;
	void *marker;

	event_header = log->bios_event_log;
	efispecid = (struct tcg_efi_specid_event *) event_header->event;

	if (v == SEQ_START_TOKEN) {
		event_size = sizeof(struct tcg_pcr_event) -
			sizeof(event_header->event) + event_header->event_size;
		marker = event_header;
	} else {
		event = v;
		event_size = calc_tpm2_event_size(event, efispecid);
		if (event_size < 0)
			return NULL;
		marker = event;
	}

	marker = marker + event_size;
	if (marker >= limit)
		return NULL;
	v = marker;
	event = v;

	event_size = calc_tpm2_event_size(event, efispecid);
	if (((v + event_size) >= limit) || (event_size < 0))
		return NULL;

	(*pos)++;
	return v;
}

static void tpm2_bios_measurements_stop(struct seq_file *m, void *v)
{
}

static int tpm2_binary_bios_measurements_show(struct seq_file *m, void *v)
{
	struct tpm_chip *chip = m->private;
	struct tpm_bios_log *log = &chip->log;
	struct tcg_pcr_event *event_header = log->bios_event_log;
	struct tcg_efi_specid_event *efispecid;
	struct tcg_pcr_event2 *event = v;
	void *temp_ptr;
	size_t size;

	efispecid = (struct tcg_efi_specid_event *) event_header->event;

	if (v == SEQ_START_TOKEN) {
		size = sizeof(struct tcg_pcr_event) -
			sizeof(event_header->event) + event_header->event_size;

		temp_ptr = event_header;

		if (size > 0)
			seq_write(m, temp_ptr, size);
	} else {
		size = calc_tpm2_event_size(event, efispecid);
		temp_ptr = event;
		if (size > 0)
			seq_write(m, temp_ptr, size);
	}

	return 0;
}

const struct seq_operations tpm2_binary_b_measurements_seqops = {
	.start = tpm2_bios_measurements_start,
	.next = tpm2_bios_measurements_next,
	.stop = tpm2_bios_measurements_stop,
	.show = tpm2_binary_bios_measurements_show,
};
