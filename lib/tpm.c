// SPDX-License-Identifier: GPL-2.0
#include <linux/types.h>
#include <linux/export.h>
#include <linux/string.h>
#include <linux/tpm_eventlog.h>

/*
 * calc_tpm2_event_size() - calculate the event size, where event
 * is an entry in the TPM 2.0 event log. The event is of type Crypto
 * Agile Log Entry Format as defined in TCG EFI Protocol Specification
 * Family "2.0".

 * @event: event whose size is to be calculated.
 * @efispecid: pointer to structure describing algorithms used.
 *
 * Returns size of the event. If it is an invalid event, returns -1.
 */
ssize_t calc_tpm2_event_size(struct tcg_pcr_event2 *event,
			     struct tcg_efi_specid_event *efispecid)
{
	struct tcg_event_field *event_field;
	void *marker;
	void *marker_start;
	u32 halg_size;
	ssize_t size;
	u16 halg;
	int i;
	int j;

	marker = event;
	marker_start = marker;
	marker = marker + sizeof(event->pcr_idx) + sizeof(event->event_type)
		+ sizeof(event->count);

	/* Check if event is malformed. */
	if (event->count > efispecid->num_algs)
		return -1;

	for (i = 0; i < event->count; i++) {
		halg_size = sizeof(event->digests[i].alg_id);
		memcpy(&halg, marker, halg_size);
		marker = marker + halg_size;
		for (j = 0; j < efispecid->num_algs; j++) {
			if (halg == efispecid->digest_sizes[j].alg_id) {
				marker +=
					efispecid->digest_sizes[j].digest_size;
				break;
			}
		}
		/* Algorithm without known length. Such event is unparseable. */
		if (j == efispecid->num_algs)
			return -1;
	}

	event_field = (struct tcg_event_field *)marker;
	marker = marker + sizeof(event_field->event_size)
		+ event_field->event_size;
	size = marker - marker_start;

	if ((event->event_type == 0) && (event_field->event_size == 0))
		return -1;

	return size;
}

EXPORT_SYMBOL(calc_tpm2_event_size);
