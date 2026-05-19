// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026, Canonical Ltd.
 */

/*
 * Single-iteration helper for the Veraison attestation PTA, used by
 * regression_1043 to detect the mempool leak in its COSE encoder
 * (encode_cose_evidence()).
 *
 * Each invocation opens a session to the PTA, invokes
 * PTA_VERAISON_ATTESTATION_GET_CBOR_EVIDENCE once and returns the result.
 * The xtest regression case drives the loop and prints per-iteration
 * progress on the normal-world console.
 *
 * The core must be built with CFG_VERAISON_ATTESTATION_PTA=y. Otherwise
 * opening the PTA session fails with TEE_ERROR_ITEM_NOT_FOUND and the
 * caller is expected to skip the test.
 */

#include <pta_veraison_attestation.h>
#include <ta_os_test.h>
#include <tee_internal_api.h>

#include "os_test.h"

/* The PSA/COSE token produced is well under 1 KiB. */
#define VERAISON_OUTPUT_BUF_SIZE	4096

TEE_Result ta_entry_veraison_attestation(uint32_t param_types,
					 TEE_Param params[4])
{
	TEE_TASessionHandle sess = TEE_HANDLE_NULL;
	TEE_UUID uuid = PTA_VERAISON_ATTESTATION_UUID;
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t ret_orig = 0;
	uint8_t nonce[32] = { 0 };
	uint8_t impl_id[32] = { 0 };
	uint8_t *out_buf = NULL;
	TEE_Param p[4] = { };
	uint32_t pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				      TEE_PARAM_TYPE_MEMREF_OUTPUT,
				      TEE_PARAM_TYPE_MEMREF_INPUT,
				      TEE_PARAM_TYPE_NONE);
	uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
					  TEE_PARAM_TYPE_NONE,
					  TEE_PARAM_TYPE_NONE,
					  TEE_PARAM_TYPE_NONE);

	(void)params;

	if (param_types != exp_pt)
		return TEE_ERROR_BAD_PARAMETERS;

	out_buf = TEE_Malloc(VERAISON_OUTPUT_BUF_SIZE, 0);
	if (!out_buf)
		return TEE_ERROR_OUT_OF_MEMORY;

	res = TEE_OpenTASession(&uuid, TEE_TIMEOUT_INFINITE, 0, NULL, &sess,
				&ret_orig);
	if (res != TEE_SUCCESS)
		goto cleanup;	/* ITEM_NOT_FOUND => PTA not present */

	p[0].memref.buffer = nonce;
	p[0].memref.size = sizeof(nonce);
	p[1].memref.buffer = out_buf;
	p[1].memref.size = VERAISON_OUTPUT_BUF_SIZE;
	p[2].memref.buffer = impl_id;
	p[2].memref.size = sizeof(impl_id);

	res = TEE_InvokeTACommand(sess, TEE_TIMEOUT_INFINITE,
				  PTA_VERAISON_ATTESTATION_GET_CBOR_EVIDENCE,
				  pt, p, &ret_orig);

	TEE_CloseTASession(sess);

cleanup:
	TEE_Free(out_buf);
	return res;
}
