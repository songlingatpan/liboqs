// SPDX-License-Identifier: MIT

#include <oqs/oqs.h>

#ifdef OQS_USE_SHA3_OPENSSL

#include "sha3.h"
#include "sha3x4.h"

#include <openssl/evp.h>
#include "../ossl_helpers.h"

#include <string.h>

/* SHAKE-128 */

static void SHA3_shake128_x4(uint8_t *output0, uint8_t *output1, uint8_t *output2, uint8_t *output3, size_t outlen,
                             const uint8_t *in0, const uint8_t *in1, const uint8_t *in2, const uint8_t *in3, size_t inplen) {
	OQS_SHA3_shake128(output0, outlen, in0, inplen);
	OQS_SHA3_shake128(output1, outlen, in1, inplen);
	OQS_SHA3_shake128(output2, outlen, in2, inplen);
	OQS_SHA3_shake128(output3, outlen, in3, inplen);
}

/* SHAKE128 incremental */

typedef struct {
	EVP_MD_CTX *mdctx0;
	EVP_MD_CTX *mdctx1;
	EVP_MD_CTX *mdctx2;
	EVP_MD_CTX *mdctx3;
	size_t n_out;
} intrn_shake128_x4_inc_ctx;

static void SHA3_shake128_x4_inc_init(OQS_SHA3_shake128_x4_inc_ctx *state) {
	if (state == NULL) {
		return;
	}
	state->ctx = OQS_MEM_malloc(sizeof(intrn_shake128_x4_inc_ctx));
	if (state->ctx == NULL) {
		return;
	}

	intrn_shake128_x4_inc_ctx *s = (intrn_shake128_x4_inc_ctx *)state->ctx;
	s->mdctx0 = OSSL_FUNC(EVP_MD_CTX_new)();
	s->mdctx1 = OSSL_FUNC(EVP_MD_CTX_new)();
	s->mdctx2 = OSSL_FUNC(EVP_MD_CTX_new)();
	s->mdctx3 = OSSL_FUNC(EVP_MD_CTX_new)();
	if (s->mdctx0 == NULL || s->mdctx1 == NULL || s->mdctx2 == NULL || s->mdctx3 == NULL) {
		OSSL_FUNC(EVP_MD_CTX_free)(s->mdctx0);
		OSSL_FUNC(EVP_MD_CTX_free)(s->mdctx1);
		OSSL_FUNC(EVP_MD_CTX_free)(s->mdctx2);
		OSSL_FUNC(EVP_MD_CTX_free)(s->mdctx3);
		OQS_MEM_free(s);
		state->ctx = NULL;
		return;
	}
	if (OSSL_FUNC(EVP_DigestInit_ex)(s->mdctx0, oqs_shake128(), NULL) != 1 ||
	        OSSL_FUNC(EVP_DigestInit_ex)(s->mdctx1, oqs_shake128(), NULL) != 1 ||
	        OSSL_FUNC(EVP_DigestInit_ex)(s->mdctx2, oqs_shake128(), NULL) != 1 ||
	        OSSL_FUNC(EVP_DigestInit_ex)(s->mdctx3, oqs_shake128(), NULL) != 1) {
		OSSL_FUNC(EVP_MD_CTX_free)(s->mdctx0);
		OSSL_FUNC(EVP_MD_CTX_free)(s->mdctx1);
		OSSL_FUNC(EVP_MD_CTX_free)(s->mdctx2);
		OSSL_FUNC(EVP_MD_CTX_free)(s->mdctx3);
		OQS_MEM_free(s);
		state->ctx = NULL;
		return;
	}
	s->n_out = 0;
}

static void SHA3_shake128_x4_inc_absorb(OQS_SHA3_shake128_x4_inc_ctx *state, const uint8_t *in0, const uint8_t *in1, const uint8_t *in2, const uint8_t *in3, size_t inplen) {
	if (state == NULL || state->ctx == NULL) {
		return;
	}
	intrn_shake128_x4_inc_ctx *s = (intrn_shake128_x4_inc_ctx *)state->ctx;
	OSSL_FUNC(EVP_DigestUpdate)(s->mdctx0, in0, inplen);
	OSSL_FUNC(EVP_DigestUpdate)(s->mdctx1, in1, inplen);
	OSSL_FUNC(EVP_DigestUpdate)(s->mdctx2, in2, inplen);
	OSSL_FUNC(EVP_DigestUpdate)(s->mdctx3, in3, inplen);
}

static void SHA3_shake128_x4_inc_finalize(OQS_SHA3_shake128_x4_inc_ctx *state) {
	(void)state;
}

static void SHA3_shake128_x4_inc_squeeze(uint8_t *out0, uint8_t *out1, uint8_t *out2, uint8_t *out3, size_t outlen, OQS_SHA3_shake128_x4_inc_ctx *state) {
	if (state == NULL || state->ctx == NULL) {
		return;
	}
	intrn_shake128_x4_inc_ctx *s = (intrn_shake128_x4_inc_ctx *)state->ctx;
#if OPENSSL_VERSION_NUMBER >= 0x30300000L
	EVP_DigestSqueeze(s->mdctx0, out0, outlen);
	EVP_DigestSqueeze(s->mdctx1, out1, outlen);
	EVP_DigestSqueeze(s->mdctx2, out2, outlen);
	EVP_DigestSqueeze(s->mdctx3, out3, outlen);
#else
	EVP_MD_CTX *clone;

	clone = OSSL_FUNC(EVP_MD_CTX_new)();
	if (clone == NULL) {
		return;
	}
	if (OSSL_FUNC(EVP_DigestInit_ex)(clone, oqs_shake128(), NULL) != 1) {
		OSSL_FUNC(EVP_MD_CTX_free)(clone);
		return;
	}
	if (s->n_out == 0) {
		if (OSSL_FUNC(EVP_MD_CTX_copy_ex)(clone, s->mdctx0) != 1 ||
		        OSSL_FUNC(EVP_DigestFinalXOF)(clone, out0, outlen) != 1 ||
		        OSSL_FUNC(EVP_MD_CTX_copy_ex)(clone, s->mdctx1) != 1 ||
		        OSSL_FUNC(EVP_DigestFinalXOF)(clone, out1, outlen) != 1 ||
		        OSSL_FUNC(EVP_MD_CTX_copy_ex)(clone, s->mdctx2) != 1 ||
		        OSSL_FUNC(EVP_DigestFinalXOF)(clone, out2, outlen) != 1 ||
		        OSSL_FUNC(EVP_MD_CTX_copy_ex)(clone, s->mdctx3) != 1 ||
		        OSSL_FUNC(EVP_DigestFinalXOF)(clone, out3, outlen) != 1) {
			OSSL_FUNC(EVP_MD_CTX_free)(clone);
			return;
		}
	} else {
		uint8_t *tmp = OQS_MEM_checked_malloc(s->n_out + outlen);
		if (tmp == NULL) {
			OSSL_FUNC(EVP_MD_CTX_free)(clone);
			return;
		}
		if (OSSL_FUNC(EVP_MD_CTX_copy_ex)(clone, s->mdctx0) != 1 ||
		        OSSL_FUNC(EVP_DigestFinalXOF)(clone, tmp, s->n_out + outlen) != 1) {
			OQS_MEM_free(tmp);
			OSSL_FUNC(EVP_MD_CTX_free)(clone);
			return;
		}
		memcpy(out0, tmp + s->n_out, outlen);
		if (OSSL_FUNC(EVP_MD_CTX_copy_ex)(clone, s->mdctx1) != 1 ||
		        OSSL_FUNC(EVP_DigestFinalXOF)(clone, tmp, s->n_out + outlen) != 1) {
			OQS_MEM_free(tmp);
			OSSL_FUNC(EVP_MD_CTX_free)(clone);
			return;
		}
		memcpy(out1, tmp + s->n_out, outlen);
		if (OSSL_FUNC(EVP_MD_CTX_copy_ex)(clone, s->mdctx2) != 1 ||
		        OSSL_FUNC(EVP_DigestFinalXOF)(clone, tmp, s->n_out + outlen) != 1) {
			OQS_MEM_free(tmp);
			OSSL_FUNC(EVP_MD_CTX_free)(clone);
			return;
		}
		memcpy(out2, tmp + s->n_out, outlen);
		if (OSSL_FUNC(EVP_MD_CTX_copy_ex)(clone, s->mdctx3) != 1 ||
		        OSSL_FUNC(EVP_DigestFinalXOF)(clone, tmp, s->n_out + outlen) != 1) {
			OQS_MEM_free(tmp);
			OSSL_FUNC(EVP_MD_CTX_free)(clone);
			return;
		}
		memcpy(out3, tmp + s->n_out, outlen);
		OQS_MEM_free(tmp);
	}
	OSSL_FUNC(EVP_MD_CTX_free)(clone);
	s->n_out += outlen;
#endif
}

static void SHA3_shake128_x4_inc_ctx_clone(OQS_SHA3_shake128_x4_inc_ctx *dest, const OQS_SHA3_shake128_x4_inc_ctx *src) {
	if (dest == NULL || src == NULL || src->ctx == NULL) {
		return;
	}
	dest->ctx = OQS_MEM_malloc(sizeof(intrn_shake128_x4_inc_ctx));
	if (dest->ctx == NULL) {
		return;
	}
	intrn_shake128_x4_inc_ctx *s = (intrn_shake128_x4_inc_ctx *)src->ctx;
	intrn_shake128_x4_inc_ctx *d = (intrn_shake128_x4_inc_ctx *)dest->ctx;
	d->mdctx0 = OSSL_FUNC(EVP_MD_CTX_new)();
	d->mdctx1 = OSSL_FUNC(EVP_MD_CTX_new)();
	d->mdctx2 = OSSL_FUNC(EVP_MD_CTX_new)();
	d->mdctx3 = OSSL_FUNC(EVP_MD_CTX_new)();
	if (d->mdctx0 == NULL || d->mdctx1 == NULL || d->mdctx2 == NULL || d->mdctx3 == NULL) {
		OSSL_FUNC(EVP_MD_CTX_free)(d->mdctx0);
		OSSL_FUNC(EVP_MD_CTX_free)(d->mdctx1);
		OSSL_FUNC(EVP_MD_CTX_free)(d->mdctx2);
		OSSL_FUNC(EVP_MD_CTX_free)(d->mdctx3);
		OQS_MEM_free(d);
		dest->ctx = NULL;
		return;
	}
	if (OSSL_FUNC(EVP_MD_CTX_copy_ex)(d->mdctx0, s->mdctx0) != 1 ||
	        OSSL_FUNC(EVP_MD_CTX_copy_ex)(d->mdctx1, s->mdctx1) != 1 ||
	        OSSL_FUNC(EVP_MD_CTX_copy_ex)(d->mdctx2, s->mdctx2) != 1 ||
	        OSSL_FUNC(EVP_MD_CTX_copy_ex)(d->mdctx3, s->mdctx3) != 1) {
		OSSL_FUNC(EVP_MD_CTX_free)(d->mdctx0);
		OSSL_FUNC(EVP_MD_CTX_free)(d->mdctx1);
		OSSL_FUNC(EVP_MD_CTX_free)(d->mdctx2);
		OSSL_FUNC(EVP_MD_CTX_free)(d->mdctx3);
		OQS_MEM_free(d);
		dest->ctx = NULL;
		return;
	}
	d->n_out = s->n_out;
}
static void SHA3_shake128_x4_inc_ctx_release(OQS_SHA3_shake128_x4_inc_ctx *state) {
	if (state == NULL || state->ctx == NULL) {
		return;
	}
	intrn_shake128_x4_inc_ctx *s = (intrn_shake128_x4_inc_ctx *)state->ctx;
	OSSL_FUNC(EVP_MD_CTX_free)(s->mdctx0);
	OSSL_FUNC(EVP_MD_CTX_free)(s->mdctx1);
	OSSL_FUNC(EVP_MD_CTX_free)(s->mdctx2);
	OSSL_FUNC(EVP_MD_CTX_free)(s->mdctx3);
	OQS_MEM_free(s);
	state->ctx = NULL;
}

static void SHA3_shake128_x4_inc_ctx_reset(OQS_SHA3_shake128_x4_inc_ctx *state) {
	if (state == NULL || state->ctx == NULL) {
		return;
	}
	intrn_shake128_x4_inc_ctx *s = (intrn_shake128_x4_inc_ctx *)state->ctx;
	OSSL_FUNC(EVP_MD_CTX_reset)(s->mdctx0);
	OSSL_FUNC(EVP_MD_CTX_reset)(s->mdctx1);
	OSSL_FUNC(EVP_MD_CTX_reset)(s->mdctx2);
	OSSL_FUNC(EVP_MD_CTX_reset)(s->mdctx3);
	if (OSSL_FUNC(EVP_DigestInit_ex)(s->mdctx0, oqs_shake128(), NULL) != 1 ||
	        OSSL_FUNC(EVP_DigestInit_ex)(s->mdctx1, oqs_shake128(), NULL) != 1 ||
	        OSSL_FUNC(EVP_DigestInit_ex)(s->mdctx2, oqs_shake128(), NULL) != 1 ||
	        OSSL_FUNC(EVP_DigestInit_ex)(s->mdctx3, oqs_shake128(), NULL) != 1) {
		OSSL_FUNC(EVP_MD_CTX_free)(s->mdctx0);
		OSSL_FUNC(EVP_MD_CTX_free)(s->mdctx1);
		OSSL_FUNC(EVP_MD_CTX_free)(s->mdctx2);
		OSSL_FUNC(EVP_MD_CTX_free)(s->mdctx3);
		OQS_MEM_free(s);
		state->ctx = NULL;
		return;
	}
	s->n_out = 0;
}

/* SHAKE-256 */

static void SHA3_shake256_x4(uint8_t *output0, uint8_t *output1, uint8_t *output2, uint8_t *output3, size_t outlen,
                             const uint8_t *in0, const uint8_t *in1, const uint8_t *in2, const uint8_t *in3, size_t inplen) {
	OQS_SHA3_shake256(output0, outlen, in0, inplen);
	OQS_SHA3_shake256(output1, outlen, in1, inplen);
	OQS_SHA3_shake256(output2, outlen, in2, inplen);
	OQS_SHA3_shake256(output3, outlen, in3, inplen);
}

/* SHAKE256 incremental */

typedef struct {
	EVP_MD_CTX *mdctx0;
	EVP_MD_CTX *mdctx1;
	EVP_MD_CTX *mdctx2;
	EVP_MD_CTX *mdctx3;
	size_t n_out;
} intrn_shake256_x4_inc_ctx;
static void SHA3_shake256_x4_inc_init(OQS_SHA3_shake256_x4_inc_ctx *state) {
	if (state == NULL) {
		return;
	}
	state->ctx = OQS_MEM_malloc(sizeof(intrn_shake256_x4_inc_ctx));
	if (state->ctx == NULL) {
		return;
	}

	intrn_shake256_x4_inc_ctx *s = (intrn_shake256_x4_inc_ctx *)state->ctx;
	s->mdctx0 = OSSL_FUNC(EVP_MD_CTX_new)();
	s->mdctx1 = OSSL_FUNC(EVP_MD_CTX_new)();
	s->mdctx2 = OSSL_FUNC(EVP_MD_CTX_new)();
	s->mdctx3 = OSSL_FUNC(EVP_MD_CTX_new)();
	if (s->mdctx0 == NULL || s->mdctx1 == NULL || s->mdctx2 == NULL || s->mdctx3 == NULL) {
		OSSL_FUNC(EVP_MD_CTX_free)(s->mdctx0);
		OSSL_FUNC(EVP_MD_CTX_free)(s->mdctx1);
		OSSL_FUNC(EVP_MD_CTX_free)(s->mdctx2);
		OSSL_FUNC(EVP_MD_CTX_free)(s->mdctx3);
		OQS_MEM_free(s);
		state->ctx = NULL;
		return;
	}
	if (OSSL_FUNC(EVP_DigestInit_ex)(s->mdctx0, oqs_shake256(), NULL) != 1 ||
	        OSSL_FUNC(EVP_DigestInit_ex)(s->mdctx1, oqs_shake256(), NULL) != 1 ||
	        OSSL_FUNC(EVP_DigestInit_ex)(s->mdctx2, oqs_shake256(), NULL) != 1 ||
	        OSSL_FUNC(EVP_DigestInit_ex)(s->mdctx3, oqs_shake256(), NULL) != 1) {
		OSSL_FUNC(EVP_MD_CTX_free)(s->mdctx0);
		OSSL_FUNC(EVP_MD_CTX_free)(s->mdctx1);
		OSSL_FUNC(EVP_MD_CTX_free)(s->mdctx2);
		OSSL_FUNC(EVP_MD_CTX_free)(s->mdctx3);
		OQS_MEM_free(s);
		state->ctx = NULL;
		return;
	}
	s->n_out = 0;
}

static void SHA3_shake256_x4_inc_absorb(OQS_SHA3_shake256_x4_inc_ctx *state, const uint8_t *in0, const uint8_t *in1, const uint8_t *in2, const uint8_t *in3, size_t inplen) {
	if (state == NULL || state->ctx == NULL) {
		return;
	}
	intrn_shake256_x4_inc_ctx *s = (intrn_shake256_x4_inc_ctx *)state->ctx;
	OSSL_FUNC(EVP_DigestUpdate)(s->mdctx0, in0, inplen);
	OSSL_FUNC(EVP_DigestUpdate)(s->mdctx1, in1, inplen);
	OSSL_FUNC(EVP_DigestUpdate)(s->mdctx2, in2, inplen);
	OSSL_FUNC(EVP_DigestUpdate)(s->mdctx3, in3, inplen);
}

static void SHA3_shake256_x4_inc_finalize(OQS_SHA3_shake256_x4_inc_ctx *state) {
	(void)state;
}

static void SHA3_shake256_x4_inc_squeeze(uint8_t *out0, uint8_t *out1, uint8_t *out2, uint8_t *out3, size_t outlen, OQS_SHA3_shake256_x4_inc_ctx *state) {
	if (state == NULL || state->ctx == NULL) {
		return;
	}
	intrn_shake256_x4_inc_ctx *s = (intrn_shake256_x4_inc_ctx *)state->ctx;
#if OPENSSL_VERSION_NUMBER >= 0x30300000L
	EVP_DigestSqueeze(s->mdctx0, out0, outlen);
	EVP_DigestSqueeze(s->mdctx1, out1, outlen);
	EVP_DigestSqueeze(s->mdctx2, out2, outlen);
	EVP_DigestSqueeze(s->mdctx3, out3, outlen);
#else
	EVP_MD_CTX *clone;

	clone = OSSL_FUNC(EVP_MD_CTX_new)();
	if (clone == NULL) {
		return;
	}
	if (OSSL_FUNC(EVP_DigestInit_ex)(clone, oqs_shake256(), NULL) != 1) {
		OSSL_FUNC(EVP_MD_CTX_free)(clone);
		return;
	}
	if (s->n_out == 0) {
		if (OSSL_FUNC(EVP_MD_CTX_copy_ex)(clone, s->mdctx0) != 1 ||
		        OSSL_FUNC(EVP_DigestFinalXOF)(clone, out0, outlen) != 1 ||
		        OSSL_FUNC(EVP_MD_CTX_copy_ex)(clone, s->mdctx1) != 1 ||
		        OSSL_FUNC(EVP_DigestFinalXOF)(clone, out1, outlen) != 1 ||
		        OSSL_FUNC(EVP_MD_CTX_copy_ex)(clone, s->mdctx2) != 1 ||
		        OSSL_FUNC(EVP_DigestFinalXOF)(clone, out2, outlen) != 1 ||
		        OSSL_FUNC(EVP_MD_CTX_copy_ex)(clone, s->mdctx3) != 1 ||
		        OSSL_FUNC(EVP_DigestFinalXOF)(clone, out3, outlen) != 1) {
			OSSL_FUNC(EVP_MD_CTX_free)(clone);
			return;
		}
	} else {
		uint8_t *tmp = OQS_MEM_checked_malloc(s->n_out + outlen);
		if (tmp == NULL) {
			OSSL_FUNC(EVP_MD_CTX_free)(clone);
			return;
		}
		if (OSSL_FUNC(EVP_MD_CTX_copy_ex)(clone, s->mdctx0) != 1 ||
		        OSSL_FUNC(EVP_DigestFinalXOF)(clone, tmp, s->n_out + outlen) != 1) {
			OQS_MEM_free(tmp);
			OSSL_FUNC(EVP_MD_CTX_free)(clone);
			return;
		}
		memcpy(out0, tmp + s->n_out, outlen);
		if (OSSL_FUNC(EVP_MD_CTX_copy_ex)(clone, s->mdctx1) != 1 ||
		        OSSL_FUNC(EVP_DigestFinalXOF)(clone, tmp, s->n_out + outlen) != 1) {
			OQS_MEM_free(tmp);
			OSSL_FUNC(EVP_MD_CTX_free)(clone);
			return;
		}
		memcpy(out1, tmp + s->n_out, outlen);
		if (OSSL_FUNC(EVP_MD_CTX_copy_ex)(clone, s->mdctx2) != 1 ||
		        OSSL_FUNC(EVP_DigestFinalXOF)(clone, tmp, s->n_out + outlen) != 1) {
			OQS_MEM_free(tmp);
			OSSL_FUNC(EVP_MD_CTX_free)(clone);
			return;
		}
		memcpy(out2, tmp + s->n_out, outlen);
		if (OSSL_FUNC(EVP_MD_CTX_copy_ex)(clone, s->mdctx3) != 1 ||
		        OSSL_FUNC(EVP_DigestFinalXOF)(clone, tmp, s->n_out + outlen) != 1) {
			OQS_MEM_free(tmp);
			OSSL_FUNC(EVP_MD_CTX_free)(clone);
			return;
		}
		memcpy(out3, tmp + s->n_out, outlen);
		OQS_MEM_free(tmp);
	}
	OSSL_FUNC(EVP_MD_CTX_free)(clone);
	s->n_out += outlen;
#endif
}

static void SHA3_shake256_x4_inc_ctx_clone(OQS_SHA3_shake256_x4_inc_ctx *dest, const OQS_SHA3_shake256_x4_inc_ctx *src) {
	if (dest == NULL || src == NULL || dest->ctx == NULL || src->ctx == NULL) {
		return;
	}
	intrn_shake256_x4_inc_ctx *s = (intrn_shake256_x4_inc_ctx *)src->ctx;
	intrn_shake256_x4_inc_ctx *d = (intrn_shake256_x4_inc_ctx *)dest->ctx;
	if (OSSL_FUNC(EVP_MD_CTX_copy_ex)(d->mdctx0, s->mdctx0) != 1 ||
	        OSSL_FUNC(EVP_MD_CTX_copy_ex)(d->mdctx1, s->mdctx1) != 1 ||
	        OSSL_FUNC(EVP_MD_CTX_copy_ex)(d->mdctx2, s->mdctx2) != 1 ||
	        OSSL_FUNC(EVP_MD_CTX_copy_ex)(d->mdctx3, s->mdctx3) != 1) {
		OSSL_FUNC(EVP_MD_CTX_free)(d->mdctx0);
		OSSL_FUNC(EVP_MD_CTX_free)(d->mdctx1);
		OSSL_FUNC(EVP_MD_CTX_free)(d->mdctx2);
		OSSL_FUNC(EVP_MD_CTX_free)(d->mdctx3);
		OQS_MEM_free(d);
		dest->ctx = NULL;
		return;
	}
	d->n_out = s->n_out;
}

static void SHA3_shake256_x4_inc_ctx_release(OQS_SHA3_shake256_x4_inc_ctx *state) {
	if (state == NULL || state->ctx == NULL) {
		return;
	}
	intrn_shake256_x4_inc_ctx *s = (intrn_shake256_x4_inc_ctx *)state->ctx;
	OSSL_FUNC(EVP_MD_CTX_free)(s->mdctx0);
	OSSL_FUNC(EVP_MD_CTX_free)(s->mdctx1);
	OSSL_FUNC(EVP_MD_CTX_free)(s->mdctx2);
	OSSL_FUNC(EVP_MD_CTX_free)(s->mdctx3);
	OQS_MEM_free(s);
	state->ctx = NULL;
}

static void SHA3_shake256_x4_inc_ctx_reset(OQS_SHA3_shake256_x4_inc_ctx *state) {
	if (state == NULL || state->ctx == NULL) {
		return;
	}
	intrn_shake256_x4_inc_ctx *s = (intrn_shake256_x4_inc_ctx *)state->ctx;
	OSSL_FUNC(EVP_MD_CTX_reset)(s->mdctx0);
	OSSL_FUNC(EVP_MD_CTX_reset)(s->mdctx1);
	OSSL_FUNC(EVP_MD_CTX_reset)(s->mdctx2);
	OSSL_FUNC(EVP_MD_CTX_reset)(s->mdctx3);
	if (OSSL_FUNC(EVP_DigestInit_ex)(s->mdctx0, oqs_shake256(), NULL) != 1 ||
	    OSSL_FUNC(EVP_DigestInit_ex)(s->mdctx1, oqs_shake256(), NULL) != 1 ||
	    OSSL_FUNC(EVP_DigestInit_ex)(s->mdctx2, oqs_shake256(), NULL) != 1 ||
	    OSSL_FUNC(EVP_DigestInit_ex)(s->mdctx3, oqs_shake256(), NULL) != 1) {
		OSSL_FUNC(EVP_MD_CTX_reset)(s->mdctx0);
		OSSL_FUNC(EVP_MD_CTX_reset)(s->mdctx1);
		OSSL_FUNC(EVP_MD_CTX_reset)(s->mdctx2);
		OSSL_FUNC(EVP_MD_CTX_reset)(s->mdctx3);
		return;
	}
	s->n_out = 0;
}
	extern struct OQS_SHA3_x4_callbacks sha3_x4_default_callbacks;

	struct OQS_SHA3_x4_callbacks sha3_x4_default_callbacks = {
		SHA3_shake128_x4,
		SHA3_shake128_x4_inc_init,
		SHA3_shake128_x4_inc_absorb,
		SHA3_shake128_x4_inc_finalize,
		SHA3_shake128_x4_inc_squeeze,
		SHA3_shake128_x4_inc_ctx_release,
		SHA3_shake128_x4_inc_ctx_clone,
		SHA3_shake128_x4_inc_ctx_reset,
		SHA3_shake256_x4,
		SHA3_shake256_x4_inc_init,
		SHA3_shake256_x4_inc_absorb,
		SHA3_shake256_x4_inc_finalize,
		SHA3_shake256_x4_inc_squeeze,
		SHA3_shake256_x4_inc_ctx_release,
		SHA3_shake256_x4_inc_ctx_clone,
		SHA3_shake256_x4_inc_ctx_reset,
	};

#endif
