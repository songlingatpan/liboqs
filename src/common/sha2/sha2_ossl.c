/**
 * \file sha2_ossl.c
 * \brief Implementation of the OQS SHA2 API via calls to OpenSSL's SHA-2 functions
 *
 * SPDX-License-Identifier: MIT
 */

#include <oqs/oqs.h>

#ifdef OQS_USE_SHA2_OPENSSL

#include "sha2.h"

#include "../ossl_helpers.h"

static void do_hash(uint8_t *output, const uint8_t *input, size_t inplen, const EVP_MD *md) {
	EVP_MD_CTX *mdctx = NULL;
	unsigned int outlen;

	mdctx = OSSL_FUNC(EVP_MD_CTX_new)();
	if (mdctx == NULL) {
		OQS_EXIT_IF_NULLPTR(mdctx, "OpenSSL");
		return;
	}

	if (OSSL_FUNC(EVP_DigestInit_ex)(mdctx, md, NULL) != 1 ||
	        OSSL_FUNC(EVP_DigestUpdate)(mdctx, input, inplen) != 1 ||
	        OSSL_FUNC(EVP_DigestFinal_ex)(mdctx, output, &outlen) != 1) {
		OSSL_FUNC(EVP_MD_CTX_free)(mdctx);
		OQS_EXIT_IF_NULLPTR(NULL, "OpenSSL digest operation failed");
		return;
	}

	OSSL_FUNC(EVP_MD_CTX_free)(mdctx);
}

static void SHA2_sha256(uint8_t *output, const uint8_t *input, size_t inplen) {
	const EVP_MD *md;
	md = oqs_sha256();
	if (md == NULL) {
		OQS_EXIT_IF_NULLPTR(md, "OpenSSL");
		return;
	}
	do_hash(output, input, inplen, md);
}

static void SHA2_sha384(uint8_t *output, const uint8_t *input, size_t inplen) {
	const EVP_MD *md;
	md = oqs_sha384();
	if (md == NULL) {
		OQS_EXIT_IF_NULLPTR(md, "OpenSSL");
		return;
	}
	do_hash(output, input, inplen, md);
}
static void SHA2_sha512(uint8_t *output, const uint8_t *input, size_t inplen) {
	const EVP_MD *md;
	md = oqs_sha512();
	if (md == NULL) {
		OQS_EXIT_IF_NULLPTR(md, "OpenSSL");
		return;
	}
	do_hash(output, input, inplen, md);
}

#define SHA2_BLOCK_SIZE 64

static void SHA2_sha256_inc_init(OQS_SHA2_sha256_ctx *state) {
	EVP_MD_CTX *mdctx;
	const EVP_MD *md = NULL;
	md = oqs_sha256();
	if (md == NULL) {
		OQS_EXIT_IF_NULLPTR(md, "OpenSSL");
		return;
	}
	mdctx = OSSL_FUNC(EVP_MD_CTX_new)();
	if (mdctx == NULL) {
		OQS_EXIT_IF_NULLPTR(mdctx, "OpenSSL");
		return;
	}
	if (OSSL_FUNC(EVP_DigestInit_ex)(mdctx, md, NULL) != 1) {
		OSSL_FUNC(EVP_MD_CTX_free)(mdctx);
		OQS_EXIT_IF_NULLPTR(NULL, "OpenSSL digest initialization failed");
		return;
	}
	state->ctx = mdctx;
}
static void SHA2_sha256_inc(OQS_SHA2_sha256_ctx *state, const uint8_t *in, size_t len) {
	if (state && state->ctx) {
		OQS_OPENSSL_GUARD(OSSL_FUNC(EVP_DigestUpdate)((EVP_MD_CTX *) state->ctx, in, len));
	}
}

static void SHA2_sha256_inc_blocks(OQS_SHA2_sha256_ctx *state, const uint8_t *in, size_t inblocks) {
	if (state && state->ctx) {
		OQS_OPENSSL_GUARD(OSSL_FUNC(EVP_DigestUpdate)((EVP_MD_CTX *) state->ctx, in, inblocks * SHA2_BLOCK_SIZE));
	}
}

static void SHA2_sha256_inc_finalize(uint8_t *out, OQS_SHA2_sha256_ctx *state, const uint8_t *in, size_t inlen) {
	if (state && state->ctx && out) {
		unsigned int md_len;
		if (inlen > 0 && in) {
			OQS_OPENSSL_GUARD(OSSL_FUNC(EVP_DigestUpdate)((EVP_MD_CTX *) state->ctx, in, inlen));
		}
		OQS_OPENSSL_GUARD(OSSL_FUNC(EVP_DigestFinal_ex)((EVP_MD_CTX *) state->ctx, out, &md_len));
		OSSL_FUNC(EVP_MD_CTX_free)((EVP_MD_CTX *) state->ctx);
		state->ctx = NULL;
	}
}

static void SHA2_sha256_inc_ctx_release(OQS_SHA2_sha256_ctx *state) {
	if (state && state->ctx) {
		OSSL_FUNC(EVP_MD_CTX_free)((EVP_MD_CTX *) state->ctx);
		state->ctx = NULL;
	}
}

static void SHA2_sha256_inc_ctx_clone(OQS_SHA2_sha256_ctx *dest, const OQS_SHA2_sha256_ctx *src) {
	if (dest && src && src->ctx) {
		SHA2_sha256_inc_init(dest);
		if (dest->ctx) {
			OQS_OPENSSL_GUARD(OSSL_FUNC(EVP_MD_CTX_copy_ex)((EVP_MD_CTX *) dest->ctx, (EVP_MD_CTX *) src->ctx));
		}
	}
}

static void SHA2_sha384_inc_init(OQS_SHA2_sha384_ctx *state) {
	if (state == NULL) {
		return;
	}
	EVP_MD_CTX *mdctx;
	const EVP_MD *md = NULL;
	md = oqs_sha384();
	if (md == NULL) {
		OQS_EXIT_IF_NULLPTR(md, "OpenSSL");
		return;
	}
	mdctx = OSSL_FUNC(EVP_MD_CTX_new)();
	if (mdctx == NULL) {
		OQS_EXIT_IF_NULLPTR(mdctx, "OpenSSL");
		return;
	}
	if (OSSL_FUNC(EVP_DigestInit_ex)(mdctx, md, NULL) != 1) {
		OSSL_FUNC(EVP_MD_CTX_free)(mdctx);
		OQS_EXIT_IF_NULLPTR(NULL, "OpenSSL digest initialization failed");
		return;
	}
	state->ctx = mdctx;
}

static void SHA2_sha384_inc_blocks(OQS_SHA2_sha384_ctx *state, const uint8_t *in, size_t inblocks) {
	if (state && state->ctx && in) {
		OQS_OPENSSL_GUARD(OSSL_FUNC(EVP_DigestUpdate)((EVP_MD_CTX *) state->ctx, in, inblocks * SHA2_BLOCK_SIZE));
	}
}

static void SHA2_sha384_inc_finalize(uint8_t *out, OQS_SHA2_sha384_ctx *state, const uint8_t *in, size_t inlen) {
	if (state && state->ctx && out) {
		unsigned int md_len;
		if (inlen > 0 && in) {
			OQS_OPENSSL_GUARD(OSSL_FUNC(EVP_DigestUpdate)((EVP_MD_CTX *) state->ctx, in, inlen));
		}
		OQS_OPENSSL_GUARD(OSSL_FUNC(EVP_DigestFinal_ex)((EVP_MD_CTX *) state->ctx, out, &md_len));
		OSSL_FUNC(EVP_MD_CTX_free)((EVP_MD_CTX *) state->ctx);
		state->ctx = NULL;
	}
}

static void SHA2_sha384_inc_ctx_release(OQS_SHA2_sha384_ctx *state) {
	if (state && state->ctx) {
		OSSL_FUNC(EVP_MD_CTX_free)((EVP_MD_CTX *) state->ctx);
		state->ctx = NULL;
	}
}

static void SHA2_sha384_inc_ctx_clone(OQS_SHA2_sha384_ctx *dest, const OQS_SHA2_sha384_ctx *src) {
	if (dest && src && src->ctx) {
		SHA2_sha384_inc_init(dest);
		if (dest->ctx) {
			OQS_OPENSSL_GUARD(OSSL_FUNC(EVP_MD_CTX_copy_ex)((EVP_MD_CTX *) dest->ctx, (EVP_MD_CTX *) src->ctx));
		}
	}
}

static void SHA2_sha512_inc_init(OQS_SHA2_sha512_ctx *state) {
	if (state == NULL) {
		return;
	}
	EVP_MD_CTX *mdctx;
	const EVP_MD *md = NULL;
	md = oqs_sha512();
	if (md == NULL) {
		OQS_EXIT_IF_NULLPTR(md, "OpenSSL");
		return;
	}
	mdctx = OSSL_FUNC(EVP_MD_CTX_new)();
	if (mdctx == NULL) {
		OQS_EXIT_IF_NULLPTR(mdctx, "OpenSSL");
		return;
	}
	if (OSSL_FUNC(EVP_DigestInit_ex)(mdctx, md, NULL) != 1) {
		OSSL_FUNC(EVP_MD_CTX_free)(mdctx);
		OQS_EXIT_IF_NULLPTR(NULL, "OpenSSL digest initialization failed");
		return;
	}
	state->ctx = mdctx;
}

static void SHA2_sha512_inc_blocks(OQS_SHA2_sha512_ctx *state, const uint8_t *in, size_t inblocks) {
	if (state && state->ctx && in) {
		OQS_OPENSSL_GUARD(OSSL_FUNC(EVP_DigestUpdate)((EVP_MD_CTX *) state->ctx, in, inblocks * 2 * SHA2_BLOCK_SIZE));
	}
}

static void SHA2_sha512_inc_finalize(uint8_t *out, OQS_SHA2_sha512_ctx *state, const uint8_t *in, size_t inlen) {
	if (state && state->ctx && out) {
		unsigned int md_len;
		if (in && inlen > 0) {
			OQS_OPENSSL_GUARD(OSSL_FUNC(EVP_DigestUpdate)((EVP_MD_CTX *) state->ctx, in, inlen));
		}
		OQS_OPENSSL_GUARD(OSSL_FUNC(EVP_DigestFinal_ex)((EVP_MD_CTX *) state->ctx, out, &md_len));
		OSSL_FUNC(EVP_MD_CTX_free)((EVP_MD_CTX *) state->ctx);
		state->ctx = NULL;
	}
}

static void SHA2_sha512_inc_ctx_release(OQS_SHA2_sha512_ctx *state) {
	if (state && state->ctx) {
		OSSL_FUNC(EVP_MD_CTX_free)((EVP_MD_CTX *) state->ctx);
		state->ctx = NULL;
	}
}

static void SHA2_sha512_inc_ctx_clone(OQS_SHA2_sha512_ctx *dest, const OQS_SHA2_sha512_ctx *src) {
	if (dest && src && src->ctx) {
		SHA2_sha512_inc_init(dest);
		if (dest->ctx) {
			OQS_OPENSSL_GUARD(OSSL_FUNC(EVP_MD_CTX_copy_ex)((EVP_MD_CTX *) dest->ctx, (EVP_MD_CTX *) src->ctx));
		}
	}
}

struct OQS_SHA2_callbacks sha2_default_callbacks = {
	SHA2_sha256,
	SHA2_sha256_inc_init,
	SHA2_sha256_inc_ctx_clone,
	SHA2_sha256_inc,
	SHA2_sha256_inc_blocks,
	SHA2_sha256_inc_finalize,
	SHA2_sha256_inc_ctx_release,
	SHA2_sha384,
	SHA2_sha384_inc_init,
	SHA2_sha384_inc_ctx_clone,
	SHA2_sha384_inc_blocks,
	SHA2_sha384_inc_finalize,
	SHA2_sha384_inc_ctx_release,
	SHA2_sha512,
	SHA2_sha512_inc_init,
	SHA2_sha512_inc_ctx_clone,
	SHA2_sha512_inc_blocks,
	SHA2_sha512_inc_finalize,
	SHA2_sha512_inc_ctx_release,
};

#endif
