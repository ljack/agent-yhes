#ifndef YHES_WIRE_H
#define YHES_WIRE_H
#include <stddef.h>
#include <stdint.h>

/* Public-key bytes only. 1=Ed25519/raw32, 2=P256/SEC1-65. Result: 1 valid, 0 reject. */
uint8_t yhes_signer_public_key_is_valid(uint32_t algorithm, const uint8_t *bytes, size_t length);
#endif
