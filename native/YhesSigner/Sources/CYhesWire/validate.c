#include "YhesWire.h"

/* Rust ABI is kept behind this bounded shim, with no ownership transfer. */
extern uint8_t yhes_wire_public_key_is_valid(uint32_t algorithm, const uint8_t *bytes, size_t length);

uint8_t yhes_signer_public_key_is_valid(uint32_t algorithm, const uint8_t *bytes, size_t length) {
    if (bytes == NULL) return 0;
    if (!((algorithm == 1 && length == 32) || (algorithm == 2 && length == 65))) return 0;
    return yhes_wire_public_key_is_valid(algorithm, bytes, length) == 1 ? 1 : 0;
}
