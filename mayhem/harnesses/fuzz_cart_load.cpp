// fuzz_cart_load — PICO-8 cartridge LOADING only (no Lua execution, so no cart-made hangs).
//
// Entry point: Cart::Cart(const unsigned char*, size_t), the in-memory cart parser: PNG carts go
// through lodepng, the steganographic byte extraction and the pxa / legacy decompressors; text
// carts through the section splitter (__lua__/__gfx__/__gff__/__map__/__sfx__/__music__/__label__),
// the hex string-to-data helpers and the emoji/P8SCII conversion.
#include <cstddef>
#include <cstdint>
#include <string>

#include "cart.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    Cart *cart = new Cart(data, size);
    // Touch the parsed results so the parse can't be dropped as dead.
    volatile size_t sink = cart->LuaString.size() + cart->LoadError.size();
    (void)sink;
    delete cart;
    return 0;
}
