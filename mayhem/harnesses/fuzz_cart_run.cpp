// fuzz_cart_run — a PICO-8 cartridge (.p8 text or .p8.png) loaded from memory and RUN.
//
// Entry point: Vm::LoadCart(const unsigned char*, size_t) — the same in-memory loader the
// libretro core uses for retro_load_game. It dispatches on the content ("\x89PNG" -> PNG cart via
// lodepng + pxa/legacy decompression, "pico" -> text cart), parses every section, compiles the
// cart's Lua with z8lua, then vm_run() calls _init and Step() runs _update/_draw — reaching the
// PICO-8 API (spr/sspr/map/mget/mset/print/peek/poke/memcpy/reload/sfx/music) and the synth.
//
// State: a fresh StubHost + Vm per input (StubHost's ctor clears its in-memory cartdata store), so
// nothing carries over between inputs. The VM seeds its RNG from the clock in vm_run(); we reseed
// it to a constant after _init so _update/_draw are reproducible.
#include <cstddef>
#include <cstdint>

#include "vm.h"
#include "stubhost.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    StubHost *host = new StubHost();
    Vm *vm = new Vm(host);
    if (vm->LoadCart(data, size, false)) {
        vm->vm_run();
        vm->api_srand(fix32(0));
        for (int i = 0; i < 3; i++) {
            vm->Step();
        }
        // One stereo frame per uint32_t, as the libretro/SDL hosts pass it.
        uint32_t audio[256];
        vm->FillAudioBuffer(audio, 0, sizeof(audio) / sizeof(audio[0]));
    }
    delete vm;
    delete host;
    return 0;
}
