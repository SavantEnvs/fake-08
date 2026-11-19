// fuzz_cart_file — a PICO-8 cartridge loaded from a FILE PATH and run, the way the desktop/console
// front ends open a user's cart.
//
// Entry point: Vm::LoadCart(std::string filename) -> Cart::Cart(filename, cartDirectory): the
// extension/magic dispatch (get_first_four_chars), get_file_contents, the `#include <file>`
// resolution relative to the cart's directory, then vm_run() + Step() as in fuzz_cart_run.
//
// The input is written to <scratch>/cart.p8 (or cart.p8.png when it carries the PNG magic, as the
// front ends name such carts), where <scratch> is a private directory made once with mkdtemp under
// $TMPDIR. Each input overwrites that one file and nothing else in the directory is ever created,
// so an `#include` can only resolve to the input itself; a fresh StubHost + Vm per input keeps no
// VM or cartdata state between inputs.
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <unistd.h>

#include "vm.h"
#include "stubhost.h"

static std::string g_dir;

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
    const char *tmp = getenv("TMPDIR");
    std::string tmpl = std::string(tmp && *tmp ? tmp : "/tmp") + "/fake08-cart-XXXXXX";
    char *d = mkdtemp(&tmpl[0]);
    if (!d) {
        perror("mkdtemp");
        abort();
    }
    g_dir = d;
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (g_dir.empty()) {
        LLVMFuzzerInitialize(nullptr, nullptr);
    }
    bool png = size >= 4 && data[0] == 0x89 && data[1] == 'P' && data[2] == 'N' && data[3] == 'G';
    std::string path = g_dir + (png ? "/cart.p8.png" : "/cart.p8");
    std::string other = g_dir + (png ? "/cart.p8" : "/cart.p8.png");
    unlink(other.c_str());
    FILE *f = fopen(path.c_str(), "wb");
    if (!f) {
        perror("fopen");
        abort();
    }
    if (size > 0 && fwrite(data, 1, size, f) != size) {
        perror("fwrite");
        abort();
    }
    fclose(f);

    StubHost *host = new StubHost();
    Vm *vm = new Vm(host);
    if (vm->LoadCart(path, false)) {
        vm->vm_run();
        vm->api_srand(fix32(0));
        for (int i = 0; i < 3; i++) {
            vm->Step();
        }
    }
    delete vm;
    delete host;
    return 0;
}
