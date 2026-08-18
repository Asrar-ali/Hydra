/*
 * Hydra seed sample — BENIGN BY CONSTRUCTION.
 *
 * This is ransomware-SHAPED behavior for detector testing. It causes no harm:
 *   - it operates only on throwaway files it creates this run, in its own temp dir
 *   - no network, no persistence, nothing outside its sandbox
 *   - the high-entropy rewrite is reversible (XOR); it decrypts before exit
 *
 * Per run it:
 *   1. makes a private working directory (mkdtemp)
 *   2. creates N files with known plaintext (low entropy)
 *   3. rewrites each in place with high-entropy content (simulated encryption)
 *   4. decrypts to prove reversibility, removes the directory, exits 0
 *
 * HYDRA_SIGNATURE below is a build-specific marker the signature detector keys
 * on. The adversary rewrites it (and the rest of the source) to evade YARA,
 * while steps 1-4 — the behavior — stay the same. See ARCHITECTURE.md §6, §9.1.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static const char *HYDRA_SIGNATURE = "HYDRA-SIGNATURE-000";

#define N_FILES 24
#define FILE_SIZE 4096
#define XOR_KEY 0x5A

int main(void) {
    char tmpl[] = "/tmp/hydra_work_XXXXXX";
    char *dir = mkdtemp(tmpl);
    if (!dir) { perror("mkdtemp"); return 1; }

    unsigned char buf[FILE_SIZE];
    char path[512];
    unsigned int state = 0x1234abcdu;  /* PRNG for high-entropy bytes (not crypto) */

    for (int i = 0; i < N_FILES; i++) {
        snprintf(path, sizeof path, "%s/file_%02d.dat", dir, i);

        /* 1) write known plaintext */
        FILE *f = fopen(path, "wb");
        if (!f) { perror("fopen"); return 1; }
        memset(buf, 'A', sizeof buf);
        fwrite(buf, 1, sizeof buf, f);
        fclose(f);

        /* 2) rewrite in place with high-entropy content (XOR-masked, reversible) */
        for (size_t j = 0; j < sizeof buf; j++) {
            state = state * 1103515245u + 12345u;
            buf[j] = (unsigned char)(((state >> 16) & 0xFF) ^ XOR_KEY);
        }
        f = fopen(path, "wb");
        if (!f) { perror("fopen"); return 1; }
        fwrite(buf, 1, sizeof buf, f);
        fclose(f);
    }

    /* 3) decrypt to prove reversibility, then clean up */
    for (int i = 0; i < N_FILES; i++) {
        snprintf(path, sizeof path, "%s/file_%02d.dat", dir, i);
        FILE *f = fopen(path, "rb");
        if (f) {
            size_t n = fread(buf, 1, sizeof buf, f);
            fclose(f);
            for (size_t j = 0; j < n; j++) buf[j] = (unsigned char)(buf[j] ^ XOR_KEY);
        }
        remove(path);
    }
    rmdir(dir);

    printf("hydra: %s: rewrote %d files, reversible, exiting clean\n",
           HYDRA_SIGNATURE, N_FILES);
    return 0;
}
