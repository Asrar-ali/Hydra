/*
 * Hydra evasion sample — MECHANISM SWAP (rename-based), BENIGN BY CONSTRUCTION.
 *
 * Same ransomware behavior CLASS as sample/seed.c — the owner's files end up
 * high-entropy (unrecoverable without the key) — but reached by a different
 * SYSCALL MECHANISM. Each victim is replaced via write-to-temp + rename(), so no
 * existing file is ever overwritten in place. A naive behavioral rule that keys
 * on "existing file rewritten in place with high-entropy content" never fires;
 * a rule that follows rename() to the real destination still does. This is the
 * key beat: behavior preserved, naive rule evaded. See ARCHITECTURE.md §9.2.
 *
 * Safety is identical to seed.c: throwaway files in its own /tmp dir, no network,
 * no persistence, reversible (XOR), cleans up before exit.
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
    char path[512], tmp[600];
    unsigned int state = 0x1234abcdu;  /* PRNG for high-entropy bytes (not crypto) */

    for (int i = 0; i < N_FILES; i++) {
        snprintf(path, sizeof path, "%s/file_%02d.dat", dir, i);

        /* 1) create the victim with known plaintext (low entropy) */
        FILE *f = fopen(path, "wb");
        if (!f) { perror("fopen"); return 1; }
        memset(buf, 'A', sizeof buf);
        fwrite(buf, 1, sizeof buf, f);
        fclose(f);

        /* 2) write high-entropy ciphertext to a SIDE temp file — never the victim */
        for (size_t j = 0; j < sizeof buf; j++) {
            state = state * 1103515245u + 12345u;
            buf[j] = (unsigned char)(((state >> 16) & 0xFF) ^ XOR_KEY);
        }
        snprintf(tmp, sizeof tmp, "%s/file_%02d.dat.tmp", dir, i);
        f = fopen(tmp, "wb");
        if (!f) { perror("fopen"); return 1; }
        fwrite(buf, 1, sizeof buf, f);
        fclose(f);

        /* 3) atomically replace the victim — the destructive step is rename(),
         *    NOT a write() to the victim path. This is what dodges the naive rule. */
        if (rename(tmp, path) != 0) { perror("rename"); return 1; }
    }

    /* 4) prove reversibility in memory (read back + XOR), then clean up. No
     *    plaintext is ever written back to disk, so each victim's final on-disk
     *    content stays high-entropy — the behavior the robust rule must catch. */
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

    printf("hydra: %s: replaced %d files via rename, reversible, exiting clean\n",
           HYDRA_SIGNATURE, N_FILES);
    return 0;
}
