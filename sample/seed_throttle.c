/*
 * Hydra evasion sample — MECHANISM SWAP (throttled bulk write), BENIGN BY
 * CONSTRUCTION.
 *
 * Same ransomware behavior CLASS as sample/seed.c — the owner's files end up
 * high-entropy (unrecoverable without the key) — reached via the SAME
 * in-place write() mechanism seed.c uses, but PACED over time instead of
 * delivered in one burst.
 *
 * Rationale (defeats rate_windowed, ARCHITECTURE.md §9.2,
 * detectors/rules_registry.py): the rate_windowed rule fires when
 * max_rate_in_window reaches FILES_K (10, common/config.py) victims inside a
 * short sliding window (a couple of seconds). Encrypting all N_FILES
 * back-to-back would put far more than FILES_K victims inside any such
 * window and trip the rule. Splitting the work into BATCH-sized bursts
 * separated by SLEEP_SECONDS of idle time means no window — wherever it's
 * positioned — ever contains more than one batch's worth (BATCH=4, well
 * under FILES_K=10) of encryptions: the gap between batches is longer than
 * the window, so two batches never share one. All N_FILES still end up
 * high-entropy, so the behavior class the robust rule must catch is
 * unchanged; only the rate rule is evaded.
 *
 * Safety is identical to seed.c: throwaway files in its own /tmp dir, no
 * network, no persistence, reversible (XOR), cleans up before exit. The
 * three SLEEP_SECONDS pauses total ~9s, well inside the arena's execution
 * timeout (30s).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static const char *HYDRA_SIGNATURE = "HYDRA-SIGNATURE-000";

#define N_FILES 16
#define BATCH 4
#define SLEEP_SECONDS 3
#define FILE_SIZE 4096
#define XOR_KEY 0x5A

int main(void) {
    char tmpl[] = "/tmp/hydra_work_XXXXXX";
    char *dir = mkdtemp(tmpl);
    if (!dir) { perror("mkdtemp"); return 1; }

    unsigned char buf[FILE_SIZE];
    char path[512];
    unsigned int state = 0x1234abcdu;  /* PRNG for high-entropy bytes (not crypto) */

    int n_batches = N_FILES / BATCH;
    for (int b = 0; b < n_batches; b++) {
        for (int k = 0; k < BATCH; k++) {
            int i = b * BATCH + k;
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

        /* Idle gap between batches: this is the throttle. Each batch alone
         * has BATCH (4) victims, under FILES_K (10); sleeping between
         * batches keeps any two batches from ever sharing a rate window. No
         * sleep after the last batch — nothing left to space out. */
        if (b < n_batches - 1) {
            sleep(SLEEP_SECONDS);
        }
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

    printf("hydra: %s: throttled-rewrote %d files in %d batches of %d, reversible, exiting clean\n",
           HYDRA_SIGNATURE, N_FILES, n_batches, BATCH);
    return 0;
}
