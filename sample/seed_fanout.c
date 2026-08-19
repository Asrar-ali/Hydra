/*
 * Hydra evasion sample — MECHANISM SWAP (multi-process fan-out), BENIGN BY
 * CONSTRUCTION.
 *
 * Same ransomware behavior CLASS as sample/seed.c — the owner's files end up
 * high-entropy (unrecoverable without the key) — reached via the SAME
 * in-place write() mechanism seed.c uses, but the encryptions are spread
 * across several short-lived child processes instead of done by one.
 *
 * Rationale (defeats per_process, ARCHITECTURE.md §9.2,
 * detectors/rules_registry.py): the per_process rule fires when
 * max_encrypted_per_pid reaches FILES_K (10, common/config.py) victims
 * encrypted by a SINGLE pid. The parent creates the shared working
 * directory, then forks N_CHILDREN (4) children; each child encrypts only
 * FILES_PER_CHILD (4) distinct files under its own pid — 4 < FILES_K, so no
 * single pid ever crosses the threshold. 16 victims total still end up
 * high-entropy (N_CHILDREN * FILES_PER_CHILD == 16), so the behavior class
 * the robust rule must catch is unchanged; only the per-process rule is
 * evaded. The parent itself never touches a victim file — it only
 * coordinates (mkdtemp, fork, wait, rmdir).
 *
 * Safety is identical to seed.c: throwaway files in its own /tmp dir, no
 * network, no persistence, reversible (XOR — each child decrypts in memory
 * and never writes plaintext back to disk), cleans up before exit. Every
 * forked child is wait()ed on by the parent (no zombies), and fork() failure
 * is handled by skipping that child rather than crashing.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

static const char *HYDRA_SIGNATURE = "HYDRA-SIGNATURE-000";

#define N_CHILDREN 4
#define FILES_PER_CHILD 4
#define FILE_SIZE 4096
#define XOR_KEY 0x5A

/* One child's work: encrypt FILES_PER_CHILD files in place under filenames
 * unique to this child (child index + own pid), decrypt in memory to prove
 * reversibility, remove its own files, then exit. Runs entirely in the
 * forked child; never returns to main()'s cleanup path. */
static void child_work(const char *dir, int child_idx) {
    unsigned char buf[FILE_SIZE];
    char path[512];
    unsigned int state = 0x1234abcdu ^ (unsigned int)(child_idx * 2654435761u);

    for (int i = 0; i < FILES_PER_CHILD; i++) {
        snprintf(path, sizeof path, "%s/file_c%d_p%d_%02d.dat", dir, child_idx, (int)getpid(), i);

        /* 1) write known plaintext */
        FILE *f = fopen(path, "wb");
        if (!f) { perror("fopen"); _exit(1); }
        memset(buf, 'A', sizeof buf);
        fwrite(buf, 1, sizeof buf, f);
        fclose(f);

        /* 2) rewrite in place with high-entropy content (XOR-masked, reversible) */
        for (size_t j = 0; j < sizeof buf; j++) {
            state = state * 1103515245u + 12345u;
            buf[j] = (unsigned char)(((state >> 16) & 0xFF) ^ XOR_KEY);
        }
        f = fopen(path, "wb");
        if (!f) { perror("fopen"); _exit(1); }
        fwrite(buf, 1, sizeof buf, f);
        fclose(f);
    }

    /* 3) decrypt in memory to prove reversibility (never write plaintext
     * back to disk), then remove this child's own files. */
    for (int i = 0; i < FILES_PER_CHILD; i++) {
        snprintf(path, sizeof path, "%s/file_c%d_p%d_%02d.dat", dir, child_idx, (int)getpid(), i);
        FILE *f = fopen(path, "rb");
        if (f) {
            size_t n = fread(buf, 1, sizeof buf, f);
            fclose(f);
            for (size_t j = 0; j < n; j++) buf[j] = (unsigned char)(buf[j] ^ XOR_KEY);
        }
        remove(path);
    }

    printf("hydra: %s: child pid %d rewrote %d files, reversible, exiting clean\n",
           HYDRA_SIGNATURE, (int)getpid(), FILES_PER_CHILD);
    /* _exit() skips stdio's atexit flush (unlike exit()/return from main),
     * so flush explicitly or this line is silently lost whenever stdout
     * isn't line-buffered (e.g. piped, not a tty). */
    fflush(stdout);
    _exit(0);
}

int main(void) {
    char tmpl[] = "/tmp/hydra_work_XXXXXX";
    char *dir = mkdtemp(tmpl);
    if (!dir) { perror("mkdtemp"); return 1; }

    pid_t pids[N_CHILDREN];
    int spawned = 0;

    for (int c = 0; c < N_CHILDREN; c++) {
        pid_t pid = fork();
        if (pid < 0) {
            /* fork() failure: skip this child, keep going with the rest. */
            perror("fork");
            continue;
        }
        if (pid == 0) {
            child_work(dir, c);
            _exit(1);  /* unreachable: child_work always calls _exit(0) */
        }
        pids[spawned++] = pid;
    }

    /* Reap every child we actually spawned — no zombies. The parent does
     * not touch any victim file itself. */
    for (int i = 0; i < spawned; i++) {
        int status;
        waitpid(pids[i], &status, 0);
    }

    rmdir(dir);

    printf("hydra: %s: parent pid %d fanned out %d children, reversible, exiting clean\n",
           HYDRA_SIGNATURE, (int)getpid(), spawned);
    return 0;
}
