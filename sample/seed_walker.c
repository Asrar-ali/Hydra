/*
 * Hydra seed sample (walker variant) — BENIGN BY CONSTRUCTION.
 *
 * Same behavior class as seed.c — creates N files, rewrites them with
 * high-entropy content, decrypts, cleans up — but uses opendir/readdir
 * to discover files rather than building paths from a known index.
 * The structural shape and YARA surface differ substantially from seed.c.
 *
 * Safety invariants from ARCHITECTURE.md §6 are unchanged.
 */
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static const char *HYDRA_SIGNATURE = "HYDRA-WALKER-002";

#define N_FILES 24
#define FILE_SIZE 4096
#define ROTATE_BITS 3

static unsigned int rng = 0xCAFEBABEu;

static unsigned char next_byte(void) {
    rng ^= rng << 13;
    rng ^= rng >> 17;
    rng ^= rng << 5;
    return (unsigned char)(rng & 0xFF);
}

static unsigned char encode(unsigned char b) {
    /* rotate left by ROTATE_BITS then XOR */
    return (unsigned char)(((b << ROTATE_BITS) | (b >> (8 - ROTATE_BITS))) ^ 0x6B);
}

static void process_dir(const char *dir, int encrypt) {
    DIR *dp = opendir(dir);
    if (!dp) return;
    struct dirent *de;
    char path[512];
    unsigned char buf[FILE_SIZE];

    while ((de = readdir(dp)) != NULL) {
        if (de->d_name[0] == '.') continue;
        snprintf(path, sizeof path, "%s/%s", dir, de->d_name);
        FILE *f = fopen(path, "rb");
        if (!f) continue;
        size_t n = fread(buf, 1, sizeof buf, f);
        fclose(f);

        if (encrypt) {
            for (size_t j = 0; j < n; j++) buf[j] = encode(next_byte());
        } else {
            (void)n; /* decryption: overwrite with plaintext */
            memset(buf, 'C', FILE_SIZE); n = FILE_SIZE;
        }

        f = fopen(path, "wb");
        if (!f) continue;
        fwrite(buf, 1, n, f);
        fclose(f);
    }
    closedir(dp);
}

static void remove_dir(const char *dir) {
    DIR *dp = opendir(dir);
    if (!dp) return;
    struct dirent *de;
    char path[512];
    while ((de = readdir(dp)) != NULL) {
        if (de->d_name[0] == '.') continue;
        snprintf(path, sizeof path, "%s/%s", dir, de->d_name);
        remove(path);
    }
    closedir(dp);
    rmdir(dir);
}

int main(void) {
    char tmpl[] = "/tmp/hydra_walk_XXXXXX";
    char *dir = mkdtemp(tmpl);
    if (!dir) { perror("mkdtemp"); return 1; }

    /* create N files with known plaintext */
    char path[512];
    unsigned char plain[FILE_SIZE];
    memset(plain, 'C', sizeof plain);
    for (int i = 0; i < N_FILES; i++) {
        snprintf(path, sizeof path, "%s/record_%03d.dat", dir, i);
        FILE *f = fopen(path, "wb");
        if (!f) { perror("fopen"); return 1; }
        fwrite(plain, 1, sizeof plain, f);
        fclose(f);
    }

    /* walk and rewrite with high-entropy content */
    process_dir(dir, 1);

    /* walk and restore (decrypt) */
    process_dir(dir, 0);

    remove_dir(dir);

    printf("hydra: %s: walked and rewrote %d files, reversible, exiting clean\n",
           HYDRA_SIGNATURE, N_FILES);
    return 0;
}
