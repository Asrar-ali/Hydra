/*
 * Hydra seed sample (mmap variant) — BENIGN BY CONSTRUCTION.
 *
 * Same behavior class as seed.c — creates N files, rewrites them with
 * high-entropy content, decrypts, cleans up — but uses mmap/munmap for
 * I/O instead of fread/fwrite. Exercises a different syscall surface so
 * the adversary must find a different rewrite path to evade YARA.
 *
 * Safety invariants from ARCHITECTURE.md §6 are unchanged.
 */
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

static const char *HYDRA_SIGNATURE = "HYDRA-MMAP-001";

#define N_FILES 24
#define FILE_SIZE 4096
#define XOR_KEY 0xA3

static unsigned int lcg_state = 0xDEADBEEFu;

static unsigned char lcg_next(void) {
    lcg_state = lcg_state * 1664525u + 1013904223u;
    return (unsigned char)((lcg_state >> 16) & 0xFF);
}

int main(void) {
    char tmpl[] = "/tmp/hydra_mmap_XXXXXX";
    char *dir = mkdtemp(tmpl);
    if (!dir) { perror("mkdtemp"); return 1; }

    char path[512];

    for (int i = 0; i < N_FILES; i++) {
        snprintf(path, sizeof path, "%s/chunk_%02d.bin", dir, i);

        /* create file at fixed size */
        int fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0600);
        if (fd < 0) { perror("open"); return 1; }
        if (ftruncate(fd, FILE_SIZE) < 0) { perror("ftruncate"); close(fd); return 1; }

        /* map and write plaintext */
        unsigned char *map = mmap(NULL, FILE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        if (map == MAP_FAILED) { perror("mmap"); close(fd); return 1; }
        memset(map, 'B', FILE_SIZE);
        munmap(map, FILE_SIZE);

        /* remap and overwrite with high-entropy content */
        map = mmap(NULL, FILE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        if (map == MAP_FAILED) { perror("mmap"); close(fd); return 1; }
        for (int j = 0; j < FILE_SIZE; j++)
            map[j] = lcg_next() ^ XOR_KEY;
        munmap(map, FILE_SIZE);
        close(fd);
    }

    /* decrypt (reverse XOR) and clean up */
    lcg_state = 0xDEADBEEFu;
    for (int i = 0; i < N_FILES; i++) {
        snprintf(path, sizeof path, "%s/chunk_%02d.bin", dir, i);
        int fd = open(path, O_RDWR);
        if (fd >= 0) {
            unsigned char *map = mmap(NULL, FILE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
            if (map != MAP_FAILED) {
                for (int j = 0; j < FILE_SIZE; j++)
                    map[j] = lcg_next() ^ XOR_KEY;
                munmap(map, FILE_SIZE);
            }
            close(fd);
        }
        unlink(path);
    }
    rmdir(dir);

    printf("hydra: %s: mmap-rewrote %d files, reversible, exiting clean\n",
           HYDRA_SIGNATURE, N_FILES);
    return 0;
}
