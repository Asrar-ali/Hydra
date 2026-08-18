/*
 * Benign control — writes MANY files but is NOT ransomware.
 *
 * It exists to prove the behavioral detector is specific: this program creates
 * a dozen files (more than the detector's file-count threshold) but fills them
 * with low-entropy plaintext, so the bulk-ENCRYPTION signal is absent and the
 * detector must stay SILENT. A detector that fired here would be flagging "writes
 * files", not "encrypts files". See tests/test_control.py.
 *
 * Benign by construction: same sandbox discipline as the seed — own temp dir,
 * no network, no persistence, cleaned up on exit.
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define N_FILES 12

int main(void) {
    char tmpl[] = "/tmp/hydra_ctl_XXXXXX";
    char *dir = mkdtemp(tmpl);
    if (!dir) { perror("mkdtemp"); return 1; }

    char path[512];
    for (int i = 0; i < N_FILES; i++) {
        snprintf(path, sizeof path, "%s/log_%02d.txt", dir, i);
        FILE *f = fopen(path, "w");
        if (!f) { perror("fopen"); return 1; }
        for (int k = 0; k < 200; k++) fprintf(f, "log entry %d: all systems ok\n", i);
        fclose(f);
    }
    for (int i = 0; i < N_FILES; i++) {
        snprintf(path, sizeof path, "%s/log_%02d.txt", dir, i);
        remove(path);
    }
    rmdir(dir);

    printf("control: wrote %d plaintext log files\n", N_FILES);
    return 0;
}
