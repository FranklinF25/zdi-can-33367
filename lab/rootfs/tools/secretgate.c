/*
 * secretgate — the ZDI-CAN-33367 lab's purpose-built SUID-root LPE target.
 *
 * The gate is an 8-byte magic array in this binary's read-only image:
 *
 *   "GATELOCK"  — factory state: the gate is closed, root flag denied.
 *   "GATEOPEN"  — after the in-lab page-cache patch: the gate accepts and
 *                 the SUID binary (euid 0) prints the root-only flag.
 *
 * The gate bytes are read through the process's OWN read-only mapping
 * (const volatile), i.e. directly from the page-cache page exec() mapped
 * this file from. poc/lpe.c patches EXACTLY those 8 file bytes via the
 * ZDI-CAN-33367 primitive (in-place ESP decrypt over splice-backed skb
 * frags); the freshly exec'd SUID copy then sees "GATEOPEN" — privilege
 * escalation purely from 8 poisoned page-cache bytes, while the on-disk
 * copy stays pristine (proven block-level by run.sh via debugfs).
 *
 * The comparison reads the array byte-by-byte through a volatile pointer
 * so the compiler cannot const-fold the gate or clone the magic into a
 * second literal (build.sh requires exactly ONE "GATELOCK" occurrence to
 * locate the patch offset).
 *
 * Deliberately useless as a real-world target (S10 ethics):
 *   - no arguments, no stdin, no environment influence;
 *   - fixed behavior: report gate state, maybe print verdict, exit;
 *   - only secret it can reveal is the lab's /root/flag.
 *
 * Exit codes:
 *   0  gate open — root flag printed (SECRETGATE-ROOT-OK)
 *   1  gate locked (denied)
 *   2  internal error (image tampered / flag unreadable)
 *
 * Build: gcc -static -O2 -o secretgate secretgate.c
 */
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/* The patchable gate: the ONLY place "GATELOCK" exists in the binary. */
static const unsigned char gate_state[8] __attribute__((used)) = {
    'G', 'A', 'T', 'E', 'L', 'O', 'C', 'K'
};

#define ROOT_FLAG "/root/flag"

int main(void)
{
    /* volatile: read the LIVE bytes of our own read-only mapping */
    const volatile unsigned char *g = gate_state;
    int prefix_ok, is_open, is_locked;
    char buf[160];
    int fd;
    ssize_t n;

    prefix_ok = g[0] == 'G' && g[1] == 'A' && g[2] == 'T' && g[3] == 'E';
    is_open   = g[4] == 'O' && g[5] == 'P' && g[6] == 'E' && g[7] == 'N';
    is_locked = g[4] == 'L' && g[5] == 'O' && g[6] == 'C' && g[7] == 'K';

    printf("SECRETGATE euid=%d gate=%c%c%c%c%c%c%c%c\n", geteuid(),
           g[0], g[1], g[2], g[3], g[4], g[5], g[6], g[7]);
    fflush(stdout);

    if (!prefix_ok || (!is_open && !is_locked)) {
        puts("SECRETGATE: gate magic not recognized (tampered binary?)");
        return 2;
    }
    if (is_locked) {
        puts("SECRETGATE: denied");
        return 1;
    }

    /* gate open: the page cache of this SUID binary was patched */
    puts("SECRETGATE-GATE state=GATEOPEN (page cache patched)");
    fflush(stdout);
    fd = open(ROOT_FLAG, O_RDONLY);
    if (fd < 0) {
        puts("SECRETGATE: flag read failed (no privilege?)");
        return 2;
    }
    n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) {
        puts("SECRETGATE: flag empty");
        return 2;
    }
    buf[n] = 0;
    buf[strcspn(buf, "\n")] = 0;   /* one line */
    printf("SECRETGATE-ROOT-OK flag=%s\n", buf);
    return 0;
}
