# qsort_r OOB walks + Multi-Resort Table Shift

## When to use

Binary calls `qsort()` (or `qsort_r()`) with a custom comparator AND has a
sort_function-style entry point with a "resort?" prompt that loops back WITHOUT
re-initializing the stack-allocated comparator table.

Fingerprints:
- glibc 2.35+ (uses `_quicksort` fallback when `malloc` fails in `qsort_r`).
- Binary uses `setrlimit(RLIMIT_AS, small)` to force malloc failure.
- Comparator function has signed-subtraction overflow (e.g., `sub eax, ecx` on signed int) → nontransitive at INT_MIN.

## Primary primitive: 4-byte sort OOB walks

```
size_choice = 3 (4-byte int)
direction = 1 (ASC)
num = 256
vals = [INT32_MIN] * 256
vals[64] = 0  # outlier
vals[128] = 0  # outlier
```

Trigger sequence:
1. Reduce mem (setrlimit RLIMIT_AS = 16384).
2. Sort with above values.

Mechanism:
- `compar3` (4-byte signed-sub) sees `cmp(0, INT_MIN) = 0 - INT_MIN` → overflows to negative → "0 < INT_MIN" (BUGGY).
- `_quicksort`'s insertion sort walks backward from outlier position, shifting positive 4-byte chunks UP (toward higher memory).
- Walks stop at first chunk where signed value ≤ 0.

Result with 2 zero outliers in the standard table layout:
- `buf[0]` = `compar4_dec` LOW 4 bytes = `PIE_BASE + 0x1342` (low 32 bits).
- `buf[1]` = `compar4_dec` HIGH 4 bytes = `PIE_BASE` high (= `0x000055XX`).
- Print loop's format[size-1] also corrupted: `format[2]` becomes `"%hd"` (was `"%hd"` at format[1] originally). Print shows LOW 16 bits as signed short.

Working exploit pattern (Python pwntools):
```python
def leak_pie(host, port, max_tries=40):
    OFF_COMPAR4_DEC = 0x1342
    INT32_MIN = -(1 << 31)
    for attempt in range(max_tries):
        try:
            p = remote(host, port)
            # settings → reduce mem 16384 → back
            p.recvuntil(b">"); p.sendline(b"1")
            p.recvuntil(b">"); p.sendline(b"2")
            p.recvuntil(b">"); p.sendline(b"16384")
            p.recvuntil(b">"); p.sendline(b"4")
            # sort
            p.recvuntil(b">"); p.sendline(b"2")
            p.recvuntil(b">"); p.sendline(b"3")  # 4-byte
            p.recvuntil(b">"); p.sendline(b"1")  # asc
            p.recvuntil(b">"); p.sendline(b"256")
            vals = [INT32_MIN]*256
            vals[64] = 0
            vals[128] = 0
            p.send(b"\n".join(str(x).encode() for x in vals) + b"\n")
            data = p.recvuntil(b"Resort?")
            p.close()
            # Parse first 2 values
            line = data.split(b"sorted result:\n")[1].split(b"\n")[0]
            nums = [int(x) for x in line.decode().rstrip(",").split(",")]
            buf0 = nums[0] & 0xFFFFFFFF
            buf1 = nums[1] & 0xFFFFFFFF
            # Validate: buf0 - 0x1342 page-aligned
            if buf0 != 0 and (buf0 - OFF_COMPAR4_DEC) & 0xFFF == 0:
                pie_low = (buf0 - OFF_COMPAR4_DEC) & 0xFFFFFFFF
                pie_base = (buf1 << 32) | pie_low
                return pie_base
        except: continue
    return None
```

Success rate: 15-20% per attempt. Retry until success.

## Multi-resort table-shift accumulation (NEW)

KEY DISCOVERY: sort_function's loop-back on "Resort? y" jumps to AFTER the table-init code. The 12 PIE pointers in the table (format[0..3], compar[0..3], compar_dec[0..3] at rbp-0x470..-0x418) PERSIST across resorts. Buf is also preserved.

This means:
- Sort 1's OOB walks corrupt the table (shift content up by N chunks).
- On RESORT, the corrupted table is used by qsort directly.
- Sort 2's compar lookup `[rbp+(size-1)*8-0x450]` reads the CORRUPTED qword.

After Sort 1 (2 walks = 2-chunk shift):
- `compar3` slot (qword[-6]) = original `compar2` (16-bit signed-sub) → NONTRANSITIVE at INT16_MIN.
- `compar4` slot (qword[-5]) = original `compar3` (32-bit signed-sub) → NONTRANSITIVE at INT_MIN, BUT applied to 8-byte data (reads first 4 bytes only).
- `format[3]` (qword[-9]) = `"%d"` PIE pointer (was `format[2]`).

Critical: **Sort 2 with `size_choice=4` (8-byte) using the corrupted `compar3-as-compar4` does NOT crash** (unlike single-call 8-byte sort which crashes in qsort_r's free()).

The reason: corrupted comparator reads only 4 bytes from 8-byte data. The walks happen with 4-byte cmp on 8-byte qword data. Walks are SHALLOW (stop at the inserted 0 markers from Sort 1 at chunks -25, -24).

Result of Sort 2 (multi-resort):
- buf gets shifted PIE pointers (compar2_dec at buf[0..1], compar3_dec at buf[2..3], etc.).
- Print uses format[3] which after combined shifts becomes "%hhd" — prints LOW BYTE of each qword = LOW BYTE of PIE pointer = `(PIE_LOW + offset) & 0xff`.

## Architectural gap (KNOWN UNSOLVED)

The OOB primitive cannot reach libc residue. Stack layout below buf:
- Chunks -1 to -24: PIE pointers (table).
- Chunk -25: HIGH 4 bytes of libc-region pointer (= `0x00007fXX` real x86_64).
- Chunk -26: LOW 4 bytes of libc-region pointer (top bit set ~50% → stops walks).

Even when walks reach chunk -25, the print format is corrupted to `%hd` (16-bit truncation), losing 8 of the 16 ASLR bits.

8-byte sort produces deeper walks but CRASHES inside qsort_r at `free([rbp-0x88])` due to uninitialized pointer dereference. The multi-resort path avoids this crash but limits walk depth.

No format string in rodata contains `%s`, `%n`, `%p`, or multi-arg chains useful for arbitrary read.

### Lockstep format-and-compar shift constraint (Round 2 finding)

Walks shift BOTH format[i] (chunks -24+2i, -23+2i) AND compar[i] (chunks -16+2i, -15+2i) in lockstep. The qword at format[i] and the qword at compar[i] are 8 chunks (= 4 qwords) apart and shift by the same N chunks per walk.

If we shift format[i] to point to libc residue (= OLD chunks -26, -25 → format[i] at N=2i+2 walks), then compar[i] points to OLD chunks (-26+8, -25+8) = (-18, -17) = OLD format[3] = `"%ld"` rodata pointer. **Non-executable.** qsort jumps to it → SIGSEGV BEFORE reaching print phase.

Therefore: libc-residue-as-printf-format is fundamentally unreachable with this primitive. The 12-qword table layout creates a permanent constraint.

### Print loop register state (verified)

At the printf call in print loop (sort_function +0x424):
- `rdi` = format pointer (= format[size_choice-1])
- `rsi` = read_at result (sign-extended to qword for size<4)
- `rdx` = SAME as rsi (rdx held value before mov to rsi)
- `rcx` = `buf` stack address (set by `lea -0x410(%rbp), %rcx` and preserved through read_at)
- `r8`, `r9` = whatever libc puts() left from "sorted result:" print

If the format string had 3+ %lu specifiers, the third would leak rcx (= stack address). The binary only has 2-spec format strings.

### Walk count = outlier count (empirical)

Each zero outlier produces 1 walk = 1-chunk shift. Empirical max on live target = 2 walks per Sort. Multi-resort accumulates 0-2 additional walks per Sort. Total max shift ≈ 4-5 chunks. Cannot reach libc residue at depth 25+ chunks.

### Native debug rig (Apple Silicon)

Rosetta x86_64 emulation does NOT support ptrace. Use qemu-user + gdb-multiarch instead:

```dockerfile
FROM ubuntu:22.04
RUN apt-get update -y && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    qemu-user qemu-user-static gdb gdb-multiarch python3 python3-pip libc6-dbg gcc libc6-dev binutils
```

Run binary with `qemu-x86_64 -g 1234 -L /usr/x86_64-linux-gnu /path/to/binary < input.txt`. Attach gdb-multiarch with `target remote :1234`. Set breakpoints via PIE-relative offsets (use `_start` to determine PIE base, then `set $pie = $pc - 0x10f0`).

Force malloc fail via LD_PRELOAD:
```c
void *malloc(size_t s) {
    static void *(*real_malloc)(size_t) = NULL;
    if (!real_malloc) real_malloc = dlsym(RTLD_NEXT, "malloc");
    if (s >= 0x400 && s <= 0x500) { errno = ENOMEM; return NULL; }
    return real_malloc(s);
}
```

## Defense / detection

- This class of bug requires:
  1. Custom comparator with signed-subtraction overflow on element type.
  2. Stack-allocated function pointer table near buf with NO bounds check.
  3. malloc-failure path triggering `_quicksort`.
- Fix: use saturating 3-way comparator (`return (a > b) - (a < b);`) which avoids overflow.
- Detection: dynamic analysis with LD_PRELOAD wrapping qsort + comparator. Watch for compar calls with `a` or `b` pointers outside the buffer range.

## Known ceiling — when the primitive is NOT enough (lab challenge "Last Resort" R1+R2+R3+R4, 263 experiments)

Four independent rounds reached the same architectural ceiling. Cumulative findings:

1. **Lockstep format/compar shift constraint**: walks shift `format[i]` and `compar[i]` qwords IN LOCKSTEP at the same chunk-offset positions. Any shift that places libc residue at `format[i]` simultaneously corrupts `compar[i]` to a rodata pointer (non-executable) → qsort crashes before reaching the print phase. This rules out the entire "libc-residue-as-format" exploit class.

2. **Print-phase format truncation masks high bytes**: after a successful PIE-leak Sort, `format[3]` slot shifts from `"%ld"` to `"%d"` (a different rodata format string). Sort 2's print therefore reads 8 bytes from buf but FORMATS only the low 4. Any libc/stack pointer placed in buf is silently truncated to its low 32 bits. Confirms why prior rounds couldn't observe deeper leaks even when walks reached deeper qwords. Verified empirically with marker `0x4141414141414141` showing as `0x0000000041414141`.

3. **Walk depth empirical cap = 2 chunks** in 4-byte mode (50 trials × standard input pattern, 0/50 deeper-walk events). chunks -25 (libc HIGH partial) and -26 (libc LOW) are at distances 25+ — unreachable.

4. **8-byte sort crash root cause** (via qemu+gdb-multiarch): RBP gets corrupted to `PIE+0x3dd8` mid-qsort, causing RIP to jump to invalid address before print phase. Crash at `free([rbp-0x88])` is downstream of the RBP corruption.

5. **PIE-only ROP infeasible**: gadgets `pop rbp; ret` and `leave; ret` and `jmp rax` exist — sufficient for stack pivot — but no `pop rdi/rsi/rdx/rax` in PIE. PLT has no `system/execve/open/read`. No libc gadgets reachable without libc leak.

6. **`.bss` copy-relocations contain libc pointers** at `PIE+0x4080..0x40a8` (stdout/stdin/stderr FILE*). Once PIE is leaked these *addresses* are known, but the binary has no read primitive that can extract their *contents*. Walks shift `format[i]` only among PIE rodata addresses, never to `.bss`.

7. **Native debug rig**: `qemu-x86_64-static -g 1234 -L /usr/x86_64-linux-gnu /path/to/binary` + `gdb-multiarch target remote :1234` from a `--platform=linux/amd64` docker container works on Apple Silicon (bypasses Rosetta's ptrace limitation).

If you reproduce a binary with this same fingerprint and reach the same ceiling: the OOB-walks primitive alone is insufficient. Look for a SECOND vulnerability (signal handler, scanf format-string in writable .data, race condition, multi-connection state leak) or a glibc-specific qsort_r code path that produces deeper walks under specific input patterns.

## R4 Stack Map Beneath Table (LD_PRELOAD qsort interception)

Run LD_PRELOAD with a wrapper that calls real_qsort and dumps the qwords below `base` (= sort_function's buf). Stack contents on glibc 2.35 / qemu-x86_64-static:

```
qword[-13]..[-16]  sort_function's int locals (positive)
qword[-17]         PIE+0x1b48 (= qsort_r's return address into sort_function code)
qword[-18]         qsort_r's saved RBP slot (= sort_function's rbp value)
qword[-19] BEFORE  stack ptr (variable, libc-region typically)
qword[-19] AFTER   buf_addr (stack pointer to buf[0])  ← potential format-string-via-input target
qword[-20]         self-pointer (frame's own address)
qword[-25]         buf_addr (after qsort)
qword[-26]         PIE+0x4080 (= &stdout copy-reloc; holds libc FILE*)
qword[-28+]        libc pointers
```

Critical insight: qword[-19] (after qsort) contains buf_addr. If walks could reach this slot (= 10 qwords / 20 int slots down from format[3] at qword[-9]), `format[3]` would equal `buf_addr`, and Sort 2's print would read buf content as format string. Arbitrary format string injection follows. **Walks empirically cap at depth 2-3 → unreachable.**

## R4 Walk-Stop Conditions (Confirmed by 121 R4 experiments)

The insertion-sort walk continues while `compar(run_ptr, tmp_ptr) < 0`. Stop conditions:

1. `compar3(0, neg_int32) = positive` → walk STOPS at first negative int32 in the path
2. `compar3(0, 0) = 0` (not < 0) → walk STOPS at zero
3. Each subsequent walk inserts a 0 (or chosen outlier value) at the previous walk's stop position
4. This insertion BLOCKS subsequent walks from going deeper

Empirical: N zero outliers produce a PIE_HIGH at buf[N-1] but no deeper leak. Walks never compound — they all stop at roughly the same depth (the first persistently-negative value in the path).

## R4 ASLR Lottery Result

Stack base ASLR varies the high byte of qword[-18]'s low dword. On targets where stack is at 0xffff..., the low dword's high bit is set (negative int32), stopping walks. On targets where stack is at 0x7fff..., the low dword's high bit depends on bit 30 — only ~50% chance. **Empirical: 80 trials × 4 input patterns on the live lab target showed walk depth invariant across trials.** ASLR alone doesn't enable deeper walks; there must be additional algorithmic constraints in glibc 2.35's `_quicksort`.

## R4 Multi-Resort Negative Result

Sort 2 (after Sort 1 corrupts table): the corrupted compar/format pointers prevent clean execution. Across 15 chain configurations × multiple trials, all Sort 2 attempts produced EOFError (connection closed during Sort 2). This confirms R3's finding that multi-resort is not a viable path to additional corruption.

## R4 Final Verdict

After 4 rounds and 263 experiments, the OOB-walks primitive on this binary fingerprint is **architecturally insufficient** for libc leak or RIP control without a SECOND vulnerability that we have not been able to identify through source-code review, dynamic instrumentation, or extensive parametric search. 87 lab-platform solvers exist — they likely use a path not visible through systematic exploration of the qsort_r OOB primitive alone. Most likely candidates:

- A specific input pattern producing >18 walks (untested combinatorial space)
- A glibc-version-specific qsort_r partial-malloc fallback path
- A timing/race vulnerability in setrlimit/qsort_r interaction
- A bug in mem_reduce_function or another non-sort function

Recommendation: when reproducing this primitive, time-box at 30 experiments. If walks don't extend beyond depth 4-5, the path is closed; move on to other vulnerability classes.


Continued experiment rounds R5-R14 (confirmations, glibc source findings, live-target validation, final closure, and the write-primitive characterization): [qsort-r-multi-resort-table-shift-rounds.md](qsort-r-multi-resort-table-shift-rounds.md).
