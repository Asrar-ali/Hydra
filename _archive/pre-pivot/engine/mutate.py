"""
Hydra — metamorphic engine.

Generates a fresh, byte-different C source for a BENIGN payload on every
generation while keeping observable behavior identical. Techniques:
  - randomized identifiers (every function/variable renamed per generation)
  - per-generation XOR-encoded string literals (banner / marker text / filename),
    decoded at runtime, so no shared plaintext survives in the binary
  - injected junk globals + unused junk functions
  - dead (no-op) statements in main
  - shuffled order of function definitions

The payload only: prints a banner and writes one harmless marker file.
There is NO malicious capability anywhere in here. This is a defensive,
educational demo about why signature/hash detection loses to mutation and
why behavioral detection wins.

An optional LLM path (--llm / HYDRA_LLM_* env) can do semantic-preserving
rewrites for the "AI-first" headline; the offline engine below is the
guaranteed-compiling fallback so the demo never depends on a live model.
"""
import random
import string

# --- invariant behavior: these are IDENTICAL across every generation -----
BANNER = "HYDRA :: benign demo payload :: my behavior never changes"
MARKER_CONTENT = "HYDRA_BENIGN_MARKER"
MARKER_FILE = "hydra_marker.txt"

_IDENT_CHARS = string.ascii_lowercase + string.digits


def _rid(rng, used):
    """A unique, valid C identifier."""
    while True:
        name = "_" + "".join(rng.choice(_IDENT_CHARS) for _ in range(rng.randint(5, 9)))
        if name not in used:
            used.add(name)
            return name


def _enc_array(rng, text, key):
    """Return (c_initializer, length, raw_bytes) for an XOR-encoded array + NUL."""
    enc = [(b ^ key) & 0xFF for b in text.encode()]
    body = ", ".join(str(x) for x in enc) + ", 0"
    return "{ " + body + " }", len(text), bytes(enc)


def generate(gen, base_seed=1337):
    """Build one generation. Returns (source:str, summary:str)."""
    rng = random.Random(base_seed * 100003 + gen)
    used = set(["main"])
    key = rng.randint(1, 255)

    fn_emit = _rid(rng, used)
    fn_mark = _rid(rng, used)
    fn_dec = _rid(rng, used)
    v_ban = _rid(rng, used)
    v_mrk = _rid(rng, used)
    v_fnm = _rid(rng, used)
    p_emit = _rid(rng, used)
    p_fn = _rid(rng, used)
    p_ct = _rid(rng, used)
    p_f = _rid(rng, used)
    d_s = _rid(rng, used)
    d_n = _rid(rng, used)
    d_k = _rid(rng, used)
    d_i = _rid(rng, used)

    ban_arr, ban_len, ban_needle = _enc_array(rng, BANNER, key)
    mrk_arr, mrk_len, _ = _enc_array(rng, MARKER_CONTENT, key)
    fnm_arr, fnm_len, _ = _enc_array(rng, MARKER_FILE, key)

    # encoded strings live as file-scope statics -> stored verbatim in the
    # binary, giving a genuine, gen-unique byte region a scanner can sign
    enc_globals = [
        f"static unsigned char {v_ban}[] = {ban_arr};",
        f"static unsigned char {v_mrk}[] = {mrk_arr};",
        f"static unsigned char {v_fnm}[] = {fnm_arr};",
    ]

    # --- real (renamed) helpers -------------------------------------------
    dec = (
        f"static void {fn_dec}(unsigned char *{d_s}, int {d_n}, int {d_k}) {{\n"
        f"    for (int {d_i} = 0; {d_i} < {d_n}; {d_i}++) {{\n"
        f"        {d_s}[{d_i}] = (unsigned char)({d_s}[{d_i}] ^ (unsigned char){d_k});\n"
        f"    }}\n}}"
    )
    emit = (
        f"static void {fn_emit}(const char *{p_emit}) {{\n"
        f"    printf(\"%s\\n\", {p_emit});\n}}"
    )
    mark = (
        f"static int {fn_mark}(const char *{p_fn}, const char *{p_ct}) {{\n"
        f"    FILE *{p_f} = fopen({p_fn}, \"w\");\n"
        f"    if (!{p_f}) return 1;\n"
        f"    fputs({p_ct}, {p_f});\n"
        f"    fclose({p_f});\n"
        f"    return 0;\n}}"
    )

    # --- junk functions (never called) ------------------------------------
    n_junk_fns = rng.randint(2, 5)
    junk_fns = []
    for _ in range(n_junk_fns):
        jn = _rid(rng, used)
        a = _rid(rng, used)
        junk_fns.append(
            f"__attribute__((unused)) static int {jn}(void) {{\n"
            f"    long {a} = {rng.randint(1, 2**31 - 1)}L;\n"
            f"    {a} ^= {rng.randint(1, 2**31 - 1)}L;\n"
            f"    {a} += {rng.randint(1, 2**20)}L;\n"
            f"    return (int)({a} & 0x7fffffff);\n}}"
        )

    # --- junk globals ------------------------------------------------------
    n_junk_globals = rng.randint(1, 4)
    junk_globals = [
        f"__attribute__((unused)) static volatile long {_rid(rng, used)} = {rng.randint(1, 2**31 - 1)}L;"
        for _ in range(n_junk_globals)
    ]

    # --- shuffle all function definitions ---------------------------------
    defs = [dec, emit, mark] + junk_fns
    rng.shuffle(defs)

    # --- dead statements in main ------------------------------------------
    n_dead = rng.randint(2, 4)
    dead = []
    for _ in range(n_dead):
        r = _rid(rng, used)
        dead.append(
            f"    {{ volatile int {r} = {rng.randint(1, 99999)}; (void){r}; }}"
        )

    headers = "#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n"
    all_globals = junk_globals + enc_globals
    rng.shuffle(all_globals)
    body_defs = "\n\n".join(all_globals) + "\n\n" + "\n\n".join(defs)

    main = (
        "int main(void) {\n"
        + "\n".join(dead) + "\n"
        + f"    {fn_dec}({v_ban}, {ban_len}, {key});\n"
        + f"    {fn_dec}({v_mrk}, {mrk_len}, {key});\n"
        + f"    {fn_dec}({v_fnm}, {fnm_len}, {key});\n"
        + f"    {fn_emit}((const char *)({v_ban}));\n"
        + f"    {fn_mark}((const char *)({v_fnm}), (const char *)({v_mrk}));\n"
        + "    return 0;\n}\n"
    )

    banner_comment = (
        f"/* Hydra generation {gen} :: benign :: bytes differ, behavior identical */\n"
    )
    source = banner_comment + headers + "\n" + body_defs + "\n\n" + main

    summary = (
        f"renamed {len(used) - 1} identifiers · XOR-encoded 3 strings (key 0x{key:02X}) · "
        f"+{n_junk_globals} junk globals · +{n_junk_fns} junk functions · reordered {len(defs)} defs"
    )
    if gen == 1:
        summary = "seed (generation 1) — signature is fingerprinted from this build"
    return source, summary, ban_needle


if __name__ == "__main__":
    import sys
    g = int(sys.argv[1]) if len(sys.argv) > 1 else 1
    src, summ, _needle = generate(g)
    print(f"// {summ}\n")
    print(src)
