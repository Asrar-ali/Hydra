# Arena image: a throwaway Linux box that compiles and runs one candidate under
# strace. It is started with --network=none and no host mounts (see arena/run.py).
#
# NOTE: `apt-get` may fail behind a TLS-intercepting egress proxy (Trend Micro
# Web Security). If the build fails on certificate errors, trust the intercept
# CA inside the image — see the repo README / CLAUDE.md before adding --no-cache.
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc \
        libc6-dev \
        strace \
        python3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /work
COPY entrypoint.sh /usr/local/bin/hydra-run
COPY entrypoint_script.sh /usr/local/bin/hydra-run-script
RUN chmod +x /usr/local/bin/hydra-run /usr/local/bin/hydra-run-script

# The candidate source is provided at run time; the entrypoint compiles + traces
# (metamorphic mode, gcc). arena/run.py overrides --entrypoint to hydra-run-script
# for promptlock mode (runs a generated Python script under strace, no compile).
ENTRYPOINT ["/usr/local/bin/hydra-run"]
