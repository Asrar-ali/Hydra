# The real-Falco sensor image (HYDRA_REAL_FALCO=1 path). Wraps the official
# no-driver image (modern eBPF, no kernel module/headers needed — see
# ARCHITECTURE.md §8) with our own rules baked in at build time, so the sensor
# doesn't depend on a host bind-mount lining up (Colima's default mounts don't
# cover /tmp, which cost real time to track down during the spike).
FROM falcosecurity/falco-no-driver:latest

COPY rules.yaml /etc/hydra_rules.yaml
