# P8 lab substitute: Ubuntu 24.04 systemd hosts

No VMs are available for P8-T01/P8-T02 (`docs/RELEASE_CONTRACT.md` §6). These containers stand in for
fresh Ubuntu 24.04 servers. Results obtained with them are reported as **PASS (lab substitute)**; the
tests on a real VM stay **BLOCKED** until one is provided.

| Container                  | Role                    | Contents                                                                        |
| -------------------------- | ----------------------- | ------------------------------------------------------------------------------- |
| `ppanel-lab-ubuntu-center` | Center host (installer) | Ubuntu 24.04 (pinned digest), systemd PID 1, `docker.io` + `docker-compose-v2`  |
| `ppanel-lab-ubuntu-node-1` | managed host            | Ubuntu 24.04, systemd PID 1, nginx with one plain site (`lab-site.example.lab`) |
| `ppanel-lab-ubuntu-node-2` | managed host            | same image as node-1                                                            |

All packages come from the Ubuntu archive. The center publishes nothing on the Mac; the hosts share the
isolated network `ppanel-lab-ubuntu` and reach the Center as `center.ppanel.lab` (network alias).

> **WARNING — LAB ONLY.** All three run `privileged: true`: systemd needs cgroups and mounts, the unit
> sandboxing (`ProtectSystem=`, `PrivateTmp=`) needs mount namespaces, and the center's dockerd needs
> iptables and overlayfs. pPanel itself never runs privileged containers. The center's
> `/var/lib/docker` and `/var/lib/containerd` are named volumes (overlay-on-overlay does not work).

## Use

Compose profile `ubuntu` in `infra/compose/lab.yml`. `scripts/lab/up.sh` does **not** start these. Start
only these services, never with dependencies:

```bash
docker compose -p ppanel-lab -f infra/compose/lab.yml --profile ubuntu up -d --build --no-deps \
  ubuntu-center ubuntu-node-1 ubuntu-node-2
python3 -I scripts/lab/e2e_p8_install.py --out docs/evidence/<date>/p8-t01-install.json   # recreates them fresh
```

Remove them (and the center's engine data):

```bash
docker compose -p ppanel-lab -f infra/compose/lab.yml --profile ubuntu rm -sfv ubuntu-center ubuntu-node-1 ubuntu-node-2
docker volume rm ppanel-lab_ubuntu-center-docker ppanel-lab_ubuntu-center-containerd
```

## Differences from a real VM

- Shared kernel (Docker Desktop linuxkit), host memory visible in `/proc/meminfo`, no real disks or
  firewall: `install.sh` port and RAM checks run but say nothing about a real host's firewall.
- No public DNS or ACME: the Center is installed with `--tls internal` and the agents get Caddy's root
  CA with `install-agent.sh --ca-file`.
- The nodes have no Docker Engine (the agent reports docker `unavailable`); container features are covered
  by the P4 lab (`lab-node-b` + `lab-dind`).
