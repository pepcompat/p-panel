# Lab git fixtures (P4b)

Each `<name>/<version>/` directory is a full source tree. `scripts/lab/git-fixtures.sh` turns every
`<name>` into a bare repo `.lab/git/<name>.git` with one commit per version directory (sorted:
`v1`, `v2`, …), committed with a fixed author/committer and date so the commit SHAs are identical on
every machine. `lab-git` serves them read-only as `git://lab-git/<name>.git` on the lab network and the
script writes `.lab/git.env` (`PPANEL_LAB_GIT_URL_<NAME>`, `PPANEL_LAB_GIT_SHA_<NAME>` = v1,
`PPANEL_LAB_GIT_SHA_<NAME>_V2` = v2, …).

| repo         | purpose                                                                                                                                                                                                                                      |
| ------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `websrc`     | Dockerfile build (busybox httpd on :8080, `/healthz`); v1/v2 differ only in the page body                                                                                                                                                    |
| `stack`      | Compose stack: `app` (PHP 8.3 + pdo_pgsql, `php -S` on :8080), `worker` (same image, heartbeat row every 2 s), `db` (postgres:16-alpine by digest, named volume `pgdata`, `${DB_PASSWORD}` secret); v2 changes only the app's version string |
| `nestjs-min` | built-in `nestjs` template test (needs the npm registry from the build node)                                                                                                                                                                 |

Lab only. Nothing here is a production pattern; pPanel production sources are https git hosts.
