# pPanel lab test image "broken": logs an error and EXITS (code 1) shortly after start, so the
# agent's health loop must fail fast, capture the log tail and remove the candidate.
FROM busybox:1.37.0@sha256:a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec
USER 65534:65534
EXPOSE 8080
CMD ["sh", "-c", "echo 'broken: starting'; sleep 2; echo 'broken: fatal: missing configuration, exiting' >&2; exit 1"]
