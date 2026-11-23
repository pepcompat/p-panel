# websrc — tiny static site for the P4b lab build test (busybox httpd, non-root, :8080, /healthz).
FROM busybox:1.37.0@sha256:a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec
COPY www/ /www/
USER 65534:65534
EXPOSE 8080
CMD ["httpd", "-f", "-v", "-p", "8080", "-h", "/www"]
