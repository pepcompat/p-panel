# pPanel lab test image "web": tiny static HTTP server (busybox httpd) on :8080.
# VERSION (v1|v2) changes the body of / so a deploy switch is observable. /healthz -> 200.
FROM busybox:1.37.0@sha256:a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec
ARG VERSION=v1
RUN mkdir -p /www && echo "ppanel-test web ${VERSION}" > /www/index.html && echo ok > /www/healthz
LABEL org.opencontainers.image.title="ppanel-test/web" org.opencontainers.image.version="${VERSION}"
USER 65534:65534
EXPOSE 8080
CMD ["httpd", "-f", "-v", "-p", "8080", "-h", "/www"]
