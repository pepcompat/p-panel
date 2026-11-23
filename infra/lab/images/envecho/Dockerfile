# pPanel lab test image "envecho": prints APP_SECRET to stdout at start (deliberately leaky app),
# then serves 200 on :8080 (/ and /healthz). Used to prove the agent redacts secret values from
# every log text it returns.
FROM busybox:1.37.0@sha256:a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec
RUN mkdir -p /www && echo "envecho" > /www/index.html && echo ok > /www/healthz
USER 65534:65534
EXPOSE 8080
CMD ["sh", "-c", "echo \"APP_SECRET=$APP_SECRET\"; echo \"boot: secret is $APP_SECRET\"; exec httpd -f -v -p 8080 -h /www"]
