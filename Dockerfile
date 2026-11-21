FROM scratch
ARG TARGETPLATFORM
COPY $TARGETPLATFORM/vault-plugin-secrets-bind-tsig /vault-plugin-secrets-bind-tsig
ENTRYPOINT ["/vault-plugin-secrets-bind-tsig"]
