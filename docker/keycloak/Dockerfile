FROM quay.io/keycloak/keycloak:latest as builder

WORKDIR /opt/keycloak
RUN /opt/keycloak/bin/kc.sh build --db=postgres

FROM quay.io/keycloak/keycloak:latest
COPY --from=builder /opt/keycloak/ /opt/keycloak/

ENTRYPOINT ["/opt/keycloak/bin/kc.sh", "start", "--log-level=INFO"]