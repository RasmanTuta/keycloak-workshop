# --- Certificate Generation Stage ---
FROM alpine:3.14 as certgen

RUN apk --no-cache add openssl

WORKDIR /certs

RUN openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout localhost.key -out localhost.crt -subj "/CN=ws-keycloak.local"

# --- Nginx Stage ---
FROM nginx:alpine

# Copy the custom Nginx configuration, certificate and key from the certgen stage
COPY docker/nginx/nginx.conf /etc/nginx/nginx.conf
COPY --from=certgen /certs/localhost.crt /etc/nginx/localhost.crt
COPY --from=certgen /certs/localhost.key /etc/nginx/localhost.key

EXPOSE 443

# Start Nginx when the container starts
CMD ["nginx", "-g", "daemon off;"]