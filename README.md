# Keycloak Workshop
In today's large landscape of OIDC / OAuth2 solutions, it can be difficult to make a choice in the myriad of solutions.

We faced such an issue when building a new business critical application for Fjord Maritime. The typical SaaS solutions can quickly become very expensive depending on your needs, either due to missing features, or due to licensing concerns, or they might not be a good choice at all for companies that want to retain control over their own software stack and costs.

This workshop, led by Anders and Kristian, delves into the world of Keycloak, a free libre open source modern solution for identity and access management. We will share our story of why we chose Keycloak, and how we configured Keycloak as a hub in the solution we built for Fjord Maritime's critical business application

Based on our experience, we will go through how to get a modern version of Keycloak running in docker, with the proper reverse proxy setup. This proved to be a challenge due to lack of updated documentation and examples for the newer versions of Keycloak. Furthermore, when running Keycloak we ran into new challenges with non standard headers which caused us headaches and misery.

By attending this workshop, you will learn how to get Keycloak running with docker and docker-compose, how to integrate it into an application, how to set up roles to ensure that the proper claims are configured, user management, and lastly, how to enforce 2FA and how to support 2FA identities.
## Prerequisites
* Docker and Docker-Compose
* Java 17 JDK or newer
* Maven
* Postman
* Terraform
## Keycloak 
* Short intro to KeyCloak
## OAuth2 / Open ID Connect
* Short intro to OAuth2 / OIDC
## Running Raw KeyCloak Docker Image

working with the Keycloak Docker container is explained in [Keycloak Containers](https://www.keycloak.org/server/containers)

If you want to quickly run Keycloak in docker without a database and over http for testing purposes, this can be done by just running the Keycloak docker image as is.
The following will run a raw Keycloak container
## Exercise 1 - Get keycloak running in a container
```shell
docker run -p 8080:8080 -e KEYCLOAK_ADMIN=admin -e KEYCLOAK_ADMIN_PASSWORD=change_me \
quay.io/keycloak/keycloak:latest start-dev

```
You now have a local Keycloak instance running on port 8080. The admin console can be found at [http://localhost:8080](http://localhost:8080)

## Exercise 2 - Enable Resource Owner Password Credentials Grant
To enable the 'Resource Owner Password Credentials Grant' do the following:
* Go to Clients/account
* Under 'Capability config' enable 'Direct access grants'. This enables 'Resource Owner Password Credentials Grant'
  <br/>It is not recommended to use this grant in production environments, but it makes it easier to log in for demo purposes.

Furthmore, in order to login we need to create a user.

Go to the users section, and click on add user.

![img.png](images/add-user.png)

![img.png](images/user-details.png)
Make sure that you check email verified. Also make sure to set a password which we can use in the curl command below. Furthermore,
make sure that the password is not temporary, or you will not be able to retrieve a token.
![img.png](images/set-password.png)
![img.png](images/set-password-details.png)

Logging in can be done through the [Postman collection](postman_collection.json) or using the following cURL:
```shell
curl -k --location 'http://localhost:8080/realms/master/protocol/openid-connect/token' \
--header 'Accept: application/json' \
--header 'Content-Type: application/x-www-form-urlencoded' \
--data-urlencode 'username=<user name>' \
--data-urlencode 'password=<user password>' \
--data-urlencode 'client_id=account' \
--data-urlencode 'grant_type=password' \
--verbose
```

You should see something like the following returned:

```shell
*   Trying [::1]:8080...
* Connected to localhost (::1) port 8080
> POST /realms/master/protocol/openid-connect/token HTTP/1.1
> Host: localhost:8080
> User-Agent: curl/8.4.0
> Accept: application/json
> Content-Type: application/x-www-form-urlencoded
> Content-Length: 65
>
< HTTP/1.1 200 OK
< Cache-Control: no-store
< Pragma: no-cache
< content-length: 2094
< Content-Type: application/json
< Referrer-Policy: no-referrer
< Strict-Transport-Security: max-age=31536000; includeSubDomains
< X-Content-Type-Options: nosniff
< X-Frame-Options: SAMEORIGIN
< X-XSS-Protection: 1; mode=block
<
* Connection #0 to host localhost left intact
{"access_token":"eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJkdDUybTJ6QmE2bjJYUnktbGM3WkItNTc1Wjl0ODNiRUEtRTI1dVROdTY0In0.eyJleHAiOjE3MTM3MTI2ODYsImlhdCI6MTcxMzcxMjYyNiwianRpIjoiZGIwNzZmODUtYzE3Zi00YTdmLWFhOWYtMmFhOGZmNWY5ZmZkIiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL3JlYWxtcy9tYXN0ZXIiLCJzdWIiOiIxMGFkYjMzMi04NTAzLTRiZWMtYjc2Mi05YTZiZjhkNGIxOGMiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJhY2NvdW50Iiwic2Vzc2lvbl9zdGF0ZSI6IjliZGVhYTYwLTk4YzAtNGRjNC05YjRhLTMyZTQyMjJmNDA5NSIsImFjciI6IjEiLCJyZXNvdXJjZV9hY2Nlc3MiOnsiYWNjb3VudCI6eyJyb2xlcyI6WyJtYW5hZ2UtYWNjb3VudCIsIm1hbmFnZS1hY2NvdW50LWxpbmtzIiwidmlldy1wcm9maWxlIl19fSwic2NvcGUiOiJwcm9maWxlIGVtYWlsIiwic2lkIjoiOWJkZWFhNjAtOThjMC00ZGM0LTliNGEtMzJlNDIyMmY0MDk1IiwiZW1haWxfdmVyaWZpZWQiOnRydWUsIm5hbWUiOiJ0ZXN0IHRlc3QiLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJ0ZXN0IiwiZ2l2ZW5fbmFtZSI6InRlc3QiLCJmYW1pbHlfbmFtZSI6InRlc3QiLCJlbWFpbCI6InRlc3RAdGVzdC5jb20ifQ.VmsWEY_DFW2bhvXYvser6EVwkwNGBTtziXClWXf5vOHwFrh1fuju-qQmV0jLSpGr4w8dAofb-7rCyLFOW9-DpJ5MpFqshgfrnlfrgYm8VMPFlSf7ad2kJ9kKQ4ic8uy9BAZQrs49mLMqdn3e-eK2NOExoloySBmHNh_EUJi0_GRNY92w34zzWvqTllUDIHdY87jF11h1SkSzfdL7y02nv5cuT6WKQkVfAZqUsVTuU183kj4o1d7U3U27qlVnqldq6QNNr0ncl9sdFgH2ecDWENIqm6gb-cHxujPn_8Er-PWUfaH55c-9OQVj0Y5NSyKtvC9CPUd0YcvGElw2HEOM8A","expires_in":60,"refresh_expires_in":1800,"refresh_token":"eyJhbGciOiJIUzUxMiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICIwNjg5OGZjYi05OTcyLTRhNmYtYjlkYi03YjdmZjgwZWYzMjUifQ.eyJleHAiOjE3MTM3MTQ0MjYsImlhdCI6MTcxMzcxMjYyNiwianRpIjoiMmE1ZDJlM2YtMGNmZC00OGQ3LTg5YjctMmE4YjEzMGUzMjBkIiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL3JlYWxtcy9tYXN0ZXIiLCJhdWQiOiJodHRwOi8vbG9jYWxob3N0OjgwODAvcmVhbG1zL21hc3RlciIsInN1YiI6IjEwYWRiMzMyLTg1MDMtNGJlYy1iNzYyLTlhNmJmOGQ0YjE4YyIsInR5cCI6IlJlZnJlc2giLCJhenAiOiJhY2NvdW50Iiwic2Vzc2lvbl9zdGF0ZSI6IjliZGVhYTYwLTk4YzAtNGRjNC05YjRhLTMyZTQyMjJmNDA5NSIsInNjb3BlIjoicHJvZmlsZSBlbWFpbCIsInNpZCI6IjliZGVhYTYwLTk4YzAtNGRjNC05YjRhLTMyZTQyMjJmNDA5NSJ9.vX1j7iwgOrZXFd3tbN7ACHLsgT6O0NkBKURZKlJ4jtwqrkpsVr7m-YDpOvZfzKpPUChdtnA9I3wfdSK500HAbg","token_type":"Bearer","not-before-policy":0,"session_state":"9bdeaa60-98c0-4dc4-9b4a-32e4222f4095","scope":"profile email"}⏎

```

The token can be inspected on sites like [jwt.io](jwt.io) , or decoded in your terminal.

## Exercise 3 - Adding a postgreSQL database 

When running Keycloak like in exercise2, all data will be lost when the container is stopped, which is really great for 
demo purposes, but otherwise, annoying.

We will proceed with creating an implementation which uses docker volumes and postgresql, storing the data persistently on your machine instead.

## Adding PostgreSQL database
We recommend setting up postgresSQL through docker-compose, but you can also choose to run a standalone postgresSQL instance
on your existing machine. The example below is an excerpt from a docker-compose file, you will need to create an entry for 
running keycloak as a container by yourself.

Here is a base yaml configuration for docker-compose to get you started. The containers (called services) go within the services block
as demonstrated below:

```yaml
version: '3.8'
services:
  hello_world:
    image: hello-world
```

```yaml
postgres:
    image: postgres:15.4
    container_name: keycloak-db
    environment:
      POSTGRES_DB: keycloak
      POSTGRES_USER: keycloak
      POSTGRES_PASSWORD: password
    volumes:
      - pgdata:/var/lib/postgresql/data
    ports:
      - "5432:5432"
```

## Exercise 4 - Adding reverse proxy and custom host name
## Adding reverse proxy and custom host name
It is recommended to reverse proxy the keycloak instance when running a production instance. This comes with some caveats and reverse proxy shenanigans. 
You can run any reverse proxy server you want, we have chosen nginx as we feel it is the most popular choice out there.

In the following section you will be provided with the relevant nginx dockerfile and configuration, as well as a yaml excerpt for 
getting nginx into docker-compose.yml

```config
events {
worker_connections 1024;
}

http {
server {
listen 443 ssl;
server_name ws-keycloak.local;
ssl_certificate /etc/nginx/localhost.crt;
ssl_certificate_key /etc/nginx/localhost.key;

        location / {
            proxy_pass http://ws-keycloak-app:8080;
            proxy_http_version 1.1;
            proxy_buffering off;

            # Set non-standard X-Forwarded-* headers
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto https;
            proxy_set_header X-Forwarded-Host  ws-keycloak.local;
            proxy_set_header X-Forwarded-Port 443;

            proxy_set_header Host $http_host;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Original-URI $request_uri;
        }
    }
}
```

We need to create our own self-signed certificate for nginx to work with https. 

```dockerfile
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
```

```yaml
nginx-keycloak:
    build:
      context: .
      dockerfile: docker/nginx/Dockerfile
    image: ws-keycloak-nginx
    container_name: ws-keycloak-nginx
    depends_on:
      - ws-keycloak-app
      - postgres
    ports:
      - "443:443"
```

## Exercise 5 - Getting the containers to work together with docker-compose
## Putting Docker-Compose together
We want to use Docker-Compose to set up a local Keycloak that resembles a production environment as closely as possible.
Instead of Adding your host to DNS, create an entry in your *hosts* file.

| Operating System | Location of hosts file          |
|------------------|---------------------------------|
| Linux            | `/etc/hosts`                    |
| macOS            | `/etc/hosts`                    |
| Windows          | `C:\Windows\System32\drivers\etc\hosts` |


```config
127.0.0.1 ws-keycloak.local
```
This is the host we will use for Keycloak throughout this workshop.

When Keycloak is behind a reverse proxy, 
it relies on both custom http headers and configuration through environment variables for correct routing and addressing configuration pages ++.

Ensure that both the [nginx.conf](docker/nginx/nginx.conf) has the needed headers configured
and the Keycloak service in the [docker-compose.yml](docker-compose.yml) has the necessary environment variables configured.
Start docker-compose using the command:
```shell
docker-compose up --build --remove-orphans --abort-on-container-exit
```

As in [Exercise 1](#exercise-1), prepare a client for logging in using 'Resource Owner Password Credentials Grant'.

## Creating a realm
### Exercise 6
In the rest of the workshop we are going to use a realm called `workshop`. A realm is a logical store for users / clients, and is useful for e.g separating environments in keycloak.
Create a new realm from the dropdown in the upper left corner:

![img.png](./images/create_realm_menu.png)

#### Create client

When the realm is created go to the `Client scopes` menu item, the available client scopes are listed with assignments.  
Set `email` and `roles` to `Default` and the rest to  `Optional`

Then go to the `Clients` menu. Click the  `Create client` menu, and create a new client called 'fruits'.
In the `Capability config` step, enable `Direct access grants`:

![img.png](./images/capability_config.png)

In the third step, leave everything as is, and save the client.

All clients will have a client scope named `<client-name>-dedicated`. This will hold claims mappers for this scope.
<br/>Go to the `fruits-dedicated` scope, and into the `Scope` tab. 
Make sure `Full scope allowed` is disabled.

![img.png](./images/full_scope.png)

This setting allows roles to leak through from other clients the user has access to.
For the sake of this workshop, this will only make the tokens kind of noisy.

In order to have time to do debugging and not have to issue new tokens we want to have a token with a longer lifespan.
<br/>Go to the client advanced settings. Scroll to the bottom and set the `Access Token Lifespan` to a more suitable value:

![img.png](./images/lifespan.png)

#### Create a user
Now we are going create a user we are going to use throughout the rest of the workshop.
* In the `Users` menu, click `Add user`.
* Add at least `username` and  `email`, `firstname` and `lastname`. Note that first name and last name are required by default in non-master realms.
* Set `Email verified` to `yes`.
* Save the user.
* After the user is created, go to the `Credentials` tab and press `Set password`.
<br/> Enter passwords and set `Temporary` to `Off`.

Log in using the newly created user, either through the [](needs adding) or using the following cURL:
```shell
curl -k --location --request POST 'https://ws-keycloak.local/realms/workshop/protocol/openid-connect/token' \
--header 'Accept: application/json' \
--header 'Content-Type: application/x-www-form-urlencoded' \
--data-urlencode 'username=<user name>' \
--data-urlencode 'password=<user password>' \
--data-urlencode 'client_id=fruits' \
--data-urlencode 'grant_type=password'
```
After a successful login, inspect your token at [jwt.io](https://jwt.io)
## Standard Claims Mappers
Keycloak is using claims mappers to map different kind of information into claims in tokens.
Some mappers are added as part of a client-scope, while others are added directly to the client itself. 
In the latter case, it is actually also added to a client scope. 
In order to add a mapper to one specific client, it has to be added to the client scope named `<client name>-dedicated`
### Audience Resolve Mapper
Audience is a standard oidc claim used to specify for what application the token is issued. 
If one realm is used against different applications, the general advice is to use different clients and different audiences for authorization for the different apps.
Clients in Keycloak have an `Audience Resolve mapper` defined. 
This adds the client id as audience if the user has at least one client role for this client.
<br/> If you use the client just for ensuring the user is authenticated without any assigned roles, this will not do the job.
Also, we have experienced that it will not add the `aud` claim unless `Full scope allowed` is used.
### Audience Mapper
In the case of the `Audience Resolve Mapper` is not doing the job, the `Audience mapper` can be used. 

To add an audience mapper, go to the dedicated client-scope. 
In the tab `Mappers` click `Configure a new mapper` and select `Audience`.
The audience can either be chosen from a list of name of the configured clients, or a custom string can be configured for the audience. 
Note that the name is for the name of the mapper, not the claim.
### User Attribute Mapper
This mapper will map a given user attribute or attribute in a user group to a custom claim.
Be aware that a user can configure her own attributes if the attribute name is not protected. 
To protect for instance all user attributes prefixed with `ws.` add the following environment variable to the keycloak app in docker-compose. Then restart docker-compose.
```
KC_SPI_USER_PROFILE_DECLARATIVE_USER_PROFILE_READ_ONLY_ATTRIBUTES=ws.*
```

### Exercise 7
Make sure that your client is configured such that the token has the `"aud":"fruits"` claim.
## Client Credentials
OAuth2 specifies a  `Client Credentials Grant`. This is typically used for machine to machine authorization. 
In Keycloak, this is known as `Service account roles`.
**In a later exercise we are going to use a client credentials client for authorization when inspecting an incoming token.**
Create a client credentials client.
### Exercise 8
In the clients tab, press the `Create client` button.
Give the new client the id and name `introspect`. Click next and in the next form, choose `Client Authentication` and `Service account roles`. 
Disable everything else.
![img.png](images/introspect_client.png)

In the last Form just click `Save`.

Observe that the `Client secret` needed when this client is used, can be found in the `Credentials` tab of the client details.

![img.png](images/introspect_client_2.png)

## Enforcing MFA
MFA can be set up in several different ways. 

The user can set an authenticator application under `Account security` at [Account settings](https://ws-keycloak.local/realms/workshop/account/#/account-security/signing-in).

The Authentication flow can be edited to enforce MFA by setting `Conditional OTP` to `Required`. 
![img.png](images/flow_mfa.png)
This will then enforce MFA for this flow only. Doing this with the Direct access grant flow will make this flow fail if no MFA is already configured, since this flow is not interactive.

In a new environment, the best way of enforcing MFA will be to set `Configure OTP` as a required action. This will enforce MFA when creating new accounts.
![img.png](images/set_otp_default.png)
### Exercise 9
* Set `Configure OTP` as a required action as described above. 
* Create a new user and go to [Account settings](https://ws-keycloak.local/realms/workshop/account) and log in using the newly created user.
* When asked, register an authenticator application.
* Authenticate using cURL or Postman. If no changes have been done since the last login, the login should be rejected.

In order to login using `Resource owner password credentials grant` with TOTP, another parameter must be added to the request:
```
--data-urlencode 'totp=<password from authenticator app>'
```
Verify that you are able to authenticate with a TOTP.
## Custom Claims Mapper
If the claims mappers provided with Keycloak does not fulfill your needs for custom claims, you can develop your own claims mappers and provide with Keycloak.
Reasons for doing this, could for instance be adding information not available directly to Keycloak to the token.
We have provided a small project with a partially implemented claims mapper. [secret-fruit-mapper](./secret-fruit-mapper/src/main/java/com/workshop/identity/oidc/mappers/ClaimsMapper.java). 

In order to make the mapper visible in Keycloak, we need the following resource files:
* [jboss-deployment-structure.xml](./secret-fruit-mapper/src/main/resources/META-INF/services/jboss-deployment-structure.xml)
* [org.keycloak.protocol.ProtocolMapper](./secret-fruit-mapper/src/main/resources/META-INF/services/org.keycloak.protocol.ProtocolMapper)

In order to have the mapper added to Keycloak, we need to add a build step to the [Dockerfile](./docker/keycloak/Dockerfile) and have the build files copied to the image.
```Dockerfile
FROM maven:3.8.3-openjdk-17 AS mvnBuild
WORKDIR build
COPY pom.xml pom.xml
COPY fruits/pom.xml fruits/pom.xml
COPY secret-fruit-mapper/src secret-fruit-mapper/src
COPY secret-fruit-mapper/pom.xml secret-fruit-mapper/pom.xml
RUN mvn install -pl secret-fruit-mapper
RUN ls -al secret-fruit-mapper/target
```
To the `builder` part of the [Dockerfile](./docker/keycloak/Dockerfile) add the following
```Dockerfile
COPY --from=mvnBuild /build/secret-fruit-mapper/target/secret-fruit-mapper*.jar /opt/keycloak/providers/secret-fruit-mapper.jar
```
### Exercise 10
Finish the secret-fruit-mapper and complete the Dockerfile in order to get a `secret-fruit` claim added to the access-token.
<br/>Verify in the fruits client `fruits-dedicated` scope, that you have the `Secret Fruit Mapper` available.
![img.png](./images/secret_fruit_mapper.png)
Add it to the client scope and verify that the claim is added to the token.
If the exercise is correctly solved, the value of the scope should change between issued tokens.
## Quarkus RBAC Tutorial 
The module `fruits` is a small Quarkus application tha serves name of fruits with descriptions.
In order to add OIDC support to the project, we can run the following:
```shell
./mvnw quarkus:add-extension -D"extensions=quarkus-oidc,quarkus-keycloak-authorization" -pl fruits
```
In order to Authorize the user, OIDC support must be configured and the resource must be annotated for role access.
Add configuration to [application.properties](./fruits/src/main/resources/application.properties)
```properties
quarkus.test.continuous-testing=disabled

quarkus.oidc.auth-server-url=https://ws-keycloak.local/realms/workshop/
quarkus.oidc.client-id=fruits
#quarkus.oidc.credentials.secret=<secret>
quarkus.oidc.introspection-credentials.name=introspect
quarkus.oidc.introspection-credentials.secret=<secret>
quarkus.oidc.tls.verification=none
quarkus.oidc.token.audience=fruits
```
`quarkus.oidc.introspection-credentials.name` and `quarkus.oidc.introspection-credentials.secret` is used if one uses a client credentials client for authorising when inspecting the token.
If the fruits client is used, it must be enabled for `Client authentication` and `Service accounts roles` must be enabled.
This also means that the client secret must be used when logging in the user.

### Exercise 11
In the [FruitResource](./fruits/src/main/java/com/workshop/FruitResource.java)
use a combination of the annotation `io.quarkus.security.authenticated` and the annotations in the package `jakarta.annotation.security` to achieve what you are after. 
The `@RolesAllowed` annotation will be especially useful.
Also, the following is a useful way of getting hold of the decoded token:
```java
    @Inject
    JsonWebToken jwt;
```

The different endpoints of the resource is commented to explain how it should work.
Running the application can be done from the shell with:
```shell
./mvnw compile quarkus:dev -pl fruits
```
Or, you can use the `Quarkus` run configuration in your favourite IDE(A)