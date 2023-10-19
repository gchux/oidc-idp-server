FROM maven:3-eclipse-temurin-17-alpine as builder

ARG JAR_NAME=oidc_idp_server

COPY src /usr/src/app/src
COPY pom.xml /usr/src/app

RUN mvn -Doidc.idp.server.jar_name=${JAR_NAME} -f /usr/src/app/pom.xml clean package

FROM openjdk:17-alpine

ARG JAR_NAME=oidc_idp_server

# ENV OIDC_DOMAIN oidc.app
# ENV OIDC_ISSUER https://localhost
# ENV OIDC_CLIENT_ID test
# ENV OIDC_CLIENT_SECRET test
# ENV OIDC_REDIRECTS http://localhost
# ENV OIDC_ENFORCE_CLIENT_ID false
# ENV OIDC_ENFORCE_CLIENT_SECRET false
# ENV OIDC_ENFORCE_REDIRECT false
# ENV OIDC_ENFORCE_DOMAIN false
# ENV OIDC_ALLOW_ALL true
# ENV OIDC_ADD_ALL true

COPY --from=builder /usr/src/app/target/${JAR_NAME}.jar /usr/app/app.jar

ENTRYPOINT ["java", "-jar", "/usr/app/app.jar"]
