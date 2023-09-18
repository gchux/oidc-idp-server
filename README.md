```shell
./mvnw clean package
docker build -t oidc-idp-server .
gcloud app deploy
```
