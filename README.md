### AUTOMATED

  ```shell
  ./oidc_idp_server
  ```

### LOCAL

  ```shell
  ./mvnw -Doidc.idp.server.jar_name=oidc_idp_server -f pom.xml clean package
  cp -vf ./target/oidc_idp_server.jar ./gae/app.jar
  ```

### LOCAL+DOCKER

  ```shell
  docker build --build-arg='JAR_NAME=oidc_idp_server' -t oidc-idp-server .
  image_id=$(docker create oidc-idp-server)
  docker cp ${image_id}:/usr/app/app.jar ./gae/app.jar
  docker rm $(image_id)
  docker image rm oidc-idp-server
  ```

### DEPLOY

1. define OIDC server properties

  ```shell
  export GCP_PROJECT_ID='...'
  export GAE_SERVICE='...'
  export OIDC_DOMAIN='...' # for users email, i/e: OIDC_DOMAIN='oidc.app' => user@oidc.app
  export OIDC_CLIENT_ID='...'
  export OIDC_CLIENT_SECRET=$
  ```

2. substitute OIDC server properties in GAE `app.yaml`

  ```shell
  envsubst < ./app_template.yaml > ./gae/app.yaml
  ```

3. deploy the OIDC server

  ```shell
  gcloud app deploy --project=${GCP_PROJECT_ID} --appyaml=./gae/app.yaml ./gae/
  ```

4. clean up

  ```shell
  unset GCP_PROJECT_ID
  unset GAE_SERVICE
  unset OIDC_DOMAIN
  unset OIDC_CLIENT_ID
  unset OIDC_CLIENT_SECRET

  rm -vf ./gae/app.*
  ```
