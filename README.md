## What's this about?

The `oidc-idp-server` aims to make it easy
to test OIDC sign-in for Google Cloud Identity Platform
by self-hosting and self-managing a very simple OIDC server.

`oidc-idp-server` is not intended for production environments,
it's main goal is to demistify OIDC without providing any guarantees
of availability or security; so it's just a playground for
learning, testing, and troubleshooting.

`oidc-idp-server` current capabilities:

- enforce `client_id`, `client_secret`, `domain`, and `redirect` ( or not, up to you )
- add new users on the fly ( or not, up to you )
- for all available settings see: `src/main/resources/application.yml`
- use both `code-flow` and `implicit-flow`

## Requirements

1. some flavor of `64bit Linux`

2. install `envsubst`:

```shell
# Debian based distros
apt-get install gettext-base

# Alpine
apk add gettext

# Arch based distros
pacman -S gettext

# Fedora and friends
yum install gettext
dnf install gettext
```

3. install Google Cloud SDK: <https://cloud.google.com/sdk/docs/install>

4. clone this repo: `git clone https://github.com/charmbracelet/gum.git`

5. a billing enabled Google Cloud Platform Project to deploy it to App Engine
  
  > App Engine ( and optionally Cloud Build ) is currently required; however, you could very easily host it elsewhere

## How to deploy the `oidc-idp-server`

run the deployment script, and follow the instructions:

```shell
chmod +x ./oidc_idp_server
# the script will walk you through the deployment process
./oidc_idp_server
```

`oidc-idp-server` will deployed to Google App Engine: https://cloud.google.com/appengine

### Build locally
  
  - build type: `Local`
  - difficulty: moderate ( requires local environment instrumentation )

  *requirements:*

  - JDK 17: https://adoptium.net/temurin/releases/?os=linux&arch=x64&package=jdk&version=17


### Build locally using Docker

  - build type: `Local/Docker`
  - difficulty: moderate to low ( these days Docker is 1 script away )

  
  *requirements:*

  - https://docs.docker.com/engine/install/ubuntu/#install-using-the-convenience-script

### Google Cloud Build

  - build type: `GCP/Cloud Build`
  - difficulty: low

  *requirements:*

  - https://cloud.google.com/build

  > see: `templates/cloudbuild.yaml`

### OTHER TOOLS

  - tasks: https://taskfile.dev/

    > advanced users are advised to install it, and then use `task --list` to see all tasks available.

  - maven: https://maven.apache.org/
  - gum: https://github.com/charmbracelet/gum

  > all of these tools are dynamically provisioned as needed

## Limitations

  - the automated deployment does not support configurations for *permissive-ness*; it should, and it will at some point.
  - `JWKS` are static, these should generated for every deployment; this is coming soon ( see: `src/main/resources/jwks.json` )

## ToDo

  - enable *permissive-ness* configuation dynamically via automated deployment script
  - create new `JWKS` file for every deployment
  - document cool instrospection features
  - document how to configura Google Cloud Identity Platform to use `oidc-idp-server`
  - add a proper changelog

---

Please report any issues via GH issue tracker
