load("@rules_java//java:defs.bzl", "java_binary", "java_library")
load("@rules_spring//springboot:springboot.bzl", "springboot")

package(default_visibility = ["//visibility:public"])

java_library(
  name = "oidc-idp-server-deps",
  exports = [
    "@rules_spring//springboot/import_bundles:springboot_required_deps",
    "@maven//:javax_annotation_javax_annotation_api",
    "@maven//:org_slf4j_slf4j_api",
    "@maven//:com_nimbusds_nimbus_jose_jwt_9_16_1",
    "@maven//:jakarta_servlet_jakarta_servlet_api",
    "@maven//:jakarta_annotation_jakarta_annotation_api",
    "@maven//:org_springframework_spring_web",
    "@maven//:org_springframework_spring_beans",
    "@maven//:org_springframework_spring_context",
    "@maven//:org_springframework_boot_spring_boot",
    "@maven//:org_springframework_boot_spring_boot_loader_tools",
    "@maven//:org_springframework_boot_spring_boot_starter_web",
    "@maven//:org_springframework_boot_spring_boot_starter_jetty",
    # "@maven//:org_apache_tomcat_embed_tomcat_embed_core",
    # "@maven//:org_springframework_boot_spring_boot_starter_tomcat",
    "@maven//:org_springframework_boot_spring_boot_autoconfigure",
    "@maven//:org_springframework_boot_spring_boot_configuration_processor",
  ],
)

java_library(
    name = "oidc-idp-server-lib",
    srcs = glob(["src/main/java/dev/chux/idp/oidc/**/*.java"]),
    resources = glob(["src/main/resources/**"]),
    deps = [
      ":oidc-idp-server-deps",
    ],
)

java_binary(
    name = "oidc-idp-server",
    main_class = "dev.chux.idp.oidc.OidcServer",
    runtime_deps = [":oidc-idp-server-lib"],
)

springboot(
    name = "oidc-idp-server-boot",
    boot_app_class = "dev.chux.idp.oidc.OidcServer",
    java_library = ":oidc-idp-server-lib",
)
