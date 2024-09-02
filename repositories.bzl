load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

def springboot():
    http_archive(
        name = "rules_spring",
        sha256 = "fa067d7ed07437a3be3a211564f485648fc9f2ecc827a189d98b60dc5a078fa2",
        url = "https://github.com/salesforce/rules_spring/releases/download/2.3.0/rules-spring-2.3.0.zip",
    )
