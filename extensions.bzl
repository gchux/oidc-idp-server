load("//:repositories.bzl", "springboot")

def _non_module_dependencies_impl(_ctx):
    springboot()

non_module_dependencies = module_extension(
    implementation = _non_module_dependencies_impl,
)
