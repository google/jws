# Description:
#   A safe subset of Json Web Signature (JWS).

package(default_visibility = ["//visibility:public"])

test_source = glob(["tests/**/*.py"])

py_library(
    name = "jwslib",
    srcs = glob(
        ["*.py"],
        exclude = test_source,
    ),
    visibility = ["//visibility:public"],
    deps = [
        "//third_party/py/cryptography",
    ],
)

py_test(
    name = "jws_test",
    srcs = ["tests/jws_test.py"],
    deps = [
        ":jwslib",
    ],
)
