# Copyright 2018 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Common utility library."""

import base64
import binascii
from cryptography import exceptions
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import json
import six


def urlsafe_b64encode(raw_bytes):
  if isinstance(raw_bytes, six.text_type):
    # https://tools.ietf.org/html/rfc7515#appendix-A.1 asks us to encode string
    # using UTF-8.
    raw_bytes = raw_bytes.encode("utf-8")
  # https://tools.ietf.org/html/rfc7515#appendix-C uses b64 encoding without
  # padding '='.
  return base64.urlsafe_b64encode(raw_bytes).decode("utf-8").rstrip("=").encode(
      "utf-8")


def urlsafe_b64decode(b64string):
  if isinstance(b64string, six.text_type):
    b64string = b64string.encode("utf-8")
  # Add extra padding '=' as https://tools.ietf.org/html/rfc7515#appendix-C uses
  # b64 encoding without padding.
  padded = b64string + b"=" * (4 - len(b64string) % 4)
  return base64.urlsafe_b64decode(padded)


def json_encode(data):
  return json.dumps(data, separators=(",", ":")).encode("utf-8")


def bytes_to_int(b):
  return int(binascii.hexlify(b), 16)


def b64_to_int(b64string):
  b = urlsafe_b64decode(b64string)
  return bytes_to_int(b)


def int_to_bytes(x, length):
  """Converts bigendian integer to byte array with fixed length."""
  res = bytearray(length)
  for i in range(length):
    res[length - i - 1] = int(x) % 256
    x = int(x) // 256
  return res


def ecdsa_algorithm_to_curve_length(algorithm):
  """Computes curve length based on ecdsa's algorithm.

  Args:
    algorithm: string, Ecdsa algorithm as defined at
    https://tools.ietf.org/html/rfc7518#section-3.1.

  Raises:
    UnsupportedAlgorithm: if the algorithm is not supported.

  Returns:
    The curve length in bytes.
  """

  _NIST_P256_CURVE_LENGTH_IN_BITS = 256
  _NIST_P384_CURVE_LENGTH_IN_BITS = 384
  _NIST_P521_CURVE_LENGTH_IN_BITS = 521

  if algorithm == "ES256":
    return int(_NIST_P256_CURVE_LENGTH_IN_BITS // 8)
  elif algorithm == "ES384":
    return int(_NIST_P384_CURVE_LENGTH_IN_BITS // 8)
  elif algorithm == "ES512":
    return int((_NIST_P521_CURVE_LENGTH_IN_BITS + 7) // 8)
  else:
    raise exceptions.UnsupportedAlgorithm("Unknown algorithm: %s" % (algorithm))


def parse_rsa_algorithm(algorithm):
  """Parses Rsa's algorithm and returns tuple (hash, padding).

  Args:
    algorithm: string, RSA algorithm as defined at
    https://tools.ietf.org/html/rfc7518#section-3.1.

  Raises:
    UnsupportedAlgorithm: if the algorithm is not supported.

  Returns:
    (hash, padding) tuple.
  """

  if algorithm == "RS256":
    return (hashes.SHA256(), padding.PKCS1v15())
  elif algorithm == "RS384":
    return (hashes.SHA384(), padding.PKCS1v15())
  elif algorithm == "RS512":
    return (hashes.SHA512(), padding.PKCS1v15())
  elif algorithm == "PS256":
    return (hashes.SHA256(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH))
  elif algorithm == "PS384":
    return (hashes.SHA384(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA384()),
                salt_length=padding.PSS.MAX_LENGTH))
  elif algorithm == "PS512":
    return (hashes.SHA512(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA512()),
                salt_length=padding.PSS.MAX_LENGTH))
  else:
    raise exceptions.UnsupportedAlgorithm("Unknown algorithm: %s" % (algorithm))
