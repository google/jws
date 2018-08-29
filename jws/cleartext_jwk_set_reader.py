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
"""Static methods for reading cleartext keysets.

Warning: storing cleartext keysets in source code or disk is a bad practice.
User should use Key Management System (KMS) such as Cloud KMS
(https://cloud.google.com/kms/) or AWS KMS (https://aws.amazon.com/kms/) to
manage raw Jwk Keyset.
"""

__author__ = "quannguyen@google.com (quan nguyen)"

import json
from . import jwsutil
from cryptography import exceptions
from cryptography.hazmat import backends
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from .jwk import Jwk
from .jwk import JwkSet


class CleartextJwkSetReader(object):
  """Static methods for reading cleartext keysets."""

  @classmethod
  def from_cryptography_key(cls, key, algorithm, kid=""):
    """Transform cryptography's key to Jwk key.

    As cryptography's key doesn't specify the full algorithm to use (e.g. a RSA
    key doesn't specify which hash function should be used), the caller has to
    specify what algorithm that it would use the key for.

    Args:
      key: rsa.RSAPrivateKey, rsa.RSAPublicKey, ec.EllipticCurvePrivateKey or
        ec.EllipticCurvePublicKey
      algorithm: string, RSA or ECDSA algorithm as defined at
        https://tools.ietf.org/html/rfc7518#section-3.1.
      kid: string, Key ID as defined at
        https://tools.ietf.org/html/rfc7515#section-4.1.4.

    Raises:
      UnsupportedAlgorithm: if the algorithm is not supported or cryptography
      key has error.

    Returns:
      A JwkSet.
    """
    rsa_algorithms = ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512"]
    ecdsa_algorithms = ["ES256", "ES384", "ES512"]

    if algorithm in rsa_algorithms:
      if isinstance(key, rsa.RSAPrivateKey):
        return JwkSet([Jwk("RSA", kid, algorithm, None, key, key.public_key())])
      elif isinstance(key, rsa.RSAPublicKey):
        return JwkSet([Jwk("RSA", kid, algorithm, None, None, key)])
      else:
        raise exceptions.UnsupportedAlgorithm(
            "Unsupported mismatch between algorithm: %s and cryptography key:%s"
            % (algorithm, key))
    elif algorithm in ecdsa_algorithms:
      if isinstance(key, ec.EllipticCurvePrivateKey):
        return JwkSet([Jwk("EC", kid, algorithm, None, key, key.public_key())])
      elif isinstance(key, ec.EllipticCurvePublicKey):
        return JwkSet([Jwk("EC", kid, algorithm, None, None, key)])
      else:
        raise exceptions.UnsupportedAlgorithm(
            "Unsupported mismatch between algorithm: %s and cryptography key:%s"
            % (algorithm, key))
    else:
      raise exceptions.UnsupportedAlgorithm(
          "Unknown algorithm: %s" % (algorithm))

  @classmethod
  def from_pem(cls, pem_key, algorithm, kid=""):
    """Parses PEM key and transformat it to Jwk key.

    As PEM key doesn't specify the full algorithm to use (e.g. a RSA key doesn't
    specify which hash function should be used), the caller has to specify what
    algorithm that it would use the key for.
    Args:
      pem_key: bytes, RSA or ECDSA key in PEM format.
      algorithm: string, RSA or ECDSA algorithm as defined at
        https://tools.ietf.org/html/rfc7518#section-3.1.
      kid: string, Key ID as defined at
        https://tools.ietf.org/html/rfc7515#section-4.1.4.

    Raises:
      UnsupportedAlgorithm: if the algorithm is not supported or pem_key is
      error.
    """
    if algorithm not in [
        "RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384",
        "PS512"
    ]:
      raise exceptions.UnsupportedAlgorithm(
          "Unknown algorithm: %s" % (algorithm))
    key_type = ""
    key = ""
    # Try to parse it as private key.
    try:
      key = load_pem_private_key(
          pem_key, None, backend=backends.default_backend())
    except (ValueError, TypeError, exceptions.UnsupportedAlgorithm) as ignored:
      # If not succeeded, try to parse it as public key.
      try:
        key = load_pem_public_key(pem_key, backend=backends.default_backend())
      except (ValueError, TypeError, exceptions.UnsupportedAlgorithm) as e:
        raise exceptions.UnsupportedAlgorithm("Pem key parsing error: %s" % (e))
    if isinstance(key, rsa.RSAPrivateKey):
      return JwkSet([Jwk("RSA", kid, algorithm, None, key, key.public_key())])
    elif isinstance(key, rsa.RSAPublicKey):
      return JwkSet([Jwk("RSA", kid, algorithm, None, None, key)])
    elif isinstance(key, ec.EllipticCurvePrivateKey):
      return JwkSet([Jwk("EC", kid, algorithm, None, key, key.public_key())])
    elif isinstance(key, ec.EllipticCurvePublicKey):
      return JwkSet([Jwk("EC", kid, algorithm, None, None, key)])
    else:
      raise exceptions.UnsupportedAlgorithm(
          "Unknown supported key pem: %s" % (e))

  @classmethod
  def from_json(cls, json_keys):
    """Parses raw string json key and transforms it to Jwk key.

    Args:
      json_keys: string, a set of Jwk keys as defined at rfc7517#section-5.1. If
        the field "keys" is missing, we'll treat it as a single key. Each single
        key format is defined at https://tools.ietf.org/html/rfc7518#section-6.

    Raises:
      UnsupportedAlgorithm: if the key type is not supported.

    Returns:
      A JwkSet.
    """

    parsed_keys = json.loads(json_keys)
    if parsed_keys.get("keys", ""):
      # A list of keys.
      keys = []
      for json_key in parsed_keys.get("keys"):
        keys.append(CleartextJwkSetReader._read_single_json_key(json_key))
      return JwkSet(keys)
    else:
      # A single key.
      return JwkSet([CleartextJwkSetReader._read_single_json_key(parsed_keys)])

  @classmethod
  def _read_single_json_key(cls, parsed_key):
    """Reads a parsed json key and transform it to Jwk key.

    The key format is defined at
    https://tools.ietf.org/html/rfc7518#section-6.

    Args:
      parsed_key: a Python reprenstation of Json object.

    Raises:
      UnsupportedAlgorithm: if the key type is not supported.

    Returns:
      A Jwk key.
    """

    key_type = parsed_key["kty"]
    algorithm = parsed_key.get("alg", "")

    if not algorithm:
      raise exceptions.UnsupportedAlgorithm("Alg field is missing")

    if algorithm not in [
        "HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "ES256", "ES384",
        "ES512", "PS256", "PS384", "PS512"
    ]:
      raise exceptions.UnsupportedAlgorithm(
          "Unknown algorithm: %s" % (algorithm))

    if key_type == "RSA":
      rsa_pub_numbers = rsa.RSAPublicNumbers(
          jwsutil.b64_to_int(parsed_key["e"]),
          jwsutil.b64_to_int(parsed_key["n"]))
      if parsed_key.get("p", None) is not None:
        # Rsa private key.
        rsa_priv_numbers = rsa.RSAPrivateNumbers(
            jwsutil.b64_to_int(parsed_key["p"]),
            jwsutil.b64_to_int(parsed_key["q"]),
            jwsutil.b64_to_int(parsed_key["d"]),
            jwsutil.b64_to_int(parsed_key["dp"]),
            jwsutil.b64_to_int(parsed_key["dq"]),
            jwsutil.b64_to_int(parsed_key["qi"]), rsa_pub_numbers)
        priv_key = rsa_priv_numbers.private_key(backends.default_backend())
        return Jwk(key_type, parsed_key.get("kid", ""), algorithm, None,
                   priv_key, priv_key.public_key())
      else:
        # Rsa public key.
        return Jwk(key_type, parsed_key.get("kid", ""), algorithm, None, None,
                   rsa_pub_numbers.public_key(backends.default_backend()))
    elif key_type == "EC":
      if parsed_key["crv"] == "P-256":
        curve = ec.SECP256R1()
      elif parsed_key["crv"] == "P-384":
        curve = ec.SECP384R1()
      elif parsed_key["crv"] == "P-521":
        curve = ec.SECP521R1()
      else:
        raise exceptions.UnsupportedAlgorithm(
            "Unknown curve: %s" % (parsed_key["crv"]))
      if parsed_key.get("d", None) is not None:
        # Ecdsa private key.
        priv_key = ec.derive_private_key(
            jwsutil.b64_to_int(parsed_key["d"]), curve,
            backends.default_backend())
        return Jwk(key_type, parsed_key.get("kid", ""), algorithm, None,
                   priv_key, priv_key.public_key())
      else:
        # Ecdsa public key.
        ec_pub_numbers = ec.EllipticCurvePublicNumbers(
            jwsutil.b64_to_int(parsed_key["x"]),
            jwsutil.b64_to_int(parsed_key["y"]), curve)
        pub_key = ec_pub_numbers.public_key(backends.default_backend())
        return Jwk(key_type, parsed_key.get("kid", ""), algorithm, None, None,
                   pub_key)
    elif key_type == "oct":
      sym_key = jwsutil.urlsafe_b64decode(parsed_key["k"])
      return Jwk(key_type, parsed_key.get("kid", ""), algorithm, sym_key)
    else:
      raise exceptions.UnsupportedAlgorithm(
          "Unsupported key type: %s" % (key_type))
