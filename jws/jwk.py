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
"""Json Web Key (JWK) (rfc7517)."""

__author__ = "quannguyen@google.com (quan nguyen)"


class JwkSet(object):
  """A set of Jwk keys that can be used in Jws."""

  def __init__(self, keys):
    """Constructor for JwkSet.

    Args:
      keys: list, a list of Jwk keys.
    """
    self.keys = keys


class Jwk(object):
  """A single Json Web Key (Jwk) that can be used in Jws."""

  def __init__(self,
               key_type,
               kid,
               algorithm,
               sym_key=None,
               priv_key=None,
               pub_key=None):
    """Construtor for Jwk.

    Args:
      key_type: string, key type such as "RSA", "EC", "oct".
      kid: string, Key ID as defined at
        https://tools.ietf.org/html/rfc7515#section-4.1.4.
      algorithm: string, algorithm as defined at
        https://tools.ietf.org/html/rfc7518#section-3.1.
      sym_key: bytes, symmetric key.
      priv_key: rsa.RSAPrivateKey or ec.EllipticCurvePrivateKey, the private key
        part of key pair.
      pub_key: rsa.RSAPublicKey or ec.EllipticCurvePublicKey, the public key
        part or key pair.
    """
    if sym_key is not None:
      self.sym_key = sym_key
    if priv_key is not None:
      self.priv_key = priv_key
    if pub_key is not None:
      self.pub_key = pub_key
    self.kid = kid
    self.key_type = key_type
    self.algorithm = algorithm
