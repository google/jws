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
"""An implementation of PublicKeySign for RSA.

The implementation supports both PKCS1-v1_5 and PSS signatures.
"""

__author__ = "quannguyen@google.com (Quan Nguyen)"

from cryptography.hazmat.primitives.asymmetric import rsa
import six

from . import jwsutil
from .public_key_sign import PublicKeySign


class RsaSign(PublicKeySign):
  """RSA signing with cryptography.io."""

  def __init__(self, priv_key, algorithm):
    """Constructor for RsaSign.

    Args:
      priv_key: rsa.RSAPrivateKey, the RSA private key.
      algorithm: string, RSA algorithm as defined at
        https://tools.ietf.org/html/rfc7518#section-3.1.

    Raises:
      TypeError: if the private key is not an instance of rsa.RSAPrivateKey.
      UnsupportedAlgorithm: if the algorithm is not supported.
    """
    if not isinstance(priv_key, rsa.RSAPrivateKey):
      raise TypeError(
          "The private key must be an instance of rsa.RSAPrivateKey")
    self.priv_key = priv_key
    self.algorithm = algorithm
    (self.hash, self.padding) = jwsutil.parse_rsa_algorithm(algorithm)

  def sign(self, data):
    """See base class."""
    if not isinstance(data, six.binary_type):
      raise TypeError("data must be bytes.")
    return self.priv_key.sign(data, self.padding, self.hash)
