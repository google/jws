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
"""An implementation of PublicKeyVerify for RSA.

The implementation supports both PKCS1-v1_5 and PSS signatures.
"""

__author__ = "quannguyen@google.com (Quan Nguyen)"

from cryptography.hazmat.primitives.asymmetric import rsa
import six

from . import jwsutil
from .exceptions import SecurityException
from .public_key_verify import PublicKeyVerify


class RsaVerify(PublicKeyVerify):
  """RSA verifying with cryptography.io."""

  def __init__(self, pub_key, algorithm):
    """Constructor for RsaVerify.

    Args:
      pub_key: rsa.RSAPublicKey
      algorithm: string, RSA algorithm as defined at
        https://tools.ietf.org/html/rfc7518#section-3.1.

    Raises:
      TypeError: if public key is not an instance of rsa.RSAPublicKey.
      UnsupportedAlgorithm: if the algorithm is not supported.
    """
    if not isinstance(pub_key, rsa.RSAPublicKey):
      raise TypeError("The public key must be an instance of RSAPublicKey")
    self.pub_key = pub_key
    self.algorithm = algorithm
    (self.hash, self.padding) = jwsutil.parse_rsa_algorithm(algorithm)

  def verify(self, signature, data):
    """See base class."""
    if not isinstance(data, six.binary_type) or not isinstance(
        data, six.binary_type):
      raise SecurityException("Signature and data must be bytes")
    try:
      self.pub_key.verify(signature, data, self.padding, self.hash)
    except:
      raise SecurityException("Invalid signature")
