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
"""An implementation of PublicKeyVerify for ECDSA."""

__author__ = "quannguyen@google.com (Quan Nguyen)"

from cryptography import exceptions
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
import six

from .public_key_verify import PublicKeyVerify


class EcdsaVerify(PublicKeyVerify):
  """ECDSA verifying with cryptography.io."""

  def __init__(self, pub_key, algorithm):
    """Constructor for EcdsaVerify.

    Args:
      pub_key: ec.EllipticCurvePublicKey, the Ecdsa public key.
      algorithm: string, Ecdsa algorithm as defined at
        https://tools.ietf.org/html/rfc7518#section-3.1.
    Raises:
      TypeError: if the public key is not an instance of
      ec.EllipticCurvePublicKey.
      UnsupportedAlgorithm: if the algorithm is not supported.
    """
    if not isinstance(pub_key, ec.EllipticCurvePublicKey):
      raise TypeError(
          "The public key must be an instance of ec.EllipticCurvePublicKey")
    self.pub_key = pub_key
    curve_name = ""
    if algorithm == "ES256":
      self.hash = hashes.SHA256()
      curve_name = "secp256r1"
    elif algorithm == "ES384":
      self.hash = hashes.SHA384()
      curve_name = "secp384r1"
    elif algorithm == "ES512":
      self.hash = hashes.SHA512()
      curve_name = "secp521r1"
    else:
      raise exceptions.UnsupportedAlgorithm(
          "Unknown algorithm : %s" % (algorithm))
    # In Ecdsa, both the key and the algorithm define the curve. Therefore, we
    # must cross check them to make sure they're the same.
    if curve_name != pub_key.curve.name:
      raise exceptions.UnsupportedAlgorithm(
          "The curve in public key %s and in algorithm % don't match" %
          (pub_key.curve.name, curve_name))
    self.algorithm = algorithm

  def verify(self, signature, data):
    """See base class."""
    if not isinstance(signature, six.binary_type) or not isinstance(
        data, six.binary_type):
      raise SecurityException("Signature and data must be bytes")
    try:
      self.pub_key.verify(signature, data, ec.ECDSA(self.hash))
    except:
      raise SecurityException("Invalid signature")
