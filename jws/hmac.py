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
"""An implementation of Mac for HMAC(rfc2104)."""

__author__ = "quannguyen@google.com (Quan Nguyen)"

from cryptography import exceptions
from cryptography.hazmat import backends
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import hmac
import six

from .mac import Mac
from .exceptions import SecurityException


class Hmac(Mac):
  """HMAC(rfc2104) with cryptography.io."""

  # TODO(quannguyen): support truncated MAC.
  def __init__(self, hmac_key, algorithm):
    """Constructor for Hmac.

    Args:
      hmac_key: bytes, the symmetric hmac key.
      algorithm: string, HMAC algorithm as defined at
        https://tools.ietf.org/html/rfc7518#section-3.1.

    Raises:
      TypeError: if the hmac key is not bytes.
      UnsupportedAlgorithm: if the algorithm is not supported or key is too
      short.
    """
    if algorithm == "HS256":
      self._hash = hashes.SHA256()
    elif algorithm == "HS384":
      self._hash = hashes.SHA384()
    elif algorithm == "HS512":
      self._hash = hashes.SHA512()
    else:
      raise exceptions.UnsupportedAlgorithm(
          "Unknown algorithm: %s " % (algorithm))
    if not isinstance(hmac_key, six.binary_type):
      raise TypeError("hmac key must be bytes")
    if len(hmac_key) < 16:
      raise exceptions.UnsupportedAlgorithm("key too short")
    self._hmac_key = hmac_key
    self.algorithm = algorithm

  def compute_mac(self, data):
    """See base class."""
    if not isinstance(data, six.binary_type):
      raise TypeError("data must be bytes")
    h = hmac.HMAC(self._hmac_key, self._hash, backends.default_backend())
    h.update(data)
    return h.finalize()

  def verify_mac(self, mac, data):
    """See base class."""
    if not isinstance(mac, six.binary_type) or not isinstance(
        data, six.binary_type):
      raise SecurityException("Mac or data must be bytes")
    try:
      h = hmac.HMAC(self._hmac_key, self._hash, backends.default_backend())
      h.update(data)
      h.verify(mac)
    except:
      raise SecurityException("Invalid mac")
