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
"""Abstract base class for message authentication code (MAC).

Security guarantees:

Message Authentication Codes provide symmetric message authentication.
Instances implementing this abstract class are secure against existential
forgery under chosen plaintext attack, and can be deterministic or randomized.
This abstract class should be used for authentication only, and not for other
purposes like generation of pseudorandom bytes."""

__author__ = "quannguyen@google.com (Quan Nguyen)"

import abc

from .exceptions import SecurityException


class Mac(object):
  """Abstract base class for message authentication code (MAC)."""
  __metaclass__ = abc.ABCMeta

  @abc.abstractmethod
  def compute_mac(self, data):
    """Computes message authentication code (MAC) for data.

    Args:
      data: bytes, the data.

    Returns:
      bytes, message authentication code (MAC) of the data.
    """

  @abc.abstractmethod
  def verify_mac(self, mac, data):
    """Verifies whether mac is the correct message authentication code of data.

    Args:
      mac: bytes, the message authentication code to verify against data.
      data: bytes, the data.
    Raises:
      SecurityException: when the mac is invalid.
    """
