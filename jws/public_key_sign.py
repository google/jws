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
"""Abstract base class for public key signing.

Security guarantees:

The functionality of Digital Signatures is represented a pair of primitives
PublicKeySign for signing of data, and PublicKeyVerify for verification of
signatures. Implementations of these primitives are secure against adaptive
chosen-message attacks. Signing data ensures the authenticity and the integrity
of that data, but not its secrecy.
"""

__author__ = "quannguyen@google.com (Quan Nguyen)"

import abc


class PublicKeySign(object):
  """Abstract base class for public key signing."""
  __metaclass__ = abc.ABCMeta

  @abc.abstractmethod
  def sign(self, data):
    """Computes the signature for data.

    Args:
      data: bytes, the data.

    Returns:
      bytes, the signature of data.

    Raises:
      TypeError: if the data is not bytes.
    """
