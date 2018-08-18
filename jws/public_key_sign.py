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
