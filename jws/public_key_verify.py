"""Abstract base class for public key verifying.

Security guarantees:

The functionality of Digital Signatures is represented a pair of primitives
PublicKeySign for signing of data, and PublicKeyVerify for verification of
signatures. Implementations of these primitives are secure against adaptive
chosen-message attacks. Signing data ensures the authenticity and the integrity
of that data, but not its secrecy.
"""

__author__ = "quannguyen@google.com (Quan Nguyen)"

import abc


class PublicKeyVerify(object):
  """Abstract base class for public key verifying."""
  __metaclass__ = abc.ABCMeta

  @abc.abstractmethod
  def verify(self, signature, data):
    """Verifies whether signature is a valid signature for data.

    Args:
      signature: bytes, the signature of data.
      data: bytes, the data to verify.

    Returns:
      True if the signature was valid, false if not.
    """
