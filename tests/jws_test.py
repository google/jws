"""Copyright 2018 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License."""

"""Tests for google3.experimental.users.quannguyen.python.jwslib.jws."""

import json
import unittest

__author__ = 'quannguyen@google.com (Quan Nguyen)'


# TODO(quannguyen): Add more tests.
class JwsTest(unittest.TestCase):
  # Test vector from https://tools.ietf.org/html/rfc7515#appendix-A.2
  json_rsa_priv_key = r"""
    {
      "kty":"RSA",
      "n":"ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ",
      "e":"AQAB",
      "d":"Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97IjlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYTCBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLhBOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ",
      "p":"4BzEEOtIpmVdVEZNCqS7baC4crd0pqnRH_5IB3jw3bcxGn6QLvnEtfdUdiYrqBdss1l58BQ3KhooKeQTa9AB0Hw_Py5PJdTJNPY8cQn7ouZ2KKDcmnPGBY5t7yLc1QlQ5xHdwW1VhvKn-nXqhJTBgIPgtldC-KDV5z-y2XDwGUc",
      "q":"uQPEfgmVtjL0Uyyx88GZFF1fOunH3-7cepKmtH4pxhtCoHqpWmT8YAmZxaewHgHAjLYsp1ZSe7zFYHj7C6ul7TjeLQeZD_YwD66t62wDmpe_HlB-TnBA-njbglfIsRLtXlnDzQkv5dTltRJ11BKBBypeeF6689rjcJIDEz9RWdc",
      "dp":"BwKfV3Akq5_MFZDFZCnW-wzl-CCo83WoZvnLQwCTeDv8uzluRSnm71I3QCLdhrqE2e9YkxvuxdBfpT_PI7Yz-FOKnu1R6HsJeDCjn12Sk3vmAktV2zb34MCdy7cpdTh_YVr7tss2u6vneTwrA86rZtu5Mbr1C1XsmvkxHQAdYo0",
      "dq":"h_96-mK1R_7glhsum81dZxjTnYynPbZpHziZjeeHcXYsXaaMwkOlODsWa7I9xXDoRwbKgB719rrmI2oKr6N3Do9U0ajaHF-NKJnwgjMd2w9cjz3_-kyNlxAr2v4IKhGNpmM5iIgOS1VZnOZ68m6_pbLBSp3nssTdlqvd0tIiTHU",
      "qi":"IYd7DHOhrWvxkwPQsRM2tOgrjbcrfvtQJipd-DlcxyVuuM9sQLdgjVk2oy26F0EmpScGLq2MowX7fhd_QJQ3ydy5cY7YIBi87w93IKLEdfnbJtoOPLUW0ITrJReOgo1cq9SbsxYawBgfp_gh6A5603k2-ZQwVK0JKSHuLFkuQ3U",
      "alg":"RS256"
     }"""

  json_rsa_pub_key = r"""
    {
      "kty":"RSA",
      "n":"ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ",
      "e":"AQAB",
      "alg":"RS256"
    }"""

  json_rsa_pub_key2 = r"""
    {
      "kty":"RSA",
      "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
      "e":"AQAB",
      "kid":"2011-04-29"
    }"""

  # Test vector from https://tools.ietf.org/html/rfc7515#appendix-A.2
  rsa_token = 'eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw'

  # Test vector from https://tools.ietf.org/html/rfc7515#appendix-A.3
  ecdsa_token = 'eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q'

  # Test vector from https://tools.ietf.org/html/rfc7515#appendix-A.3
  json_ecdsa_priv_key = r"""
    {
      "kty":"EC",
      "crv":"P-256",
      "x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
      "y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
      "d":"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI",
      "alg":"ES256"
    }"""

  json_ecdsa_pub_key = r"""
    {
      "kty":"EC",
      "crv":"P-256",
      "x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
      "y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
      "alg":"ES256"
    }"""

  # Test vector from https://tools.ietf.org/html/rfc7515#appendix-A.1
  json_hmac_key = r"""
    {
      "kty":"oct",
      "k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow",
      "alg":"HS256"
    }"""

  # Test vector from https://tools.ietf.org/html/rfc7515#appendix-A.1
  hmac_token = 'eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'

  # Key set containing multiple public keys.
  json_pub_keys = r"""{"keys":[""" + json_rsa_pub_key + ',' + json_ecdsa_pub_key + r"""]}"""

  # The followings are our own tests.

  test_header_rsa = json.dumps(
      {
          'typ': 'JWT',
          'alg': 'RS256'
      }, separators=(',', ':'))

  test_header_ecdsa = json.dumps(
      {
          'typ': 'JWT',
          'alg': 'ES256'
      }, separators=(',', ':'))

  test_header_hmac = json.dumps(
      {
          'typ': 'JWT',
          'alg': 'HS256'
      }, separators=(',', ':'))

  test_payload = json.dumps({'aud': 'audience'}, separators=(',', ':'))

  test_header_ecdsa_kid1 = json.dumps(
      {
          'typ': 'JWT',
          'alg': 'ES256',
          'kid': 'kid1'
      }, separators=(',', ':'))

  test_header_ecdsa_kid2 = json.dumps(
      {
          'typ': 'JWT',
          'alg': 'ES256',
          'kid': 'kid2'
      }, separators=(',', ':'))

  test_json_ecdsa_priv_key_kid1 = r"""
    {
      "kty":"EC",
      "crv":"P-256",
      "x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
      "y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
      "d":"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI",
      "kid":"kid1",
      "alg":"ES256"
    }"""

  test_json_ecdsa_pub_key_kid1 = r"""
    {
      "kty":"EC",
      "crv":"P-256",
      "x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
      "y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
      "kid":"kid1",
      "alg":"ES256"
    }"""

  def test_jws_rsa_verifier_with_rfc(self):
    # Set up phase: parse the key and initialize the verifier.
    keys = CleartextJwkSetReader.from_json(self.json_rsa_pub_key)
    verifier = jws.JwsPublicKeyVerify(keys)

    # Use phase
    self.assertTrue(verifier.verify(self.rsa_token))
    self.assertFalse(verifier.verify(_modify_token(self.rsa_token)))

  def test_jws_rsa_signer_and_verifier(self):
    # Sign
    priv_key = CleartextJwkSetReader.from_json(self.json_rsa_priv_key)
    signer = jws.JwsPublicKeySign(priv_key)
    signed_token = signer.sign(self.test_header_rsa, self.test_payload)

    # Verify
    pub_key = CleartextJwkSetReader.from_json(self.json_rsa_pub_key)
    verifier = jws.JwsPublicKeyVerify(pub_key)
    self.assertTrue(verifier.verify(signed_token))
    self.assertFalse(verifier.verify(_modify_token(signed_token)))

  def test_jws_ecdsa_verifier_with_rfc(self):
    # Set up phase: parse the key and initialize the verifier.
    key = CleartextJwkSetReader.from_json(self.json_ecdsa_pub_key)
    verifier = jws.JwsPublicKeyVerify(key)

    # Use phase
    self.assertTrue(verifier.verify(self.ecdsa_token))
    self.assertFalse(verifier.verify(_modify_token(self.ecdsa_token)))

  def test_jws_ecdsa_signer_verifier(self):
    # Sign
    priv_key = CleartextJwkSetReader.from_json(self.json_ecdsa_priv_key)
    signer = jws.JwsPublicKeySign(priv_key)
    signed_token = signer.sign(self.test_header_ecdsa, self.test_payload)

    # Verify
    pub_key = CleartextJwkSetReader.from_json(self.json_ecdsa_pub_key)
    verifier = jws.JwsPublicKeyVerify(pub_key)
    self.assertTrue(verifier.verify(signed_token))
    self.assertFalse(verifier.verify(_modify_token(signed_token)))

  def test_jws_verifier_with_multiple_keys(self):
    # Set up phase: parse the keys and initialize the verifier.
    keys = CleartextJwkSetReader.from_json(self.json_pub_keys)
    verifier = jws.JwsPublicKeyVerify(keys)

    # Use phase
    self.assertTrue(verifier.verify(self.rsa_token))
    self.assertTrue(verifier.verify(self.ecdsa_token))
    self.assertFalse(verifier.verify(_modify_token(self.ecdsa_token)))
    self.assertFalse(verifier.verify(_modify_token(self.rsa_token)))

  def test_jws_verifier_with_kid(self):
    # Sign
    priv_key = CleartextJwkSetReader.from_json(
        self.test_json_ecdsa_priv_key_kid1)
    signer = jws.JwsPublicKeySign(priv_key)
    signed_token_kid1 = signer.sign(self.test_header_ecdsa_kid1,
                                    self.test_payload)
    signed_token_kid2 = signer.sign(self.test_header_ecdsa_kid2,
                                    self.test_payload)

    # Verify
    pub_key = CleartextJwkSetReader.from_json(self.test_json_ecdsa_pub_key_kid1)
    verifier = jws.JwsPublicKeyVerify(pub_key)
    self.assertTrue(verifier.verify(signed_token_kid1))
    # The signature is valid but the kids don't match.
    self.assertFalse(verifier.verify(signed_token_kid2))

  def test_jws_mac_verifier_with_rfc(self):
    # Set up phase: parse the key and initialize the JwsMacVerify
    key = CleartextJwkSetReader.from_json(self.json_hmac_key)
    verifier = jws.JwsMacVerify(key)

    # Use phase
    self.assertTrue(verifier.verify(self.hmac_token))
    self.assertFalse(verifier.verify(_modify_token(self.hmac_token)))

  def test_jws_mac_authenticator_and_verifier(self):
    # Authenticator
    mac_key = CleartextJwkSetReader.from_json(self.json_hmac_key)
    authenticator = jws.JwsMacAuthenticator(mac_key)
    signed_token = authenticator.authenticate(self.test_header_hmac,
                                              self.test_payload)
    # Verify
    verifier = jws.JwsMacVerify(mac_key)
    self.assertTrue(verifier.verify(signed_token))
    self.assertFalse(verifier.verify(_modify_token(signed_token)))


def _modify_token(token):
  [header, payload, sig] = token.split('.')
  decoded_sig = jwsutil.urlsafe_b64decode(sig)
  # Change the last byte.
  decoded_sig = decoded_sig[:-1] + chr(ord(decoded_sig[-1]) ^ 1)
  return header + '.' + payload + '.' + jwsutil.urlsafe_b64encode(decoded_sig)


if __name__ == '__main__':
  unittest.main()
