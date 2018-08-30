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
"""Tests for jws package."""

__author__ = 'quannguyen@google.com (Quan Nguyen)'

import json
import unittest

from jws import jwsutil
from jws import SecurityException
import calendar
import datetime
import jws
import six
from cryptography import exceptions
from cryptography.hazmat import backends
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.serialization import load_pem_public_key


# TODO(quannguyen): Add more tests.
class JwsTest(unittest.TestCase):

  # Test vector from https://tools.ietf.org/html/rfc7515#appendix-A.2.
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
  rsa_token = 'eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw'.encode(
      'utf-8')

  # Test vector from https://tools.ietf.org/html/rfc7515#appendix-A.3
  es256_ecdsa_token = 'eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q'.encode(
      'utf-8')

  es256_ecdsa_priv_key = r"""
    {
      "kty":"EC",
      "crv":"P-256",
      "x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
      "y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
      "d":"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI",
      "alg":"ES256"
    }"""

  es256_ecdsa_pub_key = r"""
    {
      "kty":"EC",
      "crv":"P-256",
      "x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
      "y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
      "alg":"ES256"
    }"""

  # Test vector from https://tools.ietf.org/html/rfc7515#appendix-A.4.
  es512_ecdsa_token = 'eyJhbGciOiJFUzUxMiJ9.UGF5bG9hZA.AdwMgeerwtHoh-l192l60hp9wAHZFVJbLfD_UxMi70cwnZOYaRI1bKPWROc-mZZqwqT2SI-KGDKB34XO0aw_7XdtAG8GaSwFKdCAPZgoXD2YBJZCPEX3xKpRwcdOO8KpEHwJjyqOgzDO7iKvU8vcnwNrmxYbSW9ERBXukOXolLzeO_Jn'.encode(
      'utf-8')

  es512_ecdsa_priv_key = r"""
    {
      "kty":"EC",
      "crv":"P-521",
      "x":"AekpBQ8ST8a8VcfVOTNl353vSrDCLLJXmPk06wTjxrrjcBpXp5EOnYG_NjFZ6OvLFV1jSfS9tsz4qUxcWceqwQGk",
      "y":"ADSmRA43Z1DSNx_RvcLI87cdL07l6jQyyBXMoxVg_l2Th-x3S1WDhjDly79ajL4Kkd0AZMaZmh9ubmf63e3kyMj2",
      "d":"AY5pb7A0UFiB3RELSD64fTLOSV_jazdF7fLYyuTw8lOfRhWg6Y6rUrPAxerEzgdRhajnu0ferB0d53vM9mE15j2C",
      "alg":"ES512"
    }"""

  es512_ecdsa_pub_key = r"""
    {
      "kty":"EC",
      "crv":"P-521",
      "x":"AekpBQ8ST8a8VcfVOTNl353vSrDCLLJXmPk06wTjxrrjcBpXp5EOnYG_NjFZ6OvLFV1jSfS9tsz4qUxcWceqwQGk",
      "y":"ADSmRA43Z1DSNx_RvcLI87cdL07l6jQyyBXMoxVg_l2Th-x3S1WDhjDly79ajL4Kkd0AZMaZmh9ubmf63e3kyMj2",
      "alg":"ES512"
    }"""

  # Test vector from https://tools.ietf.org/html/rfc7515#appendix-A.1
  json_hmac_key = r"""
    {
      "kty":"oct",
      "k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow",
      "alg":"HS256"
    }"""

  # Test vector from https://tools.ietf.org/html/rfc7515#appendix-A.1
  hmac_token = 'eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'.encode(
      'utf-8')

  # Key set containing multiple public keys.
  json_pub_keys = r"""{"keys":[""" + json_rsa_pub_key + ',' + es256_ecdsa_pub_key + r"""]}"""

  # The followings are our own tests.

  test_header_rsa = {'typ': 'JWT', 'alg': 'RS256'}

  test_header_es256 = {'typ': 'JWT', 'alg': 'ES256'}

  test_header_es512 = {'typ': 'JWT', 'alg': 'ES512'}

  test_header_hmac = {'typ': 'JWT', 'alg': 'HS256'}

  test_payload = {
      'aud': 'aud1',
      'sub': 'subject1',
      'iss': 'issuer1',
  }

  test_header_es256_kid1 = {'typ': 'JWT', 'alg': 'ES256', 'kid': 'kid1'}

  test_header_es256_kid2 = {'typ': 'JWT', 'alg': 'ES256', 'kid': 'kid2'}

  test_json_ecdsa_priv_key_kid2 = r"""
    {
      "kty":"EC",
      "crv":"P-256",
      "x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
      "y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
      "d":"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI",
      "kid":"kid2",
      "alg":"ES256"
    }"""

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

  test_pem_rsa_2048_priv_key = r"""
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAtqZHGVsFnnmYBrZhVbNcP2ntKOTGn3PYgPLA+G5baWUNsA6E
Oldn6J+t+JY0+ogbhl8GJMr2uDbrIzOvejLja2bFSLlCRSSiGtED9HIJDXiLirDl
9sM2d8TDbXxfuscemY9COpIEmWDFOg2vh2+GQRixOqHb7kdRQppvCLvIYIRBdcrP
uc0LVolba/XsgWx8eCLKd4j+SPGK11CwTUw27uIA95I8BnP7jai7uttq+tjCMvmd
m7cVNfsbzA8jSutPXDlURSAibWHXo6kRntAyhLFxscdG+IsRsZMqmIa4suDdTHhu
KNeQUgGVwQSxu6ePmwz1ifakK6eNfBrS3AynbwIDAQABAoIBAQCvt+SrBiCvx/d0
bb3Sv02+TGA3eXGFMeRWmjUATNtw2CGFAVJA9pom+IhcodWyOYORkJXOi900eNFa
+nyVqaOVTjf6sRCKiKXT+sY9RABlj1VgRrPW5RPfwdLp4EAQ50QPI/3pb1UxYiIc
qdH3EFovAlxvNgzqfn40/3JXCqHKB5EH8QMduZCl3QWD9DTsmypOtNoGYQKM5JTL
roD/KHuZJFSHIxNAQHW5h8n/hmlWHiIOKrfHeM7hDIrVdkf1BWfDSKWiiqm8Eihk
VqF9c494A23xK38npkJMUCrprZT8mmZCkHUDJE1vNLfVC1F81GprceY7Z01Q3KRr
DeL1CVyBAoGBAO6HwVSf90nf/SHR3xWdmHiGL8wU5rkI1ms7la5XEcZZEVo9bB9w
bXqS6OSgxeeIZUHJhB1V7DVQ8tu/dGyCI47Ql9hYJzuQDF43ix4C+lTB7fWmMguf
PlAYxHLXR0e/cDT96hJZzWDWYvBI0b5HWJsvycWMcRwoHaPlhPdZwB/PAoGBAMQG
zfP43vaAKe+/8K+AhZE6DgxhTldJWcQ+Oa9xOV1jyOGabG0DvC03VrSd4wheuoHE
UQpBjRmoGRnNLax7b0q614ntxFH4tWqmKJDawdhrUWhLLVpCUjJ8f1WkpTBZ7pAa
jq9nOLKVNwxl+Mwy9GfaX97aS+3tCXC5LXnbEkZhAoGBAOAu0UKS8h0JmuRdVtj+
/F1SaLvbbRm9N6EjKEPp63fLIGb60ZMe3JZWWvL+M+KvK9PP7Q6RQea+RPLJl0eg
bID+hag8+eqeMTGf7G1xiQt+FQNKh0CrEyq+jGwO7xx8zZ3Qg11p74AzHlwNZKv8
bEe2e2Hi5C/9eBYhUn4TaWG7AoGAKCDceF0yB3QlIZdBRiwhK6Gezpn815GEds/m
LywWei+7J7PdDlP9aaQyc7b+ivAZbgcqL9dLcz0eJlICT5TVK48kIHA0CDPJr5Nk
KoMdu5f8ikUZe6in+v3Rc07JIiTG2WkWXIHc8XHqWvdk/yhPMBNcHNrDQGmNzS2b
SZ63FwECgYAsrVI53LWIIwQYtQ3ZckxRENbXOHy7N8SH/zwpUNu2k+pKtTJWCGmS
5nTKU6sIDB3DXXhQDqQfYUY0YtaTc99zPOtWpke+Vodq6QzjM6L0YNJvDY3SIYjk
ztVxVQZQYyO4L58chnANmOcjUmTJiz/SHCQYFQGuAnJpngZV4sHXzQ==
-----END RSA PRIVATE KEY-----"""

  test_pem_rsa_2048_pub_key = r"""
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtqZHGVsFnnmYBrZhVbNc
P2ntKOTGn3PYgPLA+G5baWUNsA6EOldn6J+t+JY0+ogbhl8GJMr2uDbrIzOvejLj
a2bFSLlCRSSiGtED9HIJDXiLirDl9sM2d8TDbXxfuscemY9COpIEmWDFOg2vh2+G
QRixOqHb7kdRQppvCLvIYIRBdcrPuc0LVolba/XsgWx8eCLKd4j+SPGK11CwTUw2
7uIA95I8BnP7jai7uttq+tjCMvmdm7cVNfsbzA8jSutPXDlURSAibWHXo6kRntAy
hLFxscdG+IsRsZMqmIa4suDdTHhuKNeQUgGVwQSxu6ePmwz1ifakK6eNfBrS3Ayn
bwIDAQAB
-----END PUBLIC KEY-----"""

  test_pem_ec_p256_priv_key = r"""
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIBZJ/P6e1I/nQiBnQxx9aYDPAjwUtbV9Nffuzfubyuw8oAoGCCqGSM49
AwEHoUQDQgAEKSPVJGELbULai+viQc3Zz95+x2NiFvjsDlqmh6rDNeiVuwiwdf5l
lyZ0gbLJ/vheUAwtcA2z0csWU60MfBup3Q==
-----END EC PRIVATE KEY-----"""

  test_pem_ec_p256_pub_key = r"""
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEKSPVJGELbULai+viQc3Zz95+x2Ni
FvjsDlqmh6rDNeiVuwiwdf5llyZ0gbLJ/vheUAwtcA2z0csWU60MfBup3Q==
-----END PUBLIC KEY-----"""

  def test_jws_rsa_verifier_with_rfc(self):
    # Set up phase: parse the key and initialize the verifier.
    keys = jws.CleartextJwkSetReader.from_json(self.json_rsa_pub_key)
    verifier = jws.JwsPublicKeyVerify(keys)

    # Use phase
    try:
      verified_payload = verifier.verify(self.rsa_token)
      self.assertEqual(
          '{"iss":"joe",\r\n "exp":1300819380,\r\n "http://example.com/is_root":true}'
          .encode('utf-8'), verified_payload)
    except SecurityException:
      self.fail('Valid token, should not throw exception')
    for modified_token in _modify_token(self.rsa_token):
      self.assertRaises(SecurityException, verifier.verify, modified_token)

  def test_jws_rsa_signer_and_verifier(self):
    algs = ['RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512']
    for alg in algs:
      json_priv_key = json.loads(self.json_rsa_priv_key)
      json_priv_key['alg'] = alg
      json_priv_key = json.dumps(json_priv_key)
      json_pub_key = json.loads(self.json_rsa_pub_key)
      json_pub_key['alg'] = alg
      json_pub_key = json.dumps(json_pub_key)
      json_header_rsa = dict(self.test_header_rsa)
      json_header_rsa['alg'] = alg

      # Sign
      priv_key = jws.CleartextJwkSetReader.from_json(json_priv_key)
      signer = jws.JwsPublicKeySign(priv_key)
      signed_token = signer.sign(json_header_rsa, self.test_payload)

      # Verify
      pub_key = jws.CleartextJwkSetReader.from_json(json_pub_key)
      verifier = jws.JwsPublicKeyVerify(pub_key)
      try:
        verifier.verify(signed_token)
      except SecurityException:
        self.fail('Valid token, should not throw exception')
      for modified_token in _modify_token(signed_token):
        self.assertRaises(SecurityException, verifier.verify, modified_token)

  def test_jws_ecdsa_verifier_with_rfc_es256(self):
    # Set up phase: parse the key and initialize the verifier.
    key = jws.CleartextJwkSetReader.from_json(self.es256_ecdsa_pub_key)
    verifier = jws.JwsPublicKeyVerify(key)

    # Use phase
    try:
      verified_payload = verifier.verify(self.es256_ecdsa_token)
      self.assertEqual(
          verified_payload.decode('utf-8'),
          '{"iss":"joe",\r\n "exp":1300819380,\r\n "http://example.com/is_root":true}'
      )
    except SecurityException:
      self.fail('Valid token, should not throw exception')
    for modified_token in _modify_token(self.es256_ecdsa_token):
      self.assertRaises(SecurityException, verifier.verify, modified_token)

  def test_jws_ecdsa_verifier_with_rfc_es512(self):
    # Verify
    pub_key = jws.CleartextJwkSetReader.from_json(self.es512_ecdsa_pub_key)
    verifier = jws.JwsPublicKeyVerify(pub_key)

    try:
      verified_payload = verifier.verify(self.es512_ecdsa_token)
      self.assertEqual(b'Payload', verified_payload)
    except SecurityException:
      self.fail('Valid token, should not throw exception')
    for modified_token in _modify_token(self.es512_ecdsa_token):
      self.assertRaises(SecurityException, verifier.verify, modified_token)

  def test_jws_ecdsa_signer_verifier_es512(self):
    # Sign
    priv_key = jws.CleartextJwkSetReader.from_json(self.es512_ecdsa_priv_key)
    signer = jws.JwsPublicKeySign(priv_key)
    signed_token = signer.sign(self.test_header_es512, self.test_payload)

    # Verify
    pub_key = jws.CleartextJwkSetReader.from_json(self.es512_ecdsa_pub_key)
    verifier = jws.JwsPublicKeyVerify(pub_key)
    try:
      verifier.verify(signed_token)
    except SecurityException:
      self.fail('Valid token, should not throw exception')
    for modified_token in _modify_token(signed_token):
      self.assertRaises(SecurityException, verifier.verify, modified_token)

  def test_jws_ecdsa_signer_verifier_es256(self):
    # Sign
    priv_key = jws.CleartextJwkSetReader.from_json(self.es256_ecdsa_priv_key)
    signer = jws.JwsPublicKeySign(priv_key)
    signed_token = signer.sign(self.test_header_es256, self.test_payload)

    # Verify
    pub_key = jws.CleartextJwkSetReader.from_json(self.es256_ecdsa_pub_key)
    verifier = jws.JwsPublicKeyVerify(pub_key)
    try:
      verifier.verify(signed_token)
    except SecurityException:
      self.fail('Valid token, should not throw exception')
    for modified_token in _modify_token(signed_token):
      self.assertRaises(SecurityException, verifier.verify, modified_token)

  def test_jws_verifier_with_multiple_keys(self):
    # Set up phase: parse the keys and initialize the verifier.
    keys = jws.CleartextJwkSetReader.from_json(self.json_pub_keys)
    verifier = jws.JwsPublicKeyVerify(keys)

    # Use phase
    try:
      verifier.verify(self.rsa_token)
      verifier.verify(self.es256_ecdsa_token)
    except SecurityException:
      self.fail('Valid token, should not throw exception')
    for modified_token in _modify_token(self.rsa_token):
      self.assertRaises(SecurityException, verifier.verify, modified_token)
    for modified_token in _modify_token(self.es256_ecdsa_token):
      self.assertRaises(SecurityException, verifier.verify, modified_token)

  def test_jws_verifier_with_kid(self):
    # Sign
    priv_key1 = jws.CleartextJwkSetReader.from_json(
        self.test_json_ecdsa_priv_key_kid1)
    signer1 = jws.JwsPublicKeySign(priv_key1)
    signed_token_kid1 = signer1.sign(self.test_header_es256_kid1,
                                     self.test_payload)
    priv_key2 = jws.CleartextJwkSetReader.from_json(
        self.test_json_ecdsa_priv_key_kid2)
    signer2 = jws.JwsPublicKeySign(priv_key2)
    signed_token_kid2 = signer2.sign(self.test_header_es256_kid2,
                                     self.test_payload)

    # Verify
    pub_key = jws.CleartextJwkSetReader.from_json(
        self.test_json_ecdsa_pub_key_kid1)
    verifier = jws.JwsPublicKeyVerify(pub_key)
    try:
      verifier.verify(signed_token_kid1)
    except SecurityException:
      self.fail('Valid token, should not throw exception')
    for modified_token in _modify_token(signed_token_kid1):
      self.assertRaises(SecurityException, verifier.verify, modified_token)
    # The signature is valid but the kids don't match.
    self.assertRaises(SecurityException, verifier.verify, signed_token_kid2)

  def test_jws_mac_verifier_with_rfc(self):
    # Set up phase: parse the key and initialize the JwsMacVerify
    key = jws.CleartextJwkSetReader.from_json(self.json_hmac_key)
    verifier = jws.JwsMacVerify(key)

    # Use phase
    try:
      verified_payload = verifier.verify(self.hmac_token)
      self.assertEqual(
          '{"iss":"joe",\r\n "exp":1300819380,\r\n "http://example.com/is_root":true}'
          .encode('utf-8'), verified_payload)
    except SecurityException:
      self.fail('Valid token, should not throw exception')
    for modified_token in _modify_token(self.hmac_token):
      self.assertRaises(SecurityException, verifier.verify, modified_token)

  def test_jws_mac_authenticator_and_verifier(self):
    algs = ['HS256', 'HS384', 'HS512']
    for alg in algs:
      json_hmac_key = json.loads(self.json_hmac_key)
      json_hmac_key['alg'] = alg
      json_hmac_key = json.dumps(json_hmac_key)
      json_header_hmac = dict(self.test_header_hmac)
      json_header_hmac['alg'] = alg

      # Authenticator
      mac_key = jws.CleartextJwkSetReader.from_json(json_hmac_key)
      authenticator = jws.JwsMacAuthenticator(mac_key)
      authenticated_token = authenticator.authenticate(json_header_hmac,
                                                       self.test_payload)
      # Verify
      verifier = jws.JwsMacVerify(mac_key)
      try:
        verifier.verify(authenticated_token)
      except SecurityException:
        self.fail('Valid token, should not throw exception')
      for modified_token in _modify_token(authenticated_token):
        self.assertRaises(SecurityException, verifier.verify, modified_token)

  def test_jws_with_mismatch_kid_or_algorithm(self):
    hmac_key = jws.CleartextJwkSetReader.from_json(self.json_hmac_key)
    authenticator = jws.JwsMacAuthenticator(hmac_key)
    json_header_hmac = dict(self.test_header_hmac)
    # Change the algorithm to a wrong one.
    json_header_hmac['alg'] = 'HS512'
    self.assertRaises(SecurityException, authenticator.authenticate,
                      json_header_hmac, self.test_payload)
    priv_key = jws.CleartextJwkSetReader.from_json(
        self.test_json_ecdsa_priv_key_kid1)
    signer = jws.JwsPublicKeySign(priv_key)
    json_header_es256 = dict(self.test_header_es256_kid1)
    # Change the algorithm to a wrong one.
    json_header_es256['alg'] = 'ES512'
    self.assertRaises(SecurityException, signer.sign, json_header_es256,
                      self.test_payload)

    json_header_es256 = dict(self.test_header_es256_kid1)
    # Change kid to a wrong one.
    json_header_es256['kid'] = 'kid0'
    self.assertRaises(SecurityException, signer.sign, json_header_es256,
                      self.test_payload)

  def test_jws_rsa_from_cryptography_key(self):
    # Sign the token
    priv_key = load_pem_private_key(
        self.test_pem_rsa_2048_priv_key.encode('utf-8'),
        None,
        backend=backends.default_backend())
    jwk_priv_key = jws.CleartextJwkSetReader.from_cryptography_key(
        priv_key, 'RS256')
    signer = jws.JwsPublicKeySign(jwk_priv_key)
    signed_token = signer.sign(self.test_header_rsa, self.test_payload)

    # Verify the token
    # The real use case is that cryptography supports extracting public key from
    # certificate, but we simulate it here by reading it from PEM.
    pub_key = load_pem_public_key(
        self.test_pem_rsa_2048_pub_key.encode('utf-8'),
        backend=backends.default_backend())
    jwk_pub_key = jws.CleartextJwkSetReader.from_cryptography_key(
        pub_key, 'RS256')
    verifier = jws.JwsPublicKeyVerify(jwk_pub_key)
    try:
      verifier.verify(signed_token)
    except SecurityException:
      self.fail('Valid token, should not throw exception')
    for modified_token in _modify_token(signed_token):
      self.assertRaises(SecurityException, verifier.verify, modified_token)

  def test_jws_ec_from_cryptography_key(self):
    # Sign the token.
    priv_key = load_pem_private_key(
        self.test_pem_ec_p256_priv_key.encode('utf-8'),
        None,
        backend=backends.default_backend())
    jwk_priv_key = jws.CleartextJwkSetReader.from_cryptography_key(
        priv_key, 'ES256')
    signer = jws.JwsPublicKeySign(jwk_priv_key)
    signed_token = signer.sign(self.test_header_es256, self.test_payload)

    # Verify the token.
    # The real use case is that cryptography supports extracting public key from
    # certificate, but we simulate it here by reading it from PEM.
    pub_key = load_pem_public_key(
        self.test_pem_ec_p256_pub_key.encode('utf-8'),
        backend=backends.default_backend())
    jwk_pub_key = jws.CleartextJwkSetReader.from_cryptography_key(
        pub_key, 'ES256')
    verifier = jws.JwsPublicKeyVerify(jwk_pub_key)
    try:
      verifier.verify(signed_token)
    except SecurityException:
      self.fail('Valid token, should not throw exception')
    for modified_token in _modify_token(signed_token):
      self.assertRaises(SecurityException, verifier.verify, modified_token)

  def test_jws_ec_from_cryptography_key_algorithm_mismatch(self):
    # Sign the token.
    priv_key = load_pem_private_key(
        self.test_pem_ec_p256_priv_key.encode('utf-8'),
        None,
        backend=backends.default_backend())
    self.assertRaises(exceptions.UnsupportedAlgorithm,
                      jws.CleartextJwkSetReader.from_cryptography_key, priv_key,
                      'RS256')

  def test_jws_rsa_from_pem_key(self):
    # Sign the token
    rsa_priv_key = jws.CleartextJwkSetReader.from_pem(
        self.test_pem_rsa_2048_priv_key.encode('utf-8'), 'RS256')
    signer = jws.JwsPublicKeySign(rsa_priv_key)
    signed_token = signer.sign(self.test_header_rsa, self.test_payload)

    # Verify the token
    rsa_pub_key = jws.CleartextJwkSetReader.from_pem(
        self.test_pem_rsa_2048_pub_key.encode('utf-8'), 'RS256')
    verifier = jws.JwsPublicKeyVerify(rsa_pub_key)
    try:
      verifier.verify(signed_token)
    except SecurityException:
      self.fail('Valid token, should not throw exception')
    for modified_token in _modify_token(signed_token):
      self.assertRaises(SecurityException, verifier.verify, modified_token)

  def test_jws_ec_from_pem_key(self):
    # Sign the token
    rsa_priv_key = jws.CleartextJwkSetReader.from_pem(
        self.test_pem_ec_p256_priv_key.encode('utf-8'), 'ES256')
    signer = jws.JwsPublicKeySign(rsa_priv_key)
    signed_token = signer.sign(self.test_header_es256, self.test_payload)

    # Verify the token
    rsa_pub_key = jws.CleartextJwkSetReader.from_pem(
        self.test_pem_ec_p256_pub_key.encode('utf-8'), 'ES256')
    verifier = jws.JwsPublicKeyVerify(rsa_pub_key)
    try:
      verifier.verify(signed_token)
    except SecurityException:
      self.fail('Valid token, should not throw exception')
    for modified_token in _modify_token(signed_token):
      self.assertRaises(SecurityException, verifier.verify, modified_token)

  def test_jwt_public_key_verifier_with_issuer_subject_audiences(self):
    # Sign
    priv_key = jws.CleartextJwkSetReader.from_json(self.json_rsa_priv_key)
    signer = jws.JwtPublicKeySign(priv_key)
    signed_token = signer.sign(self.test_header_rsa, self.test_payload)
    # Verify
    pub_key = jws.CleartextJwkSetReader.from_json(self.json_rsa_pub_key)
    # Ignore issuer, subject and audience.
    verifier = jws.JwtPublicKeyVerify(pub_key)
    try:
      parsed_payload = verifier.verify(signed_token)
      self.assertEqual(parsed_payload['iss'], self.test_payload['iss'])
      self.assertEqual(parsed_payload['aud'], self.test_payload['aud'])
      self.assertEqual(parsed_payload['sub'], self.test_payload['sub'])
    except SecurityException:
      self.fail('Valid token, should not throw exception')
    for modified_token in _modify_token(signed_token):
      self.assertRaises(SecurityException, verifier.verify, modified_token)

    # Correct issuer, subject and audience.
    verifier = jws.JwtPublicKeyVerify(pub_key, 'issuer1', 'subject1',
                                      ['aud1', 'aud2'])
    try:
      verifier.verify(signed_token)
    except SecurityException:
      self.fail('Valid token, should not throw exception')
    # Modify token.
    for modified_token in _modify_token(signed_token):
      self.assertRaises(SecurityException, verifier.verify, modified_token)
    # Incorrect issuer.
    verifier = jws.JwtPublicKeyVerify(pub_key, 'issuer0', 'subject1', ['aud1'])
    self.assertRaises(SecurityException, verifier.verify, signed_token)
    # Incorrect subject.
    verifier = jws.JwtPublicKeyVerify(pub_key, 'issuer1', 'subject0', ['aud1'])
    self.assertRaises(SecurityException, verifier.verify, signed_token)
    # Incorrect audience.
    verifier = jws.JwtPublicKeyVerify(pub_key, 'issuer1', 'subject1', ['aud'])
    self.assertRaises(SecurityException, verifier.verify, signed_token)

  def test_jwt_public_key_verifier_with_exp_nbf(self):
    # Sign
    priv_key = jws.CleartextJwkSetReader.from_json(self.json_rsa_priv_key)
    signer = jws.JwtPublicKeySign(priv_key)
    # Valid exp time.
    payload = dict(self.test_payload)
    payload['exp'] = _get_unix_timestamp() + 100
    signed_token = signer.sign(self.test_header_rsa, payload)
    # Verify
    pub_key = jws.CleartextJwkSetReader.from_json(self.json_rsa_pub_key)
    verifier = jws.JwtPublicKeyVerify(pub_key)
    try:
      self.assertTrue(verifier.verify(signed_token))
    except SecurityException:
      self.fail('Valid token, should not throw exception')
    # Modify token.
    for modified_token in _modify_token(signed_token):
      self.assertRaises(SecurityException, verifier.verify, modified_token)
    # Invalid exp time.
    payload = dict(self.test_payload)
    payload['exp'] = _get_unix_timestamp() - 100
    signed_token = signer.sign(self.test_header_rsa, payload)
    # Verify
    self.assertRaises(SecurityException, verifier.verify, signed_token)
    # Add clock_skew_tolerance
    verifier = jws.JwtPublicKeyVerify(pub_key, None, None, None, 200)
    try:
      verifier.verify(signed_token)
    except SecurityException:
      self.fail('Valid token, should not throw exception')
    verifier = jws.JwtPublicKeyVerify(pub_key)
    # Valid nbf time.
    payload = dict(self.test_payload)
    payload['nbf'] = _get_unix_timestamp() - 100
    signed_token = signer.sign(self.test_header_rsa, payload)
    # Verify
    try:
      verifier.verify(signed_token)
    except SecurityException:
      self.fail('Valid token, should not throw exception')
    # Modify token.
    for modified_token in _modify_token(signed_token):
      self.assertRaises(SecurityException, verifier.verify, modified_token)
    # Invalid nbf time.
    payload = dict(self.test_payload)
    payload['nbf'] = _get_unix_timestamp() + 100
    signed_token = signer.sign(self.test_header_rsa, payload)
    # Verify
    self.assertRaises(SecurityException, verifier.verify, signed_token)
    # Add clock_skew_tolerance
    verifier = jws.JwtPublicKeyVerify(pub_key, None, None, None, 200)
    try:
      verifier.verify(signed_token)
    except SecurityException:
      self.fail('Valid token, should not throw exception')
    # Modify token.
    for modified_token in _modify_token(signed_token):
      self.assertRaises(SecurityException, verifier.verify, modified_token)

  def test_jwt_mac_verifier_with_issuer_subject_audiences(self):
    # Sign
    key = jws.CleartextJwkSetReader.from_json(self.json_hmac_key)
    authenticator = jws.JwtMacAuthenticator(key)
    authenticated_token = authenticator.authenticate(self.test_header_hmac,
                                                     self.test_payload)
    # Verify
    # Ignore issuer, subject and audience.
    verifier = jws.JwtMacVerify(key)
    try:
      parsed_payload = verifier.verify(authenticated_token)
      self.assertEqual(parsed_payload['iss'], self.test_payload['iss'])
      self.assertEqual(parsed_payload['aud'], self.test_payload['aud'])
      self.assertEqual(parsed_payload['sub'], self.test_payload['sub'])
    except SecurityException:
      self.fail('Valid token, should not throw exception')
    # Modify token.
    for modified_token in _modify_token(authenticated_token):
      self.assertRaises(SecurityException, verifier.verify, modified_token)

    # Correct issuer, subject and audience.
    verifier = jws.JwtMacVerify(key, 'issuer1', 'subject1', ['aud1', 'aud2'])
    try:
      verifier.verify(authenticated_token)
    except SecurityException:
      self.fail('Valid token, should not throw exception')
    # Modify token.
    for modified_token in _modify_token(authenticated_token):
      self.assertRaises(SecurityException, verifier.verify, modified_token)
    # Incorrect issuer.
    verifier = jws.JwtMacVerify(key, 'issuer0', 'subject1', ['aud1'])
    self.assertRaises(SecurityException, verifier.verify, authenticated_token)
    # Incorrect subject.
    verifier = jws.JwtMacVerify(key, 'issuer1', 'subject0', ['aud1'])
    self.assertRaises(SecurityException, verifier.verify, authenticated_token)
    # Incorrect audience.
    verifier = jws.JwtMacVerify(key, 'issuer1', 'subject1', ['aud'])
    self.assertRaises(SecurityException, verifier.verify, authenticated_token)

  def test_jwt_mac_verifier_with_exp_nbf(self):
    # Sign
    key = jws.CleartextJwkSetReader.from_json(self.json_hmac_key)
    authenticator = jws.JwtMacAuthenticator(key)
    # Valid exp time.
    payload = dict(self.test_payload)
    payload['exp'] = _get_unix_timestamp() + 100
    authenticated_token = authenticator.authenticate(self.test_header_hmac,
                                                     payload)
    # Verify
    verifier = jws.JwtMacVerify(key)
    try:
      self.assertTrue(verifier.verify(authenticated_token))
    except SecurityException:
      self.fail('Valid token, should not throw exception')
    # Modify token.
    for modified_token in _modify_token(authenticated_token):
      self.assertRaises(SecurityException, verifier.verify, modified_token)
    # Invalid exp time.
    payload = dict(self.test_payload)
    payload['exp'] = _get_unix_timestamp() - 100
    authenticated_token = authenticator.authenticate(self.test_header_hmac,
                                                     payload)
    # Verify
    self.assertRaises(SecurityException, verifier.verify, authenticated_token)
    # Add clock_skew_tolerance
    verifier = jws.JwtMacVerify(key, None, None, None, 200)
    try:
      verifier.verify(authenticated_token)
    except SecurityException:
      self.fail('Valid token, should not throw exception')
    # Modify token.
    for modified_token in _modify_token(authenticated_token):
      self.assertRaises(SecurityException, verifier.verify, modified_token)
    verifier = jws.JwtMacVerify(key)
    # Valid nbf time.
    payload = dict(self.test_payload)
    payload['nbf'] = _get_unix_timestamp() - 100
    authenticated_token = authenticator.authenticate(self.test_header_hmac,
                                                     payload)
    # Verify
    try:
      verifier.verify(authenticated_token)
    except SecurityException:
      self.fail('Valid token, should not throw exception')
    # Modify token.
    for modified_token in _modify_token(authenticated_token):
      self.assertRaises(SecurityException, verifier.verify, modified_token)
    # Invalid nbf time.
    payload = dict(self.test_payload)
    payload['nbf'] = _get_unix_timestamp() + 100
    authenticated_token = authenticator.authenticate(self.test_header_hmac,
                                                     payload)
    # Verify
    self.assertRaises(SecurityException, verifier.verify, authenticated_token)
    # Add clock_skew_tolerance
    verifier = jws.JwtMacVerify(key, None, None, None, 200)
    try:
      verifier.verify(authenticated_token)
    except SecurityException:
      self.fail('Valid token, should not throw exception')
    # Modify token.
    for modified_token in _modify_token(authenticated_token):
      self.assertRaises(SecurityException, verifier.verify, modified_token)


def _get_unix_timestamp():
  return calendar.timegm(datetime.datetime.utcnow().utctimetuple())


def _modify_token(token):
  parts = token.split(b'.')
  assert (len(parts) == 3)
  for i in range(len(parts)):
    modified_parts = parts[:]
    decoded_part = jwsutil.urlsafe_b64decode(modified_parts[i])
    for s in _modify_bytes(decoded_part):
      modified_parts[i] = jwsutil.urlsafe_b64encode(s)
      yield (modified_parts[0] + b'.' + modified_parts[1] + b'.' +
             modified_parts[2])


def _modify_bytes(s):
  # Modify each bit of string.
  for i in range(len(s)):
    c = s[i]
    if not isinstance(c, six.integer_types):
      c = ord(s[i])
    for j in range(8):
      yield (s[:i] + bytes([c ^ (1 << j)]) + s[i:])

  # Truncate string.
  for i in range(len(s)):
    yield s[:i]


if __name__ == '__main__':
  unittest.main()
