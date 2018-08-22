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

__author__ = 'quannguyen@google.com (Quan Nguyen)'

import json

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
rsa_token = 'eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw'

# Test vector from https://tools.ietf.org/html/rfc7515#appendix-A.3
es256_ecdsa_token = 'eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q'

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
es512_ecdsa_token = 'eyJhbGciOiJFUzUxMiJ9.UGF5bG9hZA.AdwMgeerwtHoh-l192l60hp9wAHZFVJbLfD_UxMi70cwnZOYaRI1bKPWROc-mZZqwqT2SI-KGDKB34XO0aw_7XdtAG8GaSwFKdCAPZgoXD2YBJZCPEX3xKpRwcdOO8KpEHwJjyqOgzDO7iKvU8vcnwNrmxYbSW9ERBXukOXolLzeO_Jn'

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
hmac_token = 'eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'

# Key set containing multiple public keys.
json_pub_keys = r"""{"keys":[""" + json_rsa_pub_key + ',' + es256_ecdsa_pub_key + r"""]}"""

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

test_payload = json.dumps(
    {
        'aud': 'aud1',
        'sub': 'subject1',
        'iss': 'issuer1',
    },
    separators=(',', ':'))

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
