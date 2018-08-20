# JSON Web Signature (JWS)

## Introduction

JWT (rfc7519) is widely used. However, the RFC standards JSON Web Encryption
(JWE) (rfc7516), JSON Web Signature (JWS) (rfc7515), JSON Web Token (JWT)
(rfc7519) contain several design mistakes which make both implementations and
use of JWT dangerous. For instance, existing researchs such as
[Critical vulnerabilities in JSON Web Token libraries](https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/),
[Practical Cryptanalysis of Json Web Token](https://rwc.iacr.org/2017/Slides/nguyen.quan.pdf),
[High risk vulnerability in RFC 7515](https://mailarchive.ietf.org/arch/msg/jose/gQU_C_QURVuwmy-Q2qyVwPLQlcg)
showed several vulnerabilities at design and implementation level. Therefore, we
will only implement a safe subset of it.
[JWS Compact Serialization](https://tools.ietf.org/html/rfc7515#section-7.1)
while not ideal, is the safest option and covers the majority of use cases.
We'll harden the API to make it difficult to misuse.

## Scope

*   [JWS Compact Serialization](https://tools.ietf.org/html/rfc7515#section-7.1).
    The library supports all
    [algorithms for digital signature and MACs](https://tools.ietf.org/html/rfc7518#section-3.1),
    in particular:
    *   HMAC.
    *   RSA signature using PKCS1_v1_5 padding.
    *   RSA signature using PSS padding.
    *   ECDSA signature.
*   A subset of [JSON Web Key (JWK)](https://tools.ietf.org/html/rfc7517) where
    we eliminate easy-to-misuse options such as "x5c", "x5u".

## Out of scope

*   We will not support Json Web Encryption (JWE) or JWS JSON Serialization for
    security reasons.
*   Defining a new better standard is out of scope of this library because it
    would break compatibility.
*   After signature verification, we have to check the claims
    https://tools.ietf.org/html/rfc7519#section-4. These claims are use-case
    specific and are not related to cryptography. Users will handle claim
    verification themselves.

## Security principles

### Using cryptography.io

PyCrypto has a lot of vulnerabilities. We’ll use cryptography.io that is built
on top of OpenSSL.

### Do not support “none” option

This option is obviously broken at several layers.

### Separation of key configuration from signature or MAC verification

JWT allows the signature or MAC to contain public key, certificates or urls
pointing to certificates. This is a design mistake because in verification,
signature and MAC are under attacker control which lead to various attacks.
Therefore, in our API, once the key is configured by users, it can not be
affected by attackers through signature or MAC.

### Separation of MAC and digital signature

While MAC and signature are both used to authenticate data, they’re distinct
security primitives. MAC is symmetric key crypto, while digital signature is
public key cryptography. They have different security requirements and key
management assumptions. Furthermore, in key rotation, accidental change from
digital signature to MAC or vice versa changes the security properties of the
system and jeopardizes its security.

### Separation of public key verifier and signer

While it’s tempting to merge them together, for one key, the typical use case is
one side generates the signature and the other side verifies the signature.
Furthermore, the key protection mechanism of signer and verifier is different.
For verifier, we only need to protect the integrity of the key while for signer,
we have to protect both the integrity and confidentiality of the key.

### “kid” (Key ID): signed or unsigned?

“kid” is used as hint indicating which key should be used for verification.
RFC7515 doesn’t specify whether “kid” should be signed or unsigned. For
instance, https://tools.ietf.org/html/rfc7515#appendix-A.6.2 shows an unsigned
“kid”. However, as we only support Json Compact Serialization where the header
is signed, “kid” must be signed. This is consistent with existing use cases that
we're aware of.

### Multiple keys to support key rotation/update

For JwsPublicKeyVerify, JwsMacVerify, we support key configuration that accepts
multiple keys and “kid”. This feature is helpful in key rotation/update when the
receiver doesn’t know in advance which key should be used for verification. The
main difficulty in JWT is that at the time of parsing JWK, key type or kid don’t
fully specify what algorithm will be used during sign/verify or
compute_mac/verify_mac. For instance, let’s look at the key:

There is no way to tell whether the key should be used as encryption key or HMAC
key. Even if we know that it’s used as HMAC key, we still don’t know what hash
function should be used during HMAC verification. One way to mitigate this issue
is to enforce the field “alg” as defined at
https://tools.ietf.org/html/rfc7517#section-4. Key without “alg” field is
rejected. Note that for signer, we only support 1 key. There are 2 reasons:

*   Signer with multiple keys is rare, even in key rotation. The typical use
    case is that the signer switches to new key immediately, while the verifier
    has some grace period to use both the old key and a new key for
    verification. Furthermore, if the user needs to use multiple keys in
    signing, it’s trivial to just create 2 signers; it’s inconvenient but it
    doesn’t harm security.
*   To support multiple keys, we have to specify the primary key and default
    key, otherwise the signer wouldn’t know which key should be used to sign
    data. This makes the design and implementation unnecessary complicated for
    the main use case.

## Installation

To install jws: `git clone https://github.com/google/jws cd jws sudo python
setup.py install`

To test jws: `sudo python setup.py test`

## Usage

```
from jws import jws
from jws.cleartext_jwk_set_reader import CleartextJwkSetReader

es512_ecdsa_token = 'eyJhbGciOiJFUzUxMiJ9.UGF5bG9hZA.AdwMgeerwtHoh-l192l60hp9wAHZFVJbLfD_UxMi70cwnZOYaRI1bKPWROc-mZZqwqT2SI-KGDKB34XO0aw_7XdtAG8GaSwFKdCAPZgoXD2YBJZCPEX3xKpRwcdOO8KpEHwJjyqOgzDO7iKvU8vcnwNrmxYbSW9ERBXukOXolLzeO_Jn'
es512_ecdsa_pub_key = r"""
    {
      "kty":"EC",
      "crv":"P-521",
      "x":"AekpBQ8ST8a8VcfVOTNl353vSrDCLLJXmPk06wTjxrrjcBpXp5EOnYG_NjFZ6OvLFV1jSfS9tsz4qUxcWceqwQGk",
      "y":"ADSmRA43Z1DSNx_RvcLI87cdL07l6jQyyBXMoxVg_l2Th-x3S1WDhjDly79ajL4Kkd0AZMaZmh9ubmf63e3kyMj2",
      "alg":"ES512"
    }"""
# Set up phase: parse the key and initialize the verifier.
key = CleartextJwkSetReader.from_json(es512_ecdsa_pub_key)
verifier = jws.JwsPublicKeyVerify(key)

# Verify phase
verified = verifier.verify(es512_ecdsa_token)
```

> This is not an official Google product.
