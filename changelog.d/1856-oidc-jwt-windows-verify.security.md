- **OIDC JWT signature verification is now enforced on Windows (CRITICAL fail-open fixed).**
  On the Windows server build, `OidcProvider::verify_jwt_signature` was a stub that
  returned success **without checking the signature**, so any attacker-forged
  `RS256`/`RS384`/`RS512` ID token with a valid structure was accepted — arbitrary
  OIDC session minting / account takeover. Verification now runs the same OpenSSL
  EVP (JWKS → RSA) path on every platform; a token whose signature cannot be
  verified against a cached JWKS key is rejected. (#1856, #1782)
