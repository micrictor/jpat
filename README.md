## JSON Packet Authentication Tokens

JSON Packet Authentication Tokens, or JPATs, are an application of JSON Web Tokens (JWTs) to the issue of Single Packet Authorization.

### What is Single Packet Authorization?

Single packet authorization (SPA) is the process of permitting a remote actor to connect to internal network services with zero round trips required.

[Port knocking](https://wiki.archlinux.org/title/Port_knocking) is an early implementation of this, where remote parties that know the expected sequence of ports to "knock on" will then be permitted to connect to the configured service.

This approach has weak authentication and authorization, as the sequence of ports can be observed in plaintext by actors on the network, and the authenticating service has no way of validating identity or expiring tokens.

[fwknop](https://github.com/mrash/fwknop) builds upon the idea of port knocking, using HMAC-authenticated RSA, or any GnuPG algorithim, encryption as a means of asserting the identity of the user seeking to be authenticated.

### Why is this different?

[JWTs](https://jwt.io/introduction) are a widely accepted means of authenticating users. These tokens are centrally issued, can contain custom metadata about who the token was issued to, and can be validated using a combination of a shared passphrase or asymmetric cipher and hash-based message authentication codes (HMACs). For example, a central authority can issue a token for a user with the following claims:
```
{
  "sub": "1234567890",
  "iss": "https://identityprovider.contoso.com/jwks"
  "userName": "Michael Torres",
  "userGroups": ["admin", "security", "developer"],
  "iat": 1516239022,
  "nbf": 1516239022,
  "exp": 1640847207
}
```

Then, any network service can check the vailidity of the token by:
* Ensuring that the "Not before" (nbf) claim time has passed
* Ensuring that the "Expiration" (exp) claim time has not been met
* Checking the JWT signature using a shared secret OR an asymmetric algorithm and an HMAC (typically SHA256)

Once verified, the network server can use the information in the JWT claims to permit network traffic to the "true" service on a temporary basis.

### How does it work?

#### Ideal view

Inside of the hit startup "Doordash for Pets," there is an internal TLS-enabled HTTP API for updating listings. The owner of this service wants to restrict connections to the HTTPS server to only authenticated and authorized internal users in order to reduce the attack surface of the application from the perspective of unauthorized actors.

The central identity provider inside of Doordash for Pets is capable of issuing JWTs with the following claims:
* sub - Unique principal identifier; `employee:micrictor` or `machine:${uuid}`
* iss - Issuer, endpoint link to JWKS endpoint on identity provider
* nbf - Earliest time the token is valid
* exp - Latest time the token is valid
* roles - JSON list of roles the principal has


Before any network request to the internal API is issued, or possibly immediately afterwards as coordinated by filter drivers or eBPFs, the client sends their JWT to the internal API's JPAT server.

The JPAT server then validates the token and evaluates the claims to determine if the principal should be permitted to connect. For examaple, the JPAT server could only permit network connection if:
* The `sub` of the token is an `employee`
* `roles` contains the `commerce-listings-admin` role
* `roles` does NOT contain the `doge` role - Doges can't be trusted to not change listings to get themselves more treats

If all conditions match, the JPAT server will add a temporary firewall rule to permit the network traffic from the client to the HTTP API. This rule will timeout either after a preconfigured time-to-live, or the expiration of the toke, whichever is sooner.
