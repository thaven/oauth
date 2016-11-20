# OAuth
The `oauth` package provides an implementation of the [OAuth 2.0 Authorization
framework][RFC6749].

This package is in early development phase. Subsequent versions may not be fully
compatible. Especially between versions 0.0.1 and 0.1.0 the API changed a lot.

# API Overview

Full documentation is in the source, here is just an overview of the 0.1.0+ API.

You'll need at least one `OAuthProvider`. Support for Facebook, Google and Azure
is included, though the latter two are to be considered beta. You generally
don't reference instances of this class directly, except when registering a
custom provider.

An `OAuthSettings` instance contains application-specific settings, such as the
client id, for use with a particular provider. Also it provides methods to
obtain authorization using these settings. If authorization is successful, an
`OAuthSession` instance is returned. For three-legged OAuth, use the
`userAuthUri` method to obtain the URL where the user agent is to be redirected
to. When the authorization code is received, through redirection back to the
application, call `userSession` to obtain the `OAuthSession`.

An `OAuthSession` holds an access token and optionally a refresh token. Use its
`authorizeRequest` method to apply the access token to an
[HTTPClientRequest](http://vibed.org/api/vibe.http.client/HTTPClientRequest).
If the access token  has expired, it will automatically be refreshed, if a
refresh token is available.

[RFC6749]: https://tools.ietf.org/html/rfc6749
