# OAuth [![Dub](https://img.shields.io/dub/v/oauth.svg)](https://code.dlang.org/packages/oauth)
The `oauth` package provides an implementation of the [OAuth 2.0 Authorization
framework][RFC6749].

# [API docs](http://thaven.github.io/oauth)

This package is stabilizing, but not quite 1.0 yet. Subsequent versions may not
be fully compatible.

In 0.2.0 the `oauth.client` module has been split out into multiple modules and
a few methods moved to another class (e.g. `OAuthSession.load` instead of
`OAuthSettings.loadSession`). The old names are deprecated.

# API Overview

You'll need at least one `OAuthProvider`. Support for various authorization
providers is included, and it's easy to add your own. You generally don't
reference `OAuthProvider` instances directly, except when registering a custom
provider.

An `OAuthSettings` instance contains application-specific settings, such as the
client id, for use with a particular provider. Also it provides methods to
obtain authorization using these settings. If authorization is successful, an
`OAuthSession` instance is returned. For three-legged OAuth, use the
`userAuthUri` method to obtain the URL where the user agent is to be redirected
to. When the authorization code is received, through redirection back to the
application, call `userSession` to obtain the `OAuthSession`.

For convenience, there is also `OAuthWebapp` which provides a reference
implementation for three-legged OAuth. Since oauth 0.2.0 this is compatible with
the `vibe.web.auth` module.

An `OAuthSession` holds an access token and optionally a refresh token. Use its
`authorizeRequest` method to apply the access token to an
[HTTPClientRequest](http://vibed.org/api/vibe.http.client/HTTPClientRequest).
If the access token  has expired, it will automatically be refreshed, if a
refresh token is available.

# Authorization providers
Support for the following authorization providers is built in:
- Azure AD / Office365
- Facebook
- GitHub
- Google
- Trusted Key

[RFC6749]: https://tools.ietf.org/html/rfc6749
