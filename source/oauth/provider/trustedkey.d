/++
    OAuth 2.0 for D - Settings for Trusted Key

    Copyright: © 2016,2017 Harry T. Vennik
    License: Subject to the terms of the MIT license, as written in the included LICENSE file.
    Authors: Lionello Lunesu
  +/

module oauth.provider.trustedkey;

import oauth.provider : OAuthProvider;

shared static this()
{
    OAuthProvider.register("trustedkey", new immutable(OAuthProvider)(
        "https://wallet.trustedkey.com/oauth/authorize",
        "https://wallet.trustedkey.com/oauth/token",
        OAuthProvider.Options.explicitRedirectUri
    ));
}
