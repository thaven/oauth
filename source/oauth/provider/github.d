/++
    OAuth 2.0 for D - Settings for GitHub

    Copyright: © 2016,2017 Harry T. Vennik
    License: Subject to the terms of the MIT license, as written in the included LICENSE file.
    Authors: Sebastian Wilzbach
  +/

module oauth.provider.github;

import oauth.client : OAuthProvider;

shared static this()
{
    OAuthProvider.register("github", new immutable(OAuthProvider)(
        "https://github.com/login/oauth/authorize",
        "https://github.com/login/oauth/access_token"
    ));
}
