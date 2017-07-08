/++
    OAuth 2.0 for D - Settings and customizations for provider "facebook"

    Copyright: © 2016,2017 Harry T. Vennik
    License: Subject to the terms of the MIT license, as written in the included LICENSE file.
    Authors: Harry T. Vennik
  +/
module oauth.provider.facebook;

import oauth.provider : OAuthProvider;
import oauth.settings : OAuthSettings;

import vibe.data.json;
import vibe.http.client;
import vibe.inet.webform;

import std.exception;

/++
    Settings for 'facebook' provider.

    OAuthSettings specialized for Facebook. Just for convenience.
  +/
class FacebookAuthSettings : OAuthSettings
{
    private bool _rerequest;

    /++
        See OAuthSettings constructor for common documentation.

        The 'provider' field may be omitted. If it is included, it MUST be set
        to "facebook".

        History:
            v0.1.x supported an extra JSON key 'authType', which corresponds
                to the auth_type parameter in the authorization redirect.

            v0.2.0 adds support in OAuthSettings.userAuthUri for passing extra
                parameters to the authorization endpoint. This is now the
                preferred way to pass the auth_type parameter when needed.
                Using the JSON key is deprecated.
      +/
    this(in Json config) immutable
    {
        enforce("provider" !in config
            || (config["provider"].type == Json.Type.string
            && config["provider"].get!string == "facebook"),
            "FacebookAuthSettings can only be used with provider 'facebook'.");

        super("facebook",
            config["clientId"].get!string,
            config["clientSecret"].get!string,
            config["redirectUri"].get!string);

        if (config["authType"].type == Json.Type.string
            && config["authType"].get!string == "rerequest")
            _rerequest = true;
    }
}

/++
    Facebook specialized derivative of OAuthProvider.

    This class should not be used directly. It registers itself as an
    OAuthProvider with name `facebook`.
+/
class FacebookAuthProvider : OAuthProvider
{
    shared static this()
    {
        OAuthProvider.register("facebook", new immutable(FacebookAuthProvider));
    }

    private this() immutable
    {
        import std.typecons : BitFlags;
        super(
            "https://www.facebook.com/dialog/oauth",
            "https://graph.facebook.com/v2.3/oauth/access_token",
            BitFlags!Option (
                Option.explicitRedirectUri |
                Option.tokenRequestHttpGet |
                Option.clientAuthParams
            )
        );
    }

    override
    void authUriHandler(
        immutable OAuthSettings settings,
        string[string] params) const
    {
        if (auto fbSettings = cast(immutable FacebookAuthSettings) settings)
            if ("auth_type" !in params && fbSettings._rerequest)
                params["auth_type"] = "rerequest";
    }
}

unittest
{
    auto facebook = OAuthProvider.forName("facebook");
    assert (facebook, "Name 'facebook' not registered!");
    assert (cast(FacebookAuthProvider) facebook,
        "Some unkown OAuthProvider has been registered as 'facebook'.");
}
