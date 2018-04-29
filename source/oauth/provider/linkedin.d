module oauth.provider.linkedin;

import oauth.provider : OAuthProvider;
import oauth.settings : OAuthSettings;

import vibe.data.json;
import vibe.http.client;
import vibe.inet.webform;

import std.exception;

/++
    Settings for 'linkedin' provider.

    OAuthSettings specialized for Linkedin. Just for convenience.
  +/
class LinkedInAuthSettings : OAuthSettings
{
    private bool _rerequest;

    /++
        See OAuthSettings constructor for common documentation.

        The 'provider' field may be omitted. If it is included, it MUST be set
        to "linkedin".
      +/
    this(in Json config) immutable
    {
        enforce("provider" !in config || (config["provider"].type == Json.Type.string
                && config["provider"].get!string == "linkedin"),
                "LinkedInAuthSettings can only be used with provider 'linkedin'.");

        super("linkedin", config["clientId"].get!string,
                config["clientSecret"].get!string, config["redirectUri"].get!string);

        if (config["authType"].type == Json.Type.string
                && config["authType"].get!string == "rerequest")
            _rerequest = true;
    }
}

/++
    LinkedIn specialized derivative of OAuthProvider.

    This class should not be used directly. It registers itself as an
    OAuthProvider with name `linkedin`.
+/
class LinkedInAuthProvider : OAuthProvider
{
    shared static this()
    {
        OAuthProvider.register("linkedin", new immutable(LinkedInAuthProvider));
    }

    private this() immutable
    {
        import std.typecons : BitFlags;

        super("https://www.linkedin.com/oauth/v2/authorization", "https://www.linkedin.com/oauth/v2/accessToken",
                BitFlags!Option(Option.explicitRedirectUri,
                    Option.tokenRequestHttpGet, Option.clientAuthParams));
    }

    override void authUriHandler(immutable OAuthSettings settings, string[string] params) const
    {
        if (auto liSettings = cast(immutable LinkedInAuthSettings) settings)
            if ("auth_type" !in params && liSettings._rerequest)
                params["auth_type"] = "rerequest";
    }
}

unittest
{
    auto linkedin = OAuthProvider.forName("linkedin");
    assert(linkedin, "Name 'linkedin' not registered!");
    assert(cast(LinkedInAuthProvider) linkedin,
            "Some unkown OAuthProvider has been registered as 'linkedin'.");
}
