/++
    OAuth 2.0 for D - Settings and customizations for provider "google"

    Copyright: © 2016,2017 Harry T. Vennik
    License: Subject to the terms of the MIT license, as written in the included LICENSE file.
    Authors: Harry T. Vennik
  +/
module oauth.provider.google;

import oauth.provider : OAuthProvider;
import oauth.settings : OAuthSettings;

import vibe.core.file;
import vibe.data.json;

import std.exception : enforce;

shared static this()
{
    import std.typecons : BitFlags;
    alias OAuthProvider.Option Option;

    OAuthProvider.register("google", new immutable(OAuthProvider)(
        "https://accounts.google.com/o/oauth2/auth",
        "https://accounts.google.com/o/oauth2/token",
        BitFlags!Option(
            Option.explicitRedirectUri,
            Option.clientAuthParams
        )
    ));
}

/++
    Load settings for Google from a JSON file as exported by the API Manager
 +/
auto loadGoogleAuthSettings(
    string redirectUri = null,
    string clientType = "web",
    string path = "./client_secrets.json")
{
    auto provider = OAuthProvider.forName("google");
    auto clientSecretsJson = path.readFileUTF8.parseJsonString();

    auto settingsJson = clientSecretsJson[clientType];

    if (auto pjAuthUri = "auth_uri" in settingsJson)
        enforce(provider.authUri == pjAuthUri.get!string,
        "Authorization URI doesn't match provider 'google'.");

    if (auto pjTokenUri = "token_uri" in settingsJson)
        enforce(provider.tokenUri == pjTokenUri.get!string,
        "Token URI doesn't match provider 'google'.");

    if (!redirectUri)
        redirectUri = settingsJson["redirect_uris"][0].get!string;

    return new immutable(GoogleAuthSettings)(
        settingsJson["client_id"].get!string,
        settingsJson["client_secret"].get!string,
        settingsJson["project_id"].get!string,
        redirectUri);
}

/++
    Settings for 'google' provider.

    You can just use the OAuthSettings class if you do not need any Google-
    specific settings.
  +/
class GoogleAuthSettings : OAuthSettings
{
    string projectId; ///

    /++
        See OAuthSettings constructor for common documentation.

        The 'provider' field may be omitted. If it is included, it MUST be set
        to "google".

        Additionally, this constructor supports the following JSON key:
        $(TABLE
            $(TR $(TH Key) $(TH Type) $(TH Description))
            $(TR $(TD projectId) $(TD string) $(TD The project id of the
                application as registered with Google. Not to be confused with
                the client id.)))

        Please note that this JSON format is different from the JSON exported
        by Google's API Manager. If you want to use the JSON file downloaded
        from API Manager, call `loadGoogleAuthSettings` instead.
      +/
    this(in Json config) immutable
    {
        enforce("provider" !in config
            || (config["provider"].type == Json.Type.string
            && config["provider"].get!string == "google"),
            "GoogleAuthSettings can only be used with provider 'google'.");

        super("google",
            config["clientId"].get!string,
            config["clientSecret"].get!string,
            config["redirectUri"].get!string);

        if (config["projectId"].type == Json.Type.string)
            this.projectId = config["projectId"].get!string;
    }

    /++
        Construct GoogleAuthSettings providing settings directly.

        Params:
            clientId = The client ID to use in client authentication for
                provider.
            clientSecret = The client secret to use in client authentication
                for provider.
            projectId = The project id of the application as registered with
                Google. Not to be confused with the client id.
            redirectUri = The uri identifying this application, the user agent
                will be redirected to this uri (with some query parameters
                added) after authorization.
      +/
    this(
        string clientId,
        string clientSecret,
        string projectId,
        string redirectUri) immutable nothrow @safe
    {
        super("google", clientId, clientSecret, redirectUri);
        this.projectId = projectId;
    }
}
