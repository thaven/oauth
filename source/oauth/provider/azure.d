/++
    OAuth 2.0 for D - Settings and customizations for Microsoft Azure AD ("azure")

    Copyright: © 2016,2017 Harry T. Vennik
    License: Subject to the terms of the MIT license, as written in the included LICENSE file.
    Authors: Harry T. Vennik
  +/

module oauth.provider.azure;

import oauth.provider : OAuthProvider;
import oauth.settings : OAuthSettings;

import vibe.data.json;
import vibe.http.client;
import vibe.inet.webform;

import std.exception;
import std.format : format;

/++
    Register the OAuthProvider for Microsoft Azure AD

    Params:
        tenantId = A Microsoft Azure tenantId, or the word "common" (default)
            for multi-tenant applications.
        name = The name for the OAuthProvider to be registered. Defaults to
            "azure".
  +/
void registerAzureAuthProvider(
    string tenantId = "common",
    string name = "azure")
{
    OAuthProvider.register(name, new immutable(AzureAuthProvider)(tenantId));
}

/++
    Settings for Microsoft Azure provider.
  +/
class AzureAuthSettings : OAuthSettings
{
    private string _domainHint;

    /++
        See OAuthSettings constructor for common documentation.

        If the 'provider' field is omitted, "azure" will be assumed. If it is
        included, it MUST be set to the name of an AzureAuthProvider.

        History:
            v0.1.x supported an extra JSON key 'domainHint', which corresponds
                to the domain_hint parameter in the authorization redirect.

            v0.2.0 adds support in OAuthSettings.userAuthUri for passing extra
                parameters to the authorization endpoint. This is now the
                preferred way to pass the domain_hint parameter when needed.
                Using the JSON key is deprecated.
      +/
    this(in Json config) immutable
    {
        string providerName;
        if ("provider" !in config)
            providerName = "azure";
        else
        {
            enforce(config["provider"].type == Json.Type.string,
                "AzureAuthSettings requires provider to be specified as a name");
            providerName = config["provider"].get!string;
        }

        enforce(cast(AzureAuthProvider) this.provider,
            format("Provider '%s' is not an AzureAuthProvider.", providerName));

        super(providerName,
            config["clientId"].get!string,
            config["clientSecret"].get!string,
            config["redirectUri"].get!string);

        if (auto pjDomainHint = "domainHint" in config)
            this._domainHint = pjDomainHint.get!string;
    }
}

/++
    Microsoft Azure specialized derivative of OAuthProvider.

    This class should not be used directly. Please register an OAuthProvider
    for Azure using registerAzureAuthProvider().
+/
class AzureAuthProvider : OAuthProvider
{
    private this(string tenantId) immutable
    {
        Options azureOptions;
        azureOptions.explicitRedirectUri = true;
        azureOptions.clientAuthParams = true;

        auto baseUrl = "https://login.microsoftonline.com/" ~ tenantId;
        super(baseUrl ~ "/oauth2/authorize",
            baseUrl ~ "/oauth2/token",
            azureOptions);
    }

    override
    void authUriHandler(
        immutable OAuthSettings settings,
        string[string] params) const
    {
        params["response_mode"] = "query";

        if (auto azureSettings = cast(immutable AzureAuthSettings) settings)
        {
            if ("domain_hint" !in params && azureSettings._domainHint)
                params["domain_hint"] = azureSettings._domainHint;
        }
    }
}
