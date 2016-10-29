/++
    Settings and customizations for Microsoft Azure AD ("azure")

    Copyright: © 2016 Harry T. Vennik
    License: Subject to the terms of the MIT license, as written in the included LICENSE file.
    Authors: Harry T. Vennik
  +/

module oauth.provider.azure;

import oauth.client;

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
    string domainHint;

    /++
        See OAuthSettings constructor for common documentation.

        If the 'provider' field is omitted, "azure" will be assumed. If it is
        included, it MUST be set to the name of an AzureAuthProvider.

        Additionally, this constructor supports the following JSON key:
        $(TABLE
            $(TR $(TH Key) $(TH Type) $(TH Description))
            $(TR $(TD domainHint) $(TD string) $(TD Provides a hint about the
                tenant or domain that the user should use to sign in. The value
                of the domainHint is a registered domain for the tenant. If the
                tenant is federated to an on-premises directory, Azure AD
                redirects to the specified tenant federation server.)))
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
            this.domainHint = pjDomainHint.get!string;
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
        auto baseUrl = "https://login.microsoftonline.com/" ~ tenantId;
        super(baseUrl ~ "/oauth2/authorize", baseUrl ~ "/oauth2/token");
    }

    override
    void authUriHandler(
        immutable OAuthSettings settings,
        string[string] params) const
    {
        params["redirect_uri"] = settings.redirectUri;
        params["response_mode"] = "query";

        if (auto azureSettings = cast(immutable AzureAuthSettings) settings)
        {
            if ("domain_hint" !in params && azureSettings.domainHint)
                params["domain_hint"] = azureSettings.domainHint;
        }
    }

    override
    void tokenRequestor(
        in OAuthSettings settings,
        string[string] params,
        scope HTTPClientRequest req) const
    {
        params["client_id"] = settings.clientId;
        params["client_secret"] = settings.clientSecret;
        req.requestURL = req.requestURL ~ '?' ~ formEncode(params);
    }
}
