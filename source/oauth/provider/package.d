/++
    OAuth 2.0 for D - Registration of providers and default provider implementation

    Copyright: © 2016,2017 Harry T. Vennik
    License: Subject to the terms of the MIT license, as written in the included LICENSE file.
    Authors: Harry T. Vennik

    Standards: Conforms to RFC 6749
  +/
module oauth.provider;

import vibe.data.json : Json;
import vibe.inet.url;
import vibe.http.client : HTTPClientRequest;

import oauth.session : OAuthSession;
import oauth.settings : OAuthSettings;

/++
    Represents an OAuth 2.0 authentication server.
  +/
class OAuthProvider
{
    private
    {
        import std.typecons : Rebindable;

        /* Exclusively accessed by forName() and register(), synchronized. */
        __gshared Rebindable!(immutable OAuthProvider)[string] _servers;

        /* Set once and never changed, synchronization not necessary. */
        __gshared bool allowAutoRegister = true;

        URL _authUriParsed;
    }

    /++
        Disables automatic registration of authentication servers from JSON
        config.

        This will only prevent the application from changing the provider
        registry implicitly. Explicit registration of providers remains
        possible.

        Should be called only once and before using any OAuth functions.
      +/
    static disableAutoRegister() nothrow
    {
        import core.atomic : cas;

        static shared bool calledBefore;

        if(cas(&calledBefore, false, true))
            allowAutoRegister = false;
    }

    /++
        Get provider by name

        Params:
            name = The name of the provider
      +/
    static forName(string name) nothrow @trusted
    {
        // TODO: investigate why 'synchronized' is not nothrow
        //  Hacked around it for now.
        try synchronized(OAuthProvider.classinfo)
            if (auto p_srv = name in _servers)
                return p_srv.get;
        catch (Exception)
            assert (false);

        return null;
    }

    /++
        Register a provider

        Params:
            name = The name of the provider
            srv = The provider to register
      +/
    static register(string name, immutable OAuthProvider srv) nothrow @trusted
    {
        // TODO: investigate why 'synchronized' is not nothrow
        //  Hacked around it for now.
        try synchronized(OAuthProvider.classinfo)
            _servers[name] = srv;
        catch (Exception)
            assert (false);
    }

    string authUri;     ///
    string tokenUri;    ///

    /++
        Constructor

        Params:
            authUri = Authorization URI for this provider.
            tokenUri = Token URI for this provider.
      +/
    this(string authUri, string tokenUri) immutable @safe
    {
        this.authUri = authUri;
        this.tokenUri = tokenUri;

        this._authUriParsed = URL(authUri);
    }

    // TODO: was protected
    void authUriHandler(
        immutable OAuthSettings,
        string[string]) const @safe
    {
    }

    void tokenRequestor(
        in OAuthSettings settings,
        string[string] params,
        scope HTTPClientRequest req) const
    {
        import vibe.http.common : HTTPMethod;
        import vibe.inet.webform : formEncode;
        import vibe.http.auth.basic_auth : addBasicAuth;

        req.method = HTTPMethod.POST;
        addBasicAuth(req, settings.clientId, settings.clientSecret);
        req.contentType = "application/x-www-form-urlencoded";
        req.bodyWriter.write(formEncode(params));
    }

    package(oauth):

    URL authUriParsed() @property pure const nothrow @safe
    {
        return _authUriParsed;
    }

    this(in Json json) immutable @trusted
    {
        this(json["authUri"].get!string,
            json["tokenUri"].get!string);

        if (OAuthProvider.allowAutoRegister && "name" in json)
            OAuthProvider.register(json["name"].get!string, this);
    }
}

