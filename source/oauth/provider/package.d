/++
    OAuth 2.0 for D - Registration of providers and default provider implementation

    Copyright: © 2016,2017 Harry T. Vennik
    License: Subject to the terms of the MIT license, as written in the included LICENSE file.
    Authors: Harry T. Vennik

    Standards: Conforms to RFC 6749
  +/
module oauth.provider;

import oauth.session : OAuthSession;
import oauth.settings : OAuthSettings;

import vibe.data.json : Json;
import vibe.inet.url;

/++
    Represents an OAuth 2.0 authentication server.
  +/
class OAuthProvider
{
    private
    {
        import std.typecons : Rebindable, BitFlags;

        /* Exclusively accessed by forName() and register(), synchronized. */
        __gshared Rebindable!(immutable OAuthProvider)[string] _servers;

        /* Set once and never changed, synchronization not necessary. */
        __gshared bool allowAutoRegister = true;

        URL _authUriParsed;
        BitFlags!Option _options;
    }

    /++
        Option flags for an OAuth provider.
      +/
    enum Option
    {
        none                = 0,
        explicitRedirectUri = 0x01, /// redirect_uri parameter is required in
                                    ///     authorization redirect.
        tokenRequestHttpGet = 0x02, /// use the GET http method when requesting
                                    ///     an access token.
        clientAuthParams    = 0x04  /// pass client credentials as parameters
                                    ///     rather than using http Basic
                                    ///     authentication.
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
            options = Many OAuth 2.0 servers do not follow the standard exactly.
                Use the options to specify what non-standard behavior is to be
                expected from this provider. Default: none
      +/
    this(
        string authUri,
        string tokenUri,
        BitFlags!Option options = BitFlags!Option.init) immutable @safe
    {
        this.authUri = authUri;
        this.tokenUri = tokenUri;
        this._options = options;

        this._authUriParsed = URL(authUri);
    }

    // TODO: was protected
    void authUriHandler(
        immutable OAuthSettings,
        string[string]) const @safe
    {
    }

    package(oauth):

    URL authUriParsed() @property pure const nothrow @safe
    {
        return _authUriParsed;
    }

    BitFlags!Option options() @property pure const nothrow @safe
    {
        return _options;
    }

    this(in Json json) immutable @trusted
    {
        BitFlags!Option opt;

        if (auto pJOpt = "options" in json)
        {
            foreach (v; *pJOpt)
            {
                switch (v.get!string)
                {
                    case "explicitRedirectUri":
                        opt |= Option.explicitRedirectUri;
                        break;

                    case "tokenRequestHttpGet":
                        opt |= Option.tokenRequestHttpGet;
                        break;

                    case "clientAuthParams":
                        opt |= Option.clientAuthParams;
                        break;

                    default:
                        import std.format : format;
                        throw new Exception(format(
                            "Invalid provider option %s", v.get!string));
                }
            }
        }

        this(json["authUri"].get!string,
            json["tokenUri"].get!string, opt);

        if (OAuthProvider.allowAutoRegister && "name" in json)
            OAuthProvider.register(json["name"].get!string, this);
    }
}

