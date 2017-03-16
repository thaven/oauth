/++
    OAuth 2.0 for D - Client settings

    Copyright: © 2016,2017 Harry T. Vennik
    License: Subject to the terms of the MIT license, as written in the included LICENSE file.
    Authors: Harry T. Vennik

    Standards: Conforms to RFC 6749
  +/
module oauth.settings;

import vibe.data.json : Json;
import vibe.http.session : Base64URLNoPadding, Session;
import vibe.inet.url : URL;

import oauth.exception : OAuthException;
import oauth.provider : OAuthProvider;
import oauth.session : OAuthSession;

import std.array : join;
import std.datetime : Clock, hours, SysTime;
import std.exception : enforce;
import std.format : format;

immutable(OAuthSettings)[] loadConfig(string path)
{
    import vibe.core.file : readFileUTF8;
    import vibe.data.json : parseJsonString;

    immutable(OAuthSettings)[] cfg;
    auto json = path.readFileUTF8.parseJsonString();

    if (json.type == Json.Type.object)
    {
        cfg ~= new immutable(OAuthSettings)(json);
    }
    else
    {
        foreach (settingsJObj; json)
            cfg ~= new immutable(OAuthSettings)(settingsJObj);
    }

    return cfg;
}

@safe:

/++
    Settings for an OAuth 2.0 client application.

    One client application may hold multiple settings objects when using various
    authentication servers.

    Instances of this class must be immutable.
  +/
class OAuthSettings
{
    OAuthProvider provider; ///
    string clientId;        ///
    string clientSecret;    ///
    string redirectUri;     ///

    package ubyte[] hash;

    /++
        Construct OAuthSettings from JSON object.

        The following keys must be in the JSON object:
        $(TABLE
            $(TR $(TH Key) $(TH Type) $(TH Description))
            $(TR $(TD provider) $(TD string or object) $(TD The registered name
                of the authentication provider to be used or an object with the
                following keys:
                $(TABLE
                    $(TR $(TH Key) $(TH Type) $(TH Description))
                    $(TR $(TD name) $(TD string) $(TD $(I (Optional)) Name for
                        this provider. If a name is given and automatic
                        registration is enabled, the provider can be referenced
                        by just it's name in subsequent calls.))
                    $(TR $(TD authUri) $(TD string) $(TD Authentication uri))
                    $(TR $(TD tokenUri) $(TD string) $(TD Token uri))
                )))
            $(TR $(TD clientId) $(TD string) $(TD The client ID to use in client
                authentication for the given provider.))
            $(TR $(TD clientSecret) $(TD string) $(TD The client secret to use
                in client authentication for the given provider.))
            $(TR $(TD redirectUri) $(TD string) $(TD The uri identifying this
                application, the user agent will be redirected to this uri
                (with some query parameters added) after authorization.)))
      +/
    this(in Json config) immutable
    {
        auto sp = (config["provider"].type == Json.Type.string)
            ? OAuthProvider.forName(config["provider"].get!string)
            : new immutable(OAuthProvider)(config["provider"]);

        this(sp,
            config["clientId"].get!string,
            config["clientSecret"].get!string,
            config["redirectUri"].get!string);
    }

    /++
        Construct OAuthSettings providing settings directly.

        Params:
            provider = The registered name of the authentication _provider.
            clientId = The client ID to use in client authentication for
                provider.
            clientSecret = The client secret to use in client authentication
                for provider.
            redirectUri = The uri identifying this application, the user agent
                will be redirected to this uri (with some query parameters
                added) after authorization.
      +/
    this(
        string provider,
        string clientId,
        string clientSecret,
        string redirectUri) immutable nothrow @safe
    {
        this(OAuthProvider.forName(provider),
            clientId, clientSecret, redirectUri);
    }

    private this(
        immutable OAuthProvider provider,
        string clientId,
        string clientSecret,
        string redirectUri) immutable nothrow @safe
    {
        this.provider = provider;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.redirectUri = redirectUri;

        import std.digest.sha : sha256Of;
        assert(this.provider !is null, "Invalid provider selected");
        this.hash = sha256Of(provider.tokenUri ~ ' ' ~ clientId).idup;
    }

    /++
        User login helper method.

        Use this method to obtain a URI which can be used to redirect
        the user agent to the login page of the service we want to get
        access to on behalf of a user.

        This URI will contain a dynamically generated state parameter,
        which should be returned by the service as a query string
        parameter when the user agent is redirected back to this client.
        The user session can be started by passing this parameter
        to the `userSession` method, along with the authorization
        code.

        Params:
            httpSession = The current HTTP session.
            extraParams = Extra parameters to include in the authentication
                uri. Use this to pass provider specific parameters that cannot
                be included in the settings because they won't be the same for
                every authorization request.
            scopes = An array of identifiers specifying the scope of
                access to be requested. (optional)

        Returns: The URI the user agent should be redirected to for
        login and authorization.
      +/
    final
    string userAuthUri(
        scope Session httpSession,
        in string[string] extraParams = null,
        in string[] scopes = null) immutable
    {
        import std.array : Appender;
        import std.random : uniform;
        import std.digest.digest : toHexString;
        import vibe.inet.webform : formEncode;

        string[string] reqParams;

        foreach (k, v; extraParams)
            reqParams[k] = v;

        // the oAuth server returns a code with which a token can be requested
        reqParams["response_type"] = "code";
        reqParams["client_id"] = clientId;

        string scopesJoined = join(scopes, ' ');
        if (scopesJoined)
            reqParams["scope"] = scopesJoined;

        provider.authUriHandler(this, reqParams);

        auto t = Clock.currTime;
        auto rnd = uniform!ulong;
        auto ld = LoginData(t, rnd, scopesJoined,
            cast(bool) ("redirect_uri" in reqParams));

        reqParams["state"] = Base64URLNoPadding.encode(ld.key);
        httpSession.set("oauth.authorization", ld);
        httpSession.set("oauth.client", toHexString(this.hash));

        // generate redirect URI
        URL uri = provider.authUriParsed;
        Appender!string app;
        if (uri.queryString.length)
        {
            app.put(uri.queryString);
            app.put('&');
        }
        app.formEncode(reqParams);
        uri.queryString = app.data;

        return uri.toString;
    }

    // For compatibility with 0.1.0
    /// ditto
    final
    string userAuthUri(
        scope Session httpSession,
        string[] scopes = null) immutable
    {
        return this.userAuthUri(httpSession, null, scopes);
    }

    /++
        User login helper method, complementary to `userAuthUri`.

        Use this method to start a session with user impersonation. The
        authorizationCode MUST be obtained by redirection of the user
        agent to an URI obtained through `userAuthUri`, otherwise
        there would not be a valid state.

        Params:
            httpSession = The current HTTP session.
            state = OAuth state obtained from the '_state' query string parameter
                of the request URL.
            authorizationCode = the authorization code obtained from the
                service. It will be in the 'code' parameter in the query
                string of the request being processed.

        Returns: The new session.

        Throws: OAuthException if any of the latter two arguments is
        invalid or authentication fails otherwise.
      +/
    final
    OAuthSession userSession(
        scope Session httpSession,
        string state,
        string authorizationCode) immutable
    in
    {
        assert (httpSession && state && authorizationCode);
    }
    out(result)
    {
        assert(result !is null);
    }
    body
    {
        enforce(httpSession.isKeySet("oauth.authorization"),
            "No call to userAuthUri was made using this HTTP session.");

        auto key = Base64URLNoPadding.decode(state);
        auto ld = httpSession.get!LoginData("oauth.authorization");

        enforce!OAuthException(key == ld.key, "Invalid state parameter.");

        scope(exit) httpSession.remove("oauth.authorization");

        enforce(ld.timestamp >= Clock.currTime - 1.hours,
            "Authorization challenge timeout.");

        string[string] params;
        params["grant_type"] = "authorization_code";
        params["code"] = authorizationCode;

        if (ld.redirectUriRequired)
            params["redirect_uri"] = redirectUri;

        if (ld.scopes)
            params["scope"] = ld.scopes;

        auto session = new OAuthSession(this, params);
        session.save(httpSession);
        return session;
    }

    /++
        Start a session on behalf of the resource owner, using _username and
        _password for authentication.

        This authentication flow SHOULD be used only as a last resort, as it
        requires exposal of the plain _username and _password to the client.

        Params:
            username = The resource owner's _username.
            password = The resource owner's _password.
            scopes = An array of strings representing the scope of the
                authorization request. (may be `null`)

        Throws: OAuthException if user authentication fails or the client could
            not be granted access on behalf of the resource owner for any scope
            requested.
      +/
    final
    OAuthSession userSession(
        string username,
        string password,
        string[] scopes) immutable
    in
    {
        assert(username);
        assert(password);
    }
    out(result)
    {
        assert(result !is null);
    }
    body
    {
        string[string] params;
        params["grant_type"] = "password";
        params["username"] = username;
        params["password"] = password;

        if (scopes)
            params["scope"] = join(scopes, ' ');

        return new OAuthSession(this, params);
    }

    /++
        Obtain a new session using client credentials.

        Params:
            scopes = An array of identifiers specifying the scope of
                access to be requested. (optional)

        Returns: The new session.

        Throws: OAuthException if authentication fails.
      +/
    final
    OAuthSession clientSession(string[] scopes = null) immutable
    out(result)
    {
        assert(result !is null);
    }
    body
    {
        string[string] params;
        params["grant_type"] = "client_credentials";

        if (scopes)
            params["scope"] = join(scopes, ' ');

        return new OAuthSession(this, params);
    }

    deprecated("Please use OAuthSession.load() instead.")
    OAuthSession loadSession(scope Session httpSession) immutable
    {
        return OAuthSession.load(this, httpSession);
    }

    private:

    struct LoginData
    {
        SysTime timestamp;
        ulong   randomId;
        string  scopes;
        bool    redirectUriRequired;

        auto key() @property const nothrow @safe
        {
            import std.digest.crc : crc32Of;
            import std.digest.sha : sha256Of;

            ubyte[20] data;
            ulong[] data64 = cast(ulong[])(data[0 .. 16]);
            data64[0] = this.timestamp.toUnixTime;
            data64[1] = this.randomId;
            data[16 .. 20] = crc32Of(this.scopes);
            return sha256Of(data[]);
        }
    }
}

