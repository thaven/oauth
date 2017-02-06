/++
    OAuth 2.0 _client module

    Copyright: © 2016 Harry T. Vennik
    License: Subject to the terms of the MIT license, as written in the included LICENSE file.
    Authors: Harry T. Vennik

    Standards: Conforms to RFC 6749
  +/
module oauth.client;

import vibe.data.json;
import vibe.http.auth.basic_auth;
import vibe.http.client;
import vibe.http.session;
import vibe.inet.url;
import vibe.inet.webform;

import core.atomic;
import std.algorithm.searching;
import std.datetime;
import std.exception;
import std.format;
import std.string : split, join;
import std.uni : toLower;

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
        this.hash = sha256Of(provider.tokenUri ~ ' ' ~ clientId);
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

        string[string] reqParams;
        string scopesJoined = join(scopes, ' ');

        foreach (k, v; extraParams)
            reqParams[k] = v;

        reqParams["response_type"] = "code";
        reqParams["client_id"] = clientId;

        if (scopesJoined)
            reqParams["scope"] = scopesJoined;

        auto t = Clock.currTime;
        auto rnd = uniform!ulong;

        provider.authUriHandler(this, reqParams);

        auto key = loginKey(t, rnd, scopesJoined);
        reqParams["state"] = Base64URLNoPadding.encode(key);

        httpSession.set("oauth.authorization", LoginData(t, rnd, scopesJoined,
            cast(bool) ("redirect_uri" in reqParams)));
        httpSession.set("oauth.client", toHexString(this.hash));

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

        enforce(key == loginKey(ld.timestamp, ld.randomId, ld.scopes),
            "Invalid state parameter.");

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

        auto session = provider._sessionFactory(this);
        requestAuthorization(session, params);
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

        auto session = provider._sessionFactory(this);
        requestAuthorization(session, params);
        return session;
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

        auto session = provider._sessionFactory(this);
        requestAuthorization(session, params);
        return session;
    }

    OAuthSession loadSession(scope Session httpSession) immutable
    {
        if (!httpSession.isKeySet("oauth.session"))
            return null;

        auto data = httpSession.get!(OAuthSession.SaveData)("oauth.session");
        auto session = provider._sessionFactory(this);
        session.handleAccessTokenResponse(data.tokenData, data.timestamp, true);

        enforce!OAuthException(session.signature == data.signature,
            "Failed to load session: signature mismatch.");

        return session;
    }


    private:

    struct LoginData
    {
        SysTime timestamp;
        ulong   randomId;
        string  scopes;
        bool    redirectUriRequired;
    }

    static loginKey(SysTime t, ulong rnd, in string scopes) @safe
    {
        import std.digest.crc : crc32Of;
        import std.digest.sha : sha256Of;

        ubyte[20] data;
        ulong[] data64 = cast(ulong[])(data[0 .. 16]);
        data64[0] = t.toUnixTime;
        data64[1] = rnd;
        data[16 .. 20] = crc32Of(scopes);
        return sha256Of(data[]);
    }

    void requestAuthorization(
        OAuthSession session,
        string[string] params) immutable
    in
    {
        assert(session !is null);
        assert(session.settings == this || session.settings.hash == this.hash);
    }
    out
    {
        assert(session.token);
        assert(session.expires > Clock.currTime);
    }
    body
    {
        static bareMimeType(scope string type) pure @safe
        {
            import std.string : indexOf, strip;
            auto idx = type.indexOf(';');
            return type[0 .. ((idx >= 0) ? idx : $)].strip();
        }

        requestHTTP(
            provider.tokenUri,
            delegate void(scope HTTPClientRequest req) {
                req.headers["Accept"] = "application/json";
                provider.tokenRequestor(this, params, req);
            },
            delegate void(scope HTTPClientResponse res) {
                enforce(res.statusCode == 200, new OAuthException(
                    format("Auth server responded with HTTP status %d %s",
                        res.statusCode, res.statusPhrase)));

                auto contentType = bareMimeType(res.contentType);
                enforce!OAuthException(contentType == "application/json",
                    "Unacceptable response content type: " ~ contentType);

                SysTime httpDate;
                if (auto pResDate = "Date" in res.headers)
                    try httpDate = parseRFC822DateTime(*pResDate);
                    catch (DateTimeException) { }

                Json atr = res.readJson;

                // Authorization servers MAY omit the scope field in the
                // access token response if it would be equal to the scope
                // field specified in the access token request.
                if ("access_token" in atr &&
                    "scope" !in atr && "scope" in params)
                    atr["scope"] = params["scope"];

                session.handleAccessTokenResponse(atr, httpDate);
            }
        );
    }
}

/++
    Holds an access token and optionally a refresh token.
  +/
class OAuthSession
{
    protected immutable OAuthSettings settings;

    private
    {
        SysTime _timestamp;
        Json _tokenData;
        string _signature;
    }

    /++
        Authorize an HTTP request using this session's token.

        When implementing a REST interface client for a service using OAuth,
        you may want to set `vibe.web.rest.RestInterfaceClient.requestFilter`
        to a delegate to this method, so authorization will be handled
        automatically.

        This implementation only supports, and blindly assumes, the 'bearer'
        token type. Subclasses should override this if support for other token
        types is required.

        If this instance is mutable and the access token has expired and a
        refresh token is available, a new access token will automatically
        requested by a call to `refresh`.

        Params:
            req = The request to be authorized

        Throws: OAuthException if this session doesn't have any access token,
        or the access token has expired and cannot be refreshed.
      +/
    void authorizeRequest(scope HTTPClientRequest req)
    {
        enforce!OAuthException(token, "No access token available.");

        if (this.expired)
            refresh();

        req.headers["Authorization"] = "Bearer " ~ this.token;
    }

    /// ditto
    void authorizeRequest(scope HTTPClientRequest req) const
    {
        enforce!OAuthException(token, "No access token available.");
        req.headers["Authorization"] = "Bearer " ~ this.token;
    }

    deprecated("Use authorizeRequest instead of setAuthorizationHeader.")
    alias authorizeRequest setAuthorizationHeader;

    /++
        Refresh the access token of this session.

        Throws: OAuthException if no refresh token is available or the
            authorization fails otherwise.
      +/
    final
    void refresh()
    {
        string[string] params;
        params["grant_type"] = "refresh_token";
        params["refresh_token"] = this.refreshToken;
        params["redirect_uri"] = settings.redirectUri;

        settings.requestAuthorization(this, params);
    }

    /++
        Indicates whether this session can refresh its access token.
      +/
    bool canRefresh() @property const nothrow
    {
        try return ("refresh_token" in _tokenData) !is null;
        catch (Exception) return false;
    }

    /++
        Indicates whether this session has authorization for the given scope.

        Params:
            someScope = The scope to test for. Only one scope identifier may
                be specified, so the string should not contain whitespace.

        Returns: `true` if someScope is listed in this session's scopes.
      +/
    final
    bool hasScope(string someScope) const nothrow
    {
        return canFind(this.scopes, someScope);
    }

    /++
        Returns: `true` if this session's access token has _expired
      +/
    final
    bool expired() @property const
    {
        return (Clock.currTime > this.expires);
    }

    /++
        Expiration time of this session's access token.

        Please note that, if `this.canRefresh == true`, this is not the end
        of the session lifetime.
      +/
    SysTime expires() @property const nothrow
    {
        try return _timestamp + _tokenData["expires_in"].get!long.seconds;
        catch (Exception) return SysTime.max;
    }

    /++
        All _scopes this session has authorization for.
      +/
    string[] scopes() @property const nothrow
    {
        // TODO: Use splitter that is nothrow
        try return split(this.scopeString, ' ');
        catch (Exception) assert(false); // should never actually throw
    }

    /++
        Unique _signature of this session.
      +/
    string signature() @property const
    {
        return _signature;
    }

    /++
        Verify if this is the session referenced by the given HTTP session.

        Params:
            httpSession = The current HTTP session.

        Returns: `true` if httpSession contains this session's signature.
      +/
    bool verify(scope Session httpSession) const nothrow
    {
        try
        {
            if (!httpSession.isKeySet("oauth.session"))
                return false;

            auto data = httpSession.get!SaveData("oauth.session");
            return data.signature == _signature;
        }
        catch (Exception)
            return false;
    }

    protected:

    /++
        Constructor

        Params:
            settings = OAuth client _settings.
      +/
    this(immutable OAuthSettings settings) nothrow @safe
    {
        this.settings = settings;
    }

    /++
        Handles the response to an access token request and sets the properties
        of this session accordingly.

        This method is to be overridden by derived classes to implement support
        for additional token types and/or extension fields in the response.

        The default implementation only supports the the 'bearer' token type
        and the response fields documented in RFC 6749 sections 5.1 and 5.2.

        Params:
            atr = Access token response
            timestamp = (Optional) Best approximation available of the token
                generation time. May be used in token expiration time
                calculations. `Clock.currTime` is used if timestamp is omitted
                or set to `SysTime.init`.
            isReload = `true` if this is called in the process of loading a
                persisted session. If this is `true`, timestamp is required.

        Throws: OAuthException if: $(UL
            $(LI atr is an error response;)
            $(LI atr is missing required fields;)
            $(LI atr contains an unsupported token type;)
            $(LI timestamp is not set for a reload.))
      +/
    void handleAccessTokenResponse(
        Json atr,
        SysTime timestamp = SysTime.init,
        bool isReload = false)
    {
        if ("error" in atr)
            throw new OAuthException(atr);

        if (timestamp == SysTime.init)
        {
            enforce!OAuthException(!isReload, "Timestamp required on reload.");
            timestamp = Clock.currTime;
        }

        _signature = null;
        _tokenData = atr;
        _timestamp = timestamp;

        enforce(this.tokenType == "bearer", new OAuthException(
            format("Unsupported token type: %s", this.tokenType)));

        enforce!OAuthException(this.token, "No token received.");

        // generate new _signature
        this.sign();
    }

    /++
        Timestamp of this session
      +/
    SysTime timestamp() @property const nothrow
    {
        return _timestamp;
    }

    /++
        Json object from the access token response
      +/
    const(Json) tokenData() @property const nothrow
    {
        return _tokenData;
    }

    string scopeString() @property const nothrow
    {
        try
            if (auto pScope = "scope" in _tokenData)
                return pScope.get!string;
        catch (Exception) { }

        return null;
    }

    string token() @property const nothrow
    {
        try
            if (auto pToken = "access_token" in _tokenData)
                return pToken.get!string;
        catch (Exception) { }

        return null;
    }

    string tokenType() @property const nothrow
    {
        try
            if (auto pType = "token_type" in _tokenData)
                return pType.get!string.toLower();
        catch (Exception) { }

        return null;
    }

    void sign()
    {
        import std.digest.sha : sha256Of, toHexString;

        auto base =
            settings.hash ~ cast(ubyte[])((&_timestamp)[0 .. 1]) ~
            cast(ubyte[]) (this.classinfo.name ~ ": " ~ _tokenData.toString());

        // For some reason the string returned from toHexString seems to get
        // deallocated. Using .dup to work around.
        _signature = base.sha256Of.toHexString.dup;
    }

    private:

    string refreshToken() @property const
    {
        try
            if (auto pToken = "refresh_token" in _tokenData)
                return pToken.get!string;
        catch (Exception) { }

        throw new OAuthException("No refresh token is available.");
    }

    struct SaveData
    {
        SysTime timestamp;
        Json tokenData;
        string signature;
    }

    void save(scope Session httpSession) const
    {
        httpSession.set("oauth.session",
            SaveData(_timestamp, _tokenData, this.signature));
    }
}

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

        SessionFactory _sessionFactory;
        URL authUriParsed;
    }

    alias OAuthSession function(
        immutable OAuthSettings) nothrow SessionFactory; ///

    string authUri;     ///
    string tokenUri;    ///

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

    /++
        Constructor

        Params:
            authUri = Authorization URI for this provider.
            tokenUri = Token URI for this provider.
            sessionFactory = (Optional) function that returns a new session
                object compatible with this provider.
      +/
    this(
        string authUri,
        string tokenUri,
        SessionFactory sessionFactory
            = (settings) => new OAuthSession(settings)) immutable
    {
        this.authUri = authUri;
        this.tokenUri = tokenUri;
        this._sessionFactory = sessionFactory;

        this.authUriParsed = URL(authUri);
    }

    protected:

    void authUriHandler(immutable OAuthSettings, string[string]) const { }

    void tokenRequestor(
        in OAuthSettings settings,
        string[string] params,
        scope HTTPClientRequest req) const
    {
        req.method = HTTPMethod.POST;
        addBasicAuth(req, settings.clientId, settings.clientSecret);
        req.contentType = "application/x-www-form-urlencoded";
        req.bodyWriter.write(formEncode(params));
    }

    private:

    this(in Json json) immutable
    {
        this(json["authUri"].get!string,
            json["tokenUri"].get!string);

        if (allowAutoRegister && "name" in json)
            register(json["name"].get!string, this);
    }
}

/++
    Exception type used to indicate OAuth error conditions.

    Instances of this exception class should be created only by this module
    or classes derived from classes from this module.
  +/
class OAuthException : Exception
{
    /++
        Returns: the error code returned by the authentication server, or
        `null` if this exception was raised due to a client side error
        condition. Error codes are defined in RFC 6749 section 5.2.
      +/
    string specErrCode() @property const nothrow @safe @nogc
    {
        return _err_rfc6749;
    }

    /++
        Returns: a URI identifying a human-readable web page with information
        about the error, used to provide the client developer with additional
        information about the error. Returns `null` if either the server
        did not return an error URI, or this exception was raised due to a
        client side error condition.
      +/
    string errorUri() @property const nothrow @safe @nogc
    {
        return _err_uri;
    }

    /++
        Creates a new instance of OAuthException representing a client
        side error condition.
        
        Params:
            msg = human-readable error message.
      +/
    this(
        string msg,
        string file = __FILE__,
        size_t line = __LINE__,
        Throwable next = null) pure nothrow @safe @nogc
    {
        super(msg, file, line, next);
        _err_rfc6749 = null;
        _err_uri = null;
    }

    /++
        Creates a new instance of `OAuthException` based on an error
        response from the authentication server.
        
        Params:
            errorResponse = error response from the authentication server.
      +/
    this(
        Json errorResponse,
        string file = __FILE__,
        size_t line = __LINE__,
        Throwable next = null)
    in
    {
        assert("error" in errorResponse);
    }
    body
    {
        _err_rfc6749 = errorResponse["error"].get!string;

        auto descriptionJVal = "error_description" in errorResponse;
        auto msg = (descriptionJVal)
            ? descriptionJVal.get!string
            : _defaultOAuthErrorDescription(_err_rfc6749);
        
        if (auto uriJVal = "error_uri" in errorResponse)
            _err_uri = uriJVal.get!string;
        
        super(msg, file, line, next);
    }

    private:
    immutable string _err_rfc6749;
    immutable string _err_uri;

    string _defaultOAuthErrorDescription(string err) pure @safe
    {
        switch(err)
        {
            case "invalid_request":
                return "Invalid access token request.";

            case "invalid_client":
                return "Client authentication failed.";

            case "invalid_grant":
                return "Grant invalid or expired.";

            case "unauthorized_client":
                return "Client is not authorized to make this request.";

            case "unsupported_grant_type":
                return "Unsupported grant type.";

            case "invalid_scope":
                return "The service does not support the requested scope.";

            default:
                return "Unknown error.";
        }
    }
}


