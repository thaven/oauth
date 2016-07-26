/++
    OAuth 2.0 client module

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
import vibe.inet.webform;

import core.atomic;
import std.algorithm.searching;
import std.datetime;
import std.exception;
import std.format;
import std.string : split, join;
import std.uni : toLower;

@safe:

/++
    Settings for an OAuth 2.0 client application.

    One client application may hold multiple settings objects when using various
    authentication servers.

    Instances of this class must be immutable.
  +/
class OAuthSettings
{
    OAuthProvider provider;
    string clientId;
    string clientSecret;
    string redirectUri;

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
    this(in Json config) immutable @system
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
            provider = The registered name of the authentication provider.
            clientId = The client ID to use in client authentication for the
                given provider.
            clientSecret = The client secret to use in client authentication
                for the given provider.
            redirectUri = The uri identifying this application, the user agent
                will be redirected to this uri (with some query parameters
                added) after authorization.
      +/
    this(
        string provider,
        string clientId,
        string clientSecret,
        string redirectUri) immutable nothrow
    {
        this(OAuthProvider.forName(provider),
            clientId, clientSecret, redirectUri);
    }

    private:

    this(
        immutable OAuthProvider provider,
        string clientId,
        string clientSecret,
        string redirectUri) immutable nothrow
    {
        this.provider = provider;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.redirectUri = redirectUri;
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
        to the ($D userSession) method, along with the authorization
        code.

        Params:
            httpSession = The current HTTP session.
            scopes = An array of identifiers specifying the scope of
                access to be requested. (optional)

        Returns: The URI the user agent should be redirected to for
        login and authorization.
      +/
    final
    string userAuthUri(
        scope Session httpSession,
        string[] scopes = null) immutable @system
    {
        import std.random : uniform;

        string[string] reqParams;
        string scopesJoined = join(scopes, ' ');

        reqParams["response_type"] = "code";
        reqParams["client_id"] = clientId;

        if (scopesJoined)
            reqParams["scope"] = scopesJoined;

        auto t = Clock.currTime;
        auto rnd = uniform!ulong;

        auto key = loginKey(t, rnd, scopesJoined);
        reqParams["state"] = Base64URLNoPadding.encode(key);
        httpSession.set("oauth.authorization", LoginData(t, rnd, scopesJoined));

        return provider.authUri ~ '?' ~ reqParams.formEncode();
    }

    /++
        User login helper method, complementary to ($D userAuthUri).

        Use this method to start a session with user impersonation. The
        authorizationCode MUST be obtained by redirection of the user
        agent to an URI obtained through ($D userAuthUri), otherwise
        there would not be a valid ($D state).

        Params:
            httpSession = The current HTTP session.
            state = OAuth state obtained from the 'state' query string parameter
                of the request URL.
            authorizationCode = the authorization code obtained from the
                service. It will be in the 'code' parameter in the query
                string of the request being processed.

        Returns: The new session.

        Throws: ($D OAuthException) if any of the latter two arguments is
        invalid or authentication fails otherwise.
      +/
    final
    OAuthSession userSession(
        scope Session httpSession,
        string state,
        string authorizationCode) immutable @system
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

        // Seems like there is no way to remove a key from a session????
        scope(exit)
            httpSession.set("oauth.authorization", LoginData.init);

        enforce(ld.timestamp >= Clock.currTime - 1.hours,
            "Authorization challenge timeout.");

        string[string] params;
        params["grant_type"] = "authorization_code";
        params["code"] = authorizationCode;
        params["redirect_uri"] = redirectUri;

        if (ld.scopes)
            params["scope"] = ld.scopes;

        auto session = newSession();
        requestAuthorization(session, params);
        return session;
    }

    /++
        Start a session on behalf of the resource owner, using username and
        password for authentication.

        This authentication flow MUST be used only as a last resort, as it
        requires exposal of the plain username and password to the client.

        Params:
            username = The resource owner's username.
            password = The resource owner's password.
            scopes = An array of strings representing the scope of the
                authorization request. (may be null)

        Throws: OAuthException if user authentication fails or the client could
            not be granted access on behalf of the resource owner for any scope
            requested.
      +/
    final
    OAuthSession userSession(
        string username,
        string password,
        string[] scopes) immutable @system
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

        auto session = newSession();
        requestAuthorization(session, params);
        return session;
    }
    
    /++
        Obtain a new session using client credentials.

        Params:
            scopes = An array of identifiers specifying the scope of
                access to be requested. (optional)

        Returns: The new session.

        Throws: ($D OAuthException) if authentication fails.
      +/
    final
    OAuthSession clientSession(string[] scopes = null) immutable @system
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

        auto session = newSession();
        requestAuthorization(session, params);
        return session;
    }
    
    OAuthSession newSession() immutable nothrow
    {
        return new OAuthSession(this);
    }

    private:

    struct LoginData
    {
        SysTime timestamp;
        ulong   randomId;
        string  scopes;
    }

    static loginKey(SysTime t, ulong rnd, in string scopes)
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
        string[string] params) immutable @system
    in
    {
        assert(session !is null);
    }
    out
    {
        assert(session._token);
        assert(session._expirationTime > Clock.currTime);
    }
    body
    {
        requestHTTP(
            provider.tokenUri,
            delegate void(scope HTTPClientRequest req) {
                req.method = HTTPMethod.POST;
                addBasicAuth(req, clientId, clientSecret);
                req.contentType = "application/x-www-form-urlencoded";
                req.headers["Accept"] = "application/json";
                req.bodyWriter.write(formEncode(params));
            },
            delegate void(scope HTTPClientResponse res) {
                enforce(res.statusCode == 200, new OAuthException(
                    format("Auth server responded with HTTP status %d %s",
                        res.statusCode, res.statusPhrase)));
                enforce!OAuthException(res.contentType == "application/json",
                    "Unacceptable response content type.");

                session.handleAccessTokenResponse(res.readJson);
            }
        );
    }
}

class OAuthSession
{
    /++
        Authorize an HTTP request using this session's token.

        When implementing a REST interface client for a service using OAuth,
        you may want to set $(D vibe.web.rest.RestInterfaceClient.requestFilter)
        to a delegate to this method, so authentication will be handled
        automatically.

        This implementation only supports, and blindly assumes, the 'bearer'
        token type. Subclasses should override this if support for other token
        types is required.

        Params:
            req = HTTPClientRequest object

        Throws: OAuthException if this session doesn't have any access token,
        or the access token has expired and cannot be refreshed.
      +/
    void setAuthorizationHeader(HTTPClientRequest req) @system
    {
        enforce!OAuthException(_token, "No access token available.");
        
        if (Clock.currTime > _expirationTime)
            refresh();

        req.headers["Authorization"] = "Bearer " ~ _token;
    }
    
    /++
        Refresh the access token of this session.

        Throws: OAuthException if no refresh token is available.
      +/
    final
    void refresh() @system
    {
        enforce!OAuthException(_refreshToken, "No refresh token is available.");
    
        string[string] params;
        params["grant_type"] = "refresh_token";
        params["refresh_token"] = _refreshToken;
        params["redirect_uri"] = _settings.redirectUri;

        if (_scopes)
            params["scope"] = join(_scopes, ' ');
        
        _settings.requestAuthorization(this, params);
    }
    
    bool hasScope(string someScope) const nothrow
    {
        return canFind(_scopes, someScope);
    }
    
    protected:

    /++
        Constructor

        Params:
            settings = OAuth client settings.
      +/
    this(immutable OAuthSettings settings) nothrow
    {
        _settings = settings;
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
      +/
    void handleAccessTokenResponse(Json atr) @system
    {
        if ("error" in atr)
            throw new OAuthException(atr);
        
        enforce!OAuthException(
            atr["token_type"].get!string.toLower() == "bearer",
            format("Unsupported token type: %s", atr["token_type"].get!string));
            
        _token = atr["access_token"].get!string;
        _expirationTime = Clock.currTime +
            seconds(atr["expires_in"].get!long);

        if (auto tmp = "refresh_token" in atr)
            _refreshToken = tmp.get!string;
        
        if (auto tmp = "scope" in atr)
            _scopes = split(tmp.get!string, ' ');
    }

    private:
    immutable OAuthSettings _settings;
    string _token;
    SysTime _expirationTime;
    string _refreshToken;
    string[] _scopes;
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
    }

    string authUri;
    string tokenUri;

    /++
        Disables automatic registration of authentication servers from JSON
        config.

        This will only prevent the application from changing the provider
        registry implicitly. Explicit registration of providers remains
        possible.

        Should be called only once and before using any OAuth functions.
      +/
    static disableAutoRegister() nothrow @system
    {
        static shared bool calledBefore;

        if(cas(&calledBefore, false, true))
            allowAutoRegister = false;
    }

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

    static register(string name, immutable OAuthProvider srv) nothrow @trusted
    {
        // TODO: investigate why 'synchronized' is not nothrow
        //  Hacked around it for now.
        try synchronized(OAuthProvider.classinfo)
            _servers[name] = srv;
        catch (Exception)
            assert (false);
    }

    this(
        string authUri,
        string tokenUri) immutable nothrow
    {
        this.authUri = authUri;
        this.tokenUri = tokenUri;
    }

    private:

    this(in Json json) immutable @system
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
        ($D null) if this exception was raised due to a client side error
        condition. Error codes are defined in RFC 6749 section 5.2.
      +/
    string specErrCode() @property const nothrow @nogc
    {
        return _err_rfc6749;
    }

    /++
        Returns: a URI identifying a human-readable web page with information
        about the error, used to provide the client developer with additional
        information about the error. Returns ($D null) if either the server
        did not return an error URI, or this exception was raised due to a
        client side error condition.
      +/
    string errorUri() @property const nothrow @nogc
    {
        return _err_uri;
    }

    /++
        Creates a new instance of ($D OAuthException) representing a client
        side error condition.
        
        Params:
            msg = human-readable error message.
      +/
    this(
        string msg,
        string file = __FILE__,
        size_t line = __LINE__,
        Throwable next = null) pure nothrow @nogc
    {
        super(msg, file, line, next);
        _err_rfc6749 = null;
        _err_uri = null;
    }

    /++
        Creates a new instance of ($D OAuthException) based on an error
        response from the authentication server.
        
        Params:
            errorResponse = error response from the authentication server.
      +/
    this(
        Json errorResponse,
        string file = __FILE__,
        size_t line = __LINE__,
        Throwable next = null) @system
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

    string _defaultOAuthErrorDescription(string err) pure
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


