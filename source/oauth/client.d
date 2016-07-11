/++
	OAuth2 client module

	Copyright: © 2016 Harry T. Vennik
	License: Subject to the terms of the MIT license, as written in the included LICENSE file.
	Authors: Harry T. Vennik

    Standards: Conforms to RFC 6749
  +/
module oauth.client;

import vibe.data.json;
import vibe.http.auth.basic_auth;
import vibe.http.client;
import vibe.inet.webform;

import std.algorithm.searching;
import std.base64;
import std.datetime;
import std.exception;
import std.format;
import std.string : split, join;
import std.uni : toLower;

@safe:

/++
    Represents a client of an OAuth authentication server.
  +/
abstract class OAuthClient
{
    string clientId() const @property nothrow @nogc
    {
        return _clientId;
    }

    void clientSecret(string value) @property nothrow @nogc
    {
        _clientSecret = value;
    }

    string redirectUri() const @property nothrow @nogc
    {
        return _redirectUri;
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
            scopes = An array of identifiers specifying the scope of
                access to be requested. (optional)

        Returns: The URI the user agent should be redirected to for
        login and authorization.
      +/
    final
    string userLoginUri(string[] scopes = null)
    {
        string[string] reqParams;

        reqParams["response_type"] = "code";
        reqParams["client_id"] = clientId;

        if (scopes)
            reqParams["scope"] = join(scopes, ' ');

        auto t = Clock.currTime;
        
        ulong loginKey;
        
        do {
            loginKey = generateLoginKey();
        } while (loginKey in _ld);
        
        reqParams["state"] = encodeLoginKey(loginKey);
        _ld[loginKey] = LoginData(scopes, t + hours(1));

        if (t >= _nextCleanup)
            cleanup(); 
        
        return authorizationEndpointUri ~ '?' ~ reqParams.formEncode();
    }

    /++
        User login helper method, complementary to ($D userLoginUri).

        Use this method to start a session with user impersonation. The
        authorizationCode MUST be obtained by redirection of the user
        agent to an URI obtained through ($D userLoginUri), otherwise
        there would not be a valid ($D loginKey).

        Params:
            authorizationCode = the authorization code obtained from the
                service. It will be in the 'code' parameter in the query
                string of the request being processed.
            loginKey = the unique key used to match this call to a previous
                call to ($D userLoginUri). Can be obtained from the 'state'
                query string parameter.

        Returns: The new session.

        Throws: ($D OAuthException) if any of the two arguments is invalid or
        authentication fails otherwise.
      +/
    final
    OAuthSession userSession(
        string loginKey,
        string authorizationCode) @system
    out(result)
    {
        assert(result !is null);
    }
    body
    {
        auto key = decodeLoginKey(loginKey);
        auto ld = (key in _ld);
        
        scope(success)
            synchronized(this)
                _ld.remove(key);
        
        string[string] params;
        params["grant_type"] = "authorization_code";
        params["code"] = authorizationCode;
        params["redirect_uri"] = redirectUri;

        if (ld._scopes)
            params["scope"] = join(ld._scopes, ' ');

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
        string[] scopes) @system
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
    OAuthSession clientSession(string[] scopes = null) @system
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
    
    protected:
    
    this(string redirectUri, string clientId, string clientSecret = null)
    {
        _redirectUri = enforce!OAuthException(redirectUri,
            "Parameter redirectUri is required.");
        
        _clientId = enforce!OAuthException(clientId,
            "Parameter clientId is required.");
        
        _clientSecret = clientSecret;
    }
    
    abstract
    string authorizationEndpointUri() @property const nothrow;

    abstract
    string tokenEndpointUri() @property const nothrow;
    
    OAuthSession newSession() const nothrow
    {
        return new OAuthSession(this);
    }

    private:
    struct LoginData
    {
        string[] _scopes;
        SysTime  _cleanupTime;
    }

    immutable string _clientId;
    string           _clientSecret;
    immutable string _redirectUri;

    LoginData[ulong] _ld;
    Duration _cleanupInterval = minutes(15);
    SysTime _nextCleanup;

    void requestAuthorization(
        OAuthSession session,
        string[string] params) const @system
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
        enforce!OAuthException(_clientSecret, "Client secret is not set.");

        requestHTTP(
            tokenEndpointUri,
            delegate void(scope HTTPClientRequest req) {
                req.method = HTTPMethod.POST;
                addBasicAuth(req, _clientId, _clientSecret);
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

                import vibe.stream.operations : readAllUTF8;
                session.handleAccessTokenResponse(res.bodyReader.readAllUTF8);
            }
        );
    }

    void cleanup()
    {
        auto t = Clock.currTime;
        size_t c;
                    
        foreach (k, ref v; _ld)
            if (t >= v._cleanupTime)
                _ld.remove(k) && ++c;

        if (c >= 2000)
            _cleanupInterval /= (c / 1000);
        else if (c < 750)
            _cleanupInterval *= 2;
        
        _nextCleanup = t + _cleanupInterval;
    }
}

class OAuthSession
{
    /++
        Authorize an HTTP request using this session's token.

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
        params["redirect_uri"] = _client.redirectUri;

        if (_scopes)
            params["scope"] = join(_scopes, ' ');
        
        _client.requestAuthorization(this, params);
    }
    
    bool hasScope(string someScope) const nothrow
    {
        return canFind(_scopes, someScope);
    }
    
    protected:

    /++
        Constructor

        Params:
            client = The client this session belongs to.
      +/
    this(const OAuthClient client) nothrow
    {
        _client = client;
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
    void handleAccessTokenResponse(string atr) @system
    {
        auto atrJObj = parseJson(atr);
        
        if ("error" in atrJObj)
            throw new OAuthException(atrJObj);
        
        enforce!OAuthException(
            atrJObj["token_type"].get!string.toLower() == "bearer",
            format("Unsupported token type: %s", atrJObj["token_type"].get!string));
            
        _token = atrJObj["access_token"].get!string;
        _expirationTime = Clock.currTime +
            seconds(atrJObj["expires_in"].get!long);

        if (auto tmp = "refresh_token" in atrJObj)
            _refreshToken = tmp.get!string;
        
        if (auto tmp = "scope" in atrJObj)
            _scopes = split(tmp.get!string, ' ');
    }

    private:
    const OAuthClient _client;
    string _token;
    SysTime _expirationTime;
    string _refreshToken;
    string[] _scopes;
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

private:

ulong decodeLoginKey(string encodedKey) pure
{
    enforce(encodedKey.length == 11);
    alias Base64Impl!('-', '_', Base64.NoPadding) Base64URLt;
    return (cast(ulong[])(Base64URLt.decode(encodedKey)))[0];
}

string encodeLoginKey(ulong key) pure @trusted
out(result)
{
    assert(result.length == 11);
}
body
{
    alias Base64Impl!('-', '_', Base64.NoPadding) Base64URLt;
    return Base64URLt.encode(cast(ubyte[])((&key)[0..1]));
}

ulong generateLoginKey()
{
    import std.random : uniform;
    return uniform!ulong();
}

