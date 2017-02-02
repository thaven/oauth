/++
    OAuth 2.0 for D - Client session implementation

    Copyright: © 2016,2017 Harry T. Vennik
    License: Subject to the terms of the MIT license, as written in the included LICENSE file.
    Authors: Harry T. Vennik

    Standards: Conforms to RFC 6749
  +/
module oauth.session;

import oauth.settings : OAuthSettings;
import oauth.exception : OAuthException;

import std.datetime : Clock, seconds, SysTime;

import std.algorithm.searching : canFind;
import std.array : split;
import std.exception : enforce;
import std.format : format;
import std.uni : toLower;

import vibe.data.json : Json;
import vibe.http.client : HTTPClientRequest;
import vibe.http.session : Session;

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

    static OAuthSession load(
        immutable OAuthSettings settings,
        scope Session httpSession)
    {
        if (!httpSession.isKeySet("oauth.session"))
            return null;

        auto data = httpSession.get!(SaveData)("oauth.session");
        auto session = new OAuthSession(settings, data);

        enforce!OAuthException(session.signature == data.signature,
            "Failed to load session: signature mismatch.");

        return session;
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

        requestAuthorization(params);
    }

    /++
        Save this session's data into an HTTP session.

        Params:
            httpSession = target HTTP session.
      +/
    void save(scope Session httpSession) const
    {
        httpSession.set("oauth.session",
            SaveData(_timestamp, _tokenData, this.signature));
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

    package(oauth):

    /++
        Constructor

        Params:
            settings = OAuth client _settings.
            params = Authorization request parameters
      +/
    this(immutable OAuthSettings settings, string[string] params)
    {
        this.settings = settings;
        this.requestAuthorization(params);
    }

    protected:

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

        // TODO: for some reason the allocated string is GC collected and points
        // to garbage (hence the need for .dup)
        _signature = base.sha256Of.toHexString.dup;
    }

    private:

    this(immutable OAuthSettings settings, SaveData data)
    {
        this.settings = settings;
        this.handleAccessTokenResponse(data.tokenData, data.timestamp, true);
    }

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

    void requestAuthorization(string[string] params)
    out
    {
        assert(this.token);
        assert(this.expires > Clock.currTime);
    }
    body
    {
        import vibe.http.client : requestHTTP, HTTPClientResponse;

        static bareMimeType(scope string type) pure @safe
        {
            import std.string : indexOf, strip;
            auto idx = type.indexOf(';');
            return type[0 .. ((idx >= 0) ? idx : $)].strip();
        }

        requestHTTP(
            settings.provider.tokenUri,
            delegate void(scope HTTPClientRequest req) {
                req.headers["Accept"] = "application/json";
                settings.provider.tokenRequestor(this.settings, params, req);
            },
            delegate void(scope HTTPClientResponse res) {
                import std.datetime : DateTimeException, parseRFC822DateTime;

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

                this.handleAccessTokenResponse(atr, httpDate);
            }
        );
    }
}

