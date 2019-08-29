/++
    OAuth 2.0 for D - Exceptions

    Copyright: © 2016,2017 Harry T. Vennik
    License: Subject to the terms of the MIT license, as written in the included LICENSE file.
    Authors: Harry T. Vennik

    Standards: Conforms to RFC 6749
  +/
module oauth.exception;

import vibe.data.json : Json;

@safe:

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
            file = (implicit)
            line = (implicit)
            next = (implicit)
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
            file = (implicit)
            line = (implicit)
            next = (implicit)
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

