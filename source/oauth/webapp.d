/++
    OAuth 2.0 client `vibe.http.server` / `vibe.web.web` integration

    Copyright: © 2016,2017 Harry T. Vennik
    License: Subject to the terms of the MIT license, as written in the included LICENSE file.
    Authors: Harry T. Vennik
  +/
module oauth.webapp;

import oauth.settings : OAuthSettings;
import oauth.session : OAuthSession;

import vibe.http.server : HTTPServerRequest, HTTPServerResponse;

version (Have_vibe_d_web) {
    import vibe.web.web : noRoute;
}

import std.datetime : Clock, SysTime;

/++
    Convenience oauth API wrapper for web applications
  +/
class OAuthWebapp
{
    version (Have_vibe_d_web) @noRoute:

    private OAuthSession loadSessionToContext(scope HTTPServerRequest req, immutable OAuthSettings settings) @safe
    in {
        assert(settings !is null, "Settings can't be null");
    }
    body
    {
        auto session = OAuthSession.load(settings, req.session);
        () @trusted {
            req.context["oauth.session"] = session;
        } ();
        return session;
    }

    /++
        Check if a request is from a logged in user

        Will only detect a login using the same settings. The same provider
        and clientId at least.

        Params:
            req = The request to be checked
            settings = The _settings to be used for the login check

        Returns: `true` if this request is from a logged in user.
      +/
    bool isLoggedIn(
        scope HTTPServerRequest req,
        immutable OAuthSettings settings) @safe
    {
        // For assert in oauthSession method
        version(assert) () @trusted {
            req.context["oauth.debug.login.checked"] = true;
        } ();

        if (!req.session)
            return false;

        if (settings !is null)
        {
            loadSessionToContext(req, settings);
            return true;
        }

        return false;
    }

    /++
        Perform OAuth _login using the given _settings

        The route mapped to this method should normally match the redirectUri
        set on the settings. If multiple providers are to be supported, there
        should be a different route for each provider, all mapped to this
        method, but with different settings.

        If the request looks like a redirect back from the authentication
        server, settings.userSession is called to obtain an OAuthSession.

        Otherwise, the user agent is redirected to the authentication server.

        Params:
            req = The request
            res = Response object to be used to redirect the client to the
                authentication server
            settings = The OAuth settings that apply to this _login attempt
            scopes = (Optional) An array of identifiers specifying the scope of
                the authorization requested.
        Returns: `true` if a OAuth session was obtained and
                 `false` if no OAuth session is present and a redirect to an
                  OAuth provider will happen.
      +/
    bool login(
        scope HTTPServerRequest req,
        scope HTTPServerResponse res,
        immutable OAuthSettings settings,
        in string[string] extraParams,
        in string[] scopes = null) @safe
    {
        // redirect from the authentication server
        if (req.session && "code" in req.query && "state" in req.query)
        {
            // For assert in oauthSession method
            version(assert) () @trusted {
                req.context["oauth.debug.login.checked"] = true;
            } ();

            auto session = settings.userSession(
                req.session, req.query["state"], req.query["code"]);

            return true;
        }
        else
        {
            if (!req.session)
                req.session = res.startSession();

            res.redirect(settings.userAuthUri(req.session, extraParams, scopes));
            return false;
        }
    }

    /// ditto
    bool login(
        scope HTTPServerRequest req,
        scope HTTPServerResponse res,
        immutable OAuthSettings settings,
        in string[] scopes) @safe
    {
        return login(req, res, settings, null, scopes);
    }

    /++
        Get the OAuthSession object associated to a request.

        This method is optimized for speed. It just gets the OAuthSession
        from the request context and doesn't do any validation.

        Always make sure that either `login` or `isLoggedIn` has been
        called for a request before this method is used.

        Params:
            req = the request to get the relevant session for
            settings = The OAuth settings that apply to this _login attempt

        Returns: The session associated to req, or `null` if no
            session was found.
      +/
    final
    OAuthSession oauthSession(scope HTTPServerRequest req, immutable OAuthSettings settings = null) nothrow @trusted
    in
    {
        try
            assert (req.context.get!bool("oauth.debug.login.checked"));
        catch (Exception)
            assert(false);
    }
    do
    {
        try
        {
            if (auto pCM = "oauth.session" in req.context)
                return pCM.get!OAuthSession;
            else
                return loadSessionToContext(req, settings);
        }
        catch (Exception e)
        {
            import vibe.core.log : logError;
            logError("OAuth: Exception occurred while reading request " ~
                "context: %s", e.toString());
        }
        return null;
    }
}
