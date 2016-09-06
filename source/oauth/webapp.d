/++
    OAuth 2.0 client vibe.http.server integration

    Copyright: © 2016 Harry T. Vennik
    License: Subject to the terms of the MIT license, as written in the included LICENSE file.
    Authors: Harry T. Vennik
  +/
module oauth.webapp;

import oauth.client;
import vibe.http.server;

import std.datetime : Clock, SysTime;
import std.typecons : Rebindable;

/++
    Convenience oauth API wrapper for web applications
  +/
class OAuthWebapp
{
    private
    {
        Rebindable!(immutable OAuthSettings)[string] _settingsMap;

        struct SessionCacheEntry
        {
            OAuthSession session;
            SysTime timestamp;
        }

        SessionCacheEntry[string] _sessionCache;
    }

    /++
        Check if a request is from a logged in user

        Params:
            req = The request to be checked

        Returns: $(D true) if this request is from a logged in user.
      +/
    bool isLoggedIn(
        scope HTTPServerRequest req)
    {
        // For assert in oauthSession method
        version(assert) req.params["oauth.debug.login.checked"] = "yes";

        if (!req.session)
            return false;

        if (auto pCE = req.session.id in _sessionCache)
        {
            if (pCE.session.verify(req.session))
            {
                pCE.timestamp = Clock.currTime;
                return true;
            }
            else
                _sessionCache.remove(req.session.id);
        }

        if (req.session.isKeySet("oauth.client"))
        {
            string hash = req.session.get!string("oauth.client");
            auto settings = _settingsMap[hash].get;

            if (auto session =
                settings ? settings.loadSession(req.session) : null)
            {
                static if (__traits(compiles, req.context))
                    req.context["oauth.session"] = session;

                _sessionCache[req.session.id] =
                    SessionCacheEntry(session, Clock.currTime);

                return true;
            }
        }

        return false;
    }

    /++
        Perform OAuth login using the given settings

        The route mapped to this method should normally match the redirectUri
        set on the settings. If multiple providers are to be supported, there
        should be a different route for each provider, all mapped to this
        method, but with different settings.

        If the request looks like a redirect back from the authentication
        server, $(D settings.userSession) is called to obtain an OAuthSession.

        Otherwise, the user agent is redirected to the authentication server.

        Params:
            req = The request
            res = Response object to be used to redirect the client to the
                authentication server
            settings = The OAuth settings that apply to this login attempt
            scopes = An array of identifiers specifying the scope of
                the authorization requested. (optional)
      +/
    void login(
        scope HTTPServerRequest req,
        scope HTTPServerResponse res,
        immutable OAuthSettings settings,
        string[] scopes = null)
    {
        if (req.session && "code" in req.query && "state" in req.query)
        {
            import std.digest.digest : toHexString;
            auto hashString = settings.hash.toHexString();

            if (hashString !in _settingsMap)
                _settingsMap[hashString] = settings;

            auto session = settings.userSession(
                req.session, req.query["state"], req.query["code"]);

            if (session)
            {
                _sessionCache[req.session.id] =
                    SessionCacheEntry(session, Clock.currTime);

                // For assert in oauthSession method
                version(assert) req.params["oauth.debug.login.checked"] = "yes";
            }
        }
        else
        {
            if (!req.session)
                req.session = res.startSession();

            res.redirect(settings.userAuthUri(req.session, scopes));
        }
    }

    /++
        Get the OAuthSession object associated to a request.

        This method is optimized for speed. It just performs a session cache
        lookup and doesn't do any validation.

        Always make sure that either $(D login) or $(D isLoggedIn) has been
        called for a request before this method is used.

        Params:
            req = the request to get the relevant session for

        Returns: The session associated to $(D req), or $(D null) if no
            session was found.
      +/
    final
    OAuthSession oauthSession(in HTTPServerRequest req) nothrow
    in
    {
        try assert (req.params.get("oauth.debug.login.checked", "no") == "yes");
        catch assert(false);
    }
    body
    {
        try
        {
            static if (__traits(compiles, req.context))
                if (auto pCM = "oauth.session" in req.context)
                    return pCM.get!OAuthSession;

            if (auto pCE = req.session.id in _sessionCache)
                return pCE.session;
        }
        catch (Exception) { }

        return null;
    }
}
