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
import std.exception : enforce;
import std.typecons : Rebindable;

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

    this(string path)
    {
        import oauth.config : loadConfig;
        import std.digest.digest : toHexString;

        foreach (settings; loadConfig(path))
            _settingsMap[settings.hash.toHexString()] = settings;
    }

    /++
        Enforces OAuth authentication on the given req/res pair.

        Params:
            req = Request object that is to be checked
            res = Response object that will be used to redirect the client if
                not authenticated.
            scopes = An array of identifiers specifying the scope of
                the authorization requested. (optional)
      +/
    final
    void performOAuth(
        scope HTTPServerRequest req,
        scope HTTPServerResponse res,
        string[] scopes = null)
    {
        enforce(_settingsMap.length > 0);

        if (!req.session)
            req.session = res.startSession();
        else if (auto pCE = req.session.id in _sessionCache)
        {
            if (pCE.session.verify(req.session))
            {
                pCE.timestamp = Clock.currTime;
                return;
            }
            else
                _sessionCache.remove(req.session.id);
        }

        if (req.session.isKeySet("oauth.client"))
        {
            string hash = req.session.get!string("oauth.client");
            auto settings = _settingsMap[hash].get;
            auto session = settings.loadSession(req.session);

            if (!session && "code" in req.query && "state" in req.query)
                session = settings.userSession(
                    req.session, req.query["state"], req.query["code"]);

            if (!session)
            {
                res.redirect(settings.userAuthUri(req.session, scopes));
                return;
            }

            static if (__traits(compiles, req.context))
                req.context["oauth.session"] = session;
            else
                _sessionCache[req.session.id] =
                    SessionCacheEntry(session, Clock.currTime);
        }
        else
            unauthorized(req, res, scopes);
    }

    /++
        Get the OAuthSession object associated to a request.

        Always make sure that the $(D performOAuth) method is called for a
        request before this method is used, otherwise a stale session may be
        returned, or no session in case of a recently logged in user.

        Params:
            req = the request to get the relevant session for

        Returns: The session associated to $(D req), or $(D null) if no
            session was found.
      +/
    final
    OAuthSession oauthSession(in HTTPServerRequest req) nothrow
    {
        try
            if (auto pCE = req.session.id in _sessionCache)
                return pCE.session;
        catch (Exception) { }

        return null;
    }

    protected

    /++
        Handler called by $(D performOAuth) if the request is unauthorized.

        Default implementation doesn't do anything. Override it to take your
        application specific action on unauthorized requests.

        Params:
            req = the unauthorized request
            res = the other half of the req/res pair
            scopes = the list of scopes passed to $(D performOAuth)
      +/
    void unauthorized(
        scope HTTPServerRequest req,
        scope HTTPServerResponse res,
        string[] scopes) { }
}
