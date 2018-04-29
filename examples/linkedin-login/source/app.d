import vibe.http.server;
import vibe.web.auth;
import vibe.web.web;

import oauth.webapp;

///
struct AuthInfo
{
}

///
@requiresAuth class LinkedInLoginExample : OAuthWebapp
{
    private
    {
        import oauth.settings : OAuthSettings;

        static immutable OAuthSettings _oauthSettings;
        static immutable _scopes = ["r_basicprofile"];
    }

    shared static this()
    {
        import vibe.core.file : readFileUTF8;
        import vibe.data.json : parseJsonString;
        import oauth.provider.linkedin : LinkedInAuthSettings;

        _oauthSettings = new immutable(LinkedInAuthSettings)(
                "linkedin.json".readFileUTF8.parseJsonString());
    }

    @noRoute @safe AuthInfo authenticate(scope HTTPServerRequest req, scope HTTPServerResponse res)
    {
        if (!isLoggedIn(req, _oauthSettings))
            login(req, res, _oauthSettings, _scopes);

        return AuthInfo();
    }

    @path("/")
    @anyAuth void getIndex(scope HTTPServerRequest req)
    {
        import vibe.http.client : requestHTTP;
        import vibe.data.json : Json;

        auto session = this.oauthSession(req);
        assert(session, "No session: authenticate() not called??");

        Json userInfo;

        requestHTTP("https://api.linkedin.com/v1/people/~?format=json", delegate(scope graphReq) {
            session.authorizeRequest(graphReq);
        }, delegate(scope graphRes) {
            auto obj = graphRes.readJson();
            if ("error" !in obj)
                userInfo = obj;
        });

        render!("index.dt", userInfo);
    }

    @path("/login/linkedin")
    @noAuth void getLoginLinkedIn(scope HTTPServerRequest req, scope HTTPServerResponse res)
    {
        login(req, res, _oauthSettings, _scopes);

        if (!res.headerWritten)
            res.redirect("/");
    }

    @anyAuth void getLogout()
    {
        terminateSession();
        render!("logout.dt");
    }
}

shared static this()
{
    import vibe.http.router : URLRouter;
    import vibe.http.session : MemorySessionStore;

    auto router = new URLRouter;
    router.registerWebInterface(new LinkedInLoginExample);

    auto settings = new HTTPServerSettings;
    settings.sessionStore = new MemorySessionStore;
    settings.port = 8080;

    listenHTTP(settings, router);
}
