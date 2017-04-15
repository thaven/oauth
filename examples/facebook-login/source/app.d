import oauth.webapp;

shared static this()
{
    auto oauthSettings = () {
        import vibe.core.file : readFileUTF8;
        import vibe.data.json : parseJsonString;
        import oauth.provider.facebook : FacebookAuthSettings;

        return new immutable(FacebookAuthSettings)(
            "facebook.json".readFileUTF8.parseJsonString());
    } ();

    auto webapp = new OAuthWebapp;
    string[] scopes = [ "email" ];

    auto router = () {
        import vibe.http.router : URLRouter;
        import vibe.http.server : render;

        auto router = new URLRouter;

        router.get("/logout", delegate void(scope req, scope res) {
            res.terminateSession();
            res.render!("logout.dt", req);
        });

        router.get("/login/facebook", delegate void(scope req, scope res) {
            webapp.login(req, res, oauthSettings, scopes);
            res.redirect("/");
        });

        router.any("*", delegate void(scope req, scope res) {
            if (!webapp.isLoggedIn(req, oauthSettings))
                webapp.login(req, res, oauthSettings, null, scopes);
        });

        router.get("/", delegate (req, res) {
            import vibe.http.client : requestHTTP;
            import vibe.data.json : Json;

            assert (webapp.isLoggedIn(req, oauthSettings));

            auto session = webapp.oauthSession(req);
            Json userInfo;

            requestHTTP(
                "https://graph.facebook.com/me?fields=email,first_name,last_name",
                delegate (scope graphReq) {
                    session.authorizeRequest(graphReq);
                },
                delegate (scope graphRes) {
                    auto obj = graphRes.readJson();
                    if ("error" !in obj)
                        userInfo = obj;
                }
            );

            res.render!("index.dt", userInfo);
        });

        return router;
    } ();

    {
        import vibe.http.server : HTTPServerSettings, listenHTTP;
        import vibe.http.session : MemorySessionStore;

        auto settings = new HTTPServerSettings;
        settings.sessionStore = new MemorySessionStore;
        settings.port = 8080;

        listenHTTP(settings, router);
    }
}

