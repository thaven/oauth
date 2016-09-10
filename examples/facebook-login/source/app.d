import vibe.d;

import oauth.provider.facebook;
import oauth.webapp;

shared static this()
{
    auto oauthSettings = new immutable(FacebookAuthSettings)(
        "facebook.json".readFileUTF8.parseJsonString());

    auto webapp = new OAuthWebapp;
    string[] scopes = [ "email" ];

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
        if (!webapp.isLoggedIn(req))
            webapp.login(req, res, oauthSettings, scopes);
    });

	router.get("/", delegate (req, res) {
        assert (webapp.isLoggedIn(req));

        auto session = webapp.oauthSession(req);
        Json userInfo;

        requestHTTP(
            "https://graph.facebook.com/me?fields=email,first_name,last_name",
            delegate (scope graphReq) { session.authorizeRequest(graphReq); },
            delegate (scope graphRes) {
                auto obj = graphRes.readJson();
                if ("error" !in obj)
                    userInfo = obj;
            });

        res.render!("index.dt", userInfo);
    });

	auto settings = new HTTPServerSettings;
	settings.sessionStore = new MemorySessionStore;
	settings.port = 8080;

	listenHTTP(settings, router);
}

