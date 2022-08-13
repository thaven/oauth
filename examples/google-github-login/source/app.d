import vibe.http.router : URLRouter;
import vibe.http.server : HTTPServerSettings, listenHTTP, render;
import vibe.data.json : Json;
import vibe.http.session : MemorySessionStore;

shared static this()
{
    import vibe.core.log;
    setLogLevel(LogLevel.debug_);

    auto router = new URLRouter;

    router.get("/api/user/logout", (scope req, scope res) {
        res.terminateSession();
        logDebug("user logged out");
        res.redirect("/");
    });

    import oauthimpl : registerOAuth, isLoggedIn;
    router.registerOAuth;

    // example route to dump the current session
    with(router) {
        get("/api/session", (req, res) {
            if (req.session && req.session.isKeySet("user"))
                res.writeJsonBody(req.session.get!Json("user"));
            else
                res.writeBody("Empty Session");
        });
    }

    // load and init a permanent user storage
    import std.process : environment;
    import vibe.db.mongo.mongo : connectMongoDB;
    import users : UserController, users, User;
    auto host = environment.get("APP_MONGO_URL", "mongodb://localhost");
    auto dbName = environment.get("APP_MONGO_DB", "hackback");
    auto db = connectMongoDB(host).getDatabase(dbName);
    users = new UserController(db);

    import std.typecons : Nullable;
    // A simple main page
    with(router) {
        get("/", (req, res) {
            Nullable!User user;
            if (req.session && req.session.isKeySet("user"))
                user = req.session.get!User("user");

            res.render!("index.dt", user);
        });
    }

    auto settings = new HTTPServerSettings;
    settings.port = 8080;
    settings.sessionStore = new MemorySessionStore;
    listenHTTP(settings, router);
}
