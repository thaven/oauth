module oauth.test;

public import unit_threaded;
import oauth.provider;
import oauth.settings;
import vibe.http.session;

package(oauth):
@safe:

class TestSettings : OAuthSettings
{
    this() immutable
    {
        super("testprovider", "TEST_CLIENT_ID", "TEST_CLIENT_SECRET", "https://example.com/redirect_uri");
    }
}

immutable(OAuthSettings) testSettings()
{
    import std.typecons : Rebindable;

    static Rebindable!(immutable TestSettings) it;
    if (it is null)
        it = new immutable(TestSettings)();
    return it;
}

class TestProvider : OAuthProvider
{
    enum authUri = "https://example.com/site/oauth2/authenticate";
    enum tokenUri = "https://example.com/site/oauth2/access_token";

    this() immutable
    {
        super(authUri, tokenUri);
    }
}

immutable testProvider = new immutable(TestProvider);

shared static this()
{
    OAuthProvider.register("testprovider", testProvider);
}

Session testSession()
{
    static MemorySessionStore it;
    if (it is null)
        it = new MemorySessionStore;
    return it.create();
}
