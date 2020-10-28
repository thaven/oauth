import vibe.data.bson : BsonObjectID;
import vibe.db.mongo.mongo;
import std.typecons : tuple;

struct User
{
    import vibe.data.serialization : dbName = name;
    @dbName("_id") BsonObjectID id;
    string email;
    string name;
    long githubId;
    string googleId;
    string avatarUrl;
}

// TLS instance
UserController users;

class UserController
{
    MongoCollection m_users;

    this(MongoDatabase db)
    {
        m_users = db["users"];

        m_users.ensureIndex([tuple("googleId", 1)], IndexFlags.unique | IndexFlags.sparse);
        m_users.ensureIndex([tuple("githubId", 1)], IndexFlags.unique | IndexFlags.sparse);
    }

    User loginOrSignup(string providerId)(User user)
    {
        auto u = m_users.findOne!User([providerId: mixin("user." ~ providerId)]);
        if (!u.isNull)
        {
            // TODO: should we update attributes?
            return u.get;
        }
        else
        {
            return addUser(user);
        }
    }

    User addUser(User user)
    {
        user.id  = BsonObjectID.generate();
        m_users.insert(user);
        return user;
    }

    void updateToken(string id, string token)
    {
        m_users.update(["id": id], ["$set": token]);
    }
}
