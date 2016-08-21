/++
    OAuth 2.0 client configuration helper module

    Copyright: © 2016 Harry T. Vennik
    License: Subject to the terms of the MIT license, as written in the included LICENSE file.
    Authors: Harry T. Vennik
  +/
module oauth.config;

import oauth.client;

import vibe.core.file;
import vibe.data.json;

import std.typecons : Rebindable;

immutable(OAuthSettings)[] loadConfig(string path)
{
    immutable(OAuthSettings)[] cfg;
    auto json = path.readFileUTF8.parseJsonString();

    if (json.type == Json.Type.object)
    {
        cfg ~= new immutable(OAuthSettings)(json);
    }
    else
    {
        foreach (settingsJObj; json)
            cfg ~= new immutable(OAuthSettings)(settingsJObj);
    }

    return cfg;
}
