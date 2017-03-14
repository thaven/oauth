/++
    OAuth 2.0 for D - Compatibility module

    Copyright: © 2016,2017 Harry T. Vennik
    License: Subject to the terms of the MIT license, as written in the included LICENSE file.
    Authors: Harry T. Vennik
  +/
deprecated("You'll find what you're looking for in oauth.exception, oauth.provider, oauth.session and oauth.settings.")
module oauth.client;

public import oauth.settings : OAuthSettings;
public import oauth.session;
public import oauth.provider;
public import oauth.exception;

