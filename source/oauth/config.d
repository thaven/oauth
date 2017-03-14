/++
    OAuth 2.0 for D - Compatibility module

    Copyright: © 2016,2017 Harry T. Vennik
    License: Subject to the terms of the MIT license, as written in the included LICENSE file.
    Authors: Harry T. Vennik
  +/
deprecated("Please use oauth.settings instead.")
module oauth.config;

public import oauth.settings : loadConfig;
