/*
 * This file is part of Adblock Plus <https://adblockplus.org/>,
 * Copyright (C) 2006-present eyeo GmbH
 *
 * Adblock Plus is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 3 as
 * published by the Free Software Foundation.
 *
 * Adblock Plus is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Adblock Plus.  If not, see <http://www.gnu.org/licenses/>.
 */

"use strict";

const {Filter} = require("filterClasses");
const {generateRules} = require("../lib/abp2chromerules.js");

function testRules(test, filters, expected, transformFunction)
{
  let rules = generateRules(filters.map(Filter.fromText));

  if (transformFunction)
    rules = transformFunction(rules);

  test.deepEqual(rules, expected);
}

exports.generateRules = {
  testRequestFilters(test)
  {
    testRules(test, [
      "/foo", "||test.com^", "http://example.com/foo", "^foo^"
    ], [
      {
        id: 1,
        condition: {
          urlFilter: "/foo",
          isUrlFilterCaseSensitive: false
        },
        action: {type: "block"}
      },
      {
        id: 2,
        condition: {
          urlFilter: "||test.com^"
        },
        action: {type: "block"}
      },
      {
        id: 3,
        condition: {
          urlFilter: "http://example.com/foo",
          isUrlFilterCaseSensitive: false
        },
        action: {type: "block"}
      },
      {
        id: 4,
        condition: {
          urlFilter: "^foo^",
          isUrlFilterCaseSensitive: false
        },
        action: {type: "block"}
      }
    ]);

    testRules(test, ["||example.com"], [
      {
        id: 1,
        condition: {
          urlFilter: "||example.com"
        },
        action: {type: "block"}
      }
    ]);

    // Rules which would match no resource-types shouldn't be generated.
    testRules(test, ["foo$document", "||foo.com$document"], []);

    test.done();
  },

  testRequestFilterExceptions(test)
  {
    testRules(test, ["@@example.com"], [
      {
        id: 1,
        condition: {
          urlFilter: "example.com",
          isUrlFilterCaseSensitive: false
        },
        action: {type: "allow"}}
    ]);

    testRules(test, ["@@||example.com"], [
      {
        id: 1,
        condition: {
          urlFilter: "||example.com"
        },
        action: {type: "allow"}}
    ]);

    test.done();
  },

  testDomainWhitelisting(test)
  {
    testRules(test, ["@@||example.com^$document"], [
      {
        id: 1,
        condition: {
          domains: ["example.com"]
        },
        action: {type: "allow"}
      }
    ]);
    testRules(test, ["@@||example.com^$document,image"], [
      {
        id: 1,
        condition: {
          domains: ["example.com"]
        },
        action: {type: "allow"}
      },
      {
        id: 2,
        condition: {
          urlFilter: "||example.com^",
          resourceTypes: ["image"]
        },
        action: {type: "allow"}
      }
    ]);
    testRules(test, ["@@||bar.com^$document,image", "@@||foo.com^$document"], [
      {
        id: 1,
        condition: {
          domains: ["bar.com", "foo.com"]
        },
        action: {type: "allow"}
      },
      {
        id: 2,
        condition: {
          urlFilter: "||bar.com^",
          resourceTypes: ["image"]
        },
        action: {type: "allow"}
      }
    ]);
    testRules(test, ["@@||example.com/path^$font,document"], [
      {
        id: 1,
        condition: {
          urlFilter: "||example.com/path^",
          isUrlFilterCaseSensitive: false,
          resourceTypes: ["font"]
        },
        action: {type: "allow"}
      }
    ]);

    test.done();
  },

  testGenericblockExceptions(test)
  {
    testRules(test, ["^ad.jpg|", "@@||example.com^$genericblock"],
              [[undefined, ["example.com"]]],
              rules => rules.map(rule => [rule.condition["domains"],
                                          rule.condition["excludedDomains"]]));
    testRules(test, ["^ad.jpg|$domain=test.com",
                     "@@||example.com^$genericblock"],
              [[["test.com"], undefined]],
              rules => rules.map(rule => [rule.condition["domains"],
                                          rule.condition["excludedDomains"]]));
    testRules(test, ["^ad.jpg|$domain=~test.com",
                     "@@||example.com^$genericblock"],
              [[undefined, ["test.com", "example.com"]]],
              rules => rules.map(rule => [rule.condition["domains"],
                                          rule.condition["excludedDomains"]]));
    testRules(test, ["^ad.jpg|", "@@||example.com^$genericblock",
                     "@@ad.jpg"],
              [[undefined, ["example.com"]], [undefined, undefined]],
              rules => rules.map(rule => [rule.condition["domains"],
                                          rule.condition["excludedDomains"]]));


    test.done();
  },

  testRequestTypeMapping(test)
  {
    testRules(
      test,
      ["1", "2$image", "3$stylesheet", "4$script", "5$font", "6$media",
       "7$object", "8$object_subrequest", "9$xmlhttprequest", "10$websocket",
       "11$ping", "12$subdocument", "13$other", "14$IMAGE", "15$script,PING",
       "16$~image"],
      [undefined,
       ["image"],
       ["stylesheet"],
       ["script"],
       ["font"],
       ["media"],
       ["object"],
       ["object"],
       ["xmlhttprequest"],
       ["websocket"],
       ["ping"],
       ["sub_frame"],
       ["other", "csp_report"],
       ["image"],
       ["script", "ping"],
       ["stylesheet", "script", "font", "media", "object", "xmlhttprequest",
        "websocket", "ping", "sub_frame", "other", "csp_report"]],
      rules => rules.map(rule => rule.condition["resourceTypes"])
    );

    test.done();
  },

  testUnsupportedfilters(test)
  {
    // $sitekey
    testRules(test, ["foo$sitekey=bar"], []);

    // Element hiding
    testRules(test, ["##.whatever"], []);
    testRules(test, ["test.com##.whatever"], []);

    // Element hiding exceptions
    testRules(test, [
      "##.whatever",
      "test.com,anothertest.com###something",
      "@@||special.test.com^$elemhide",
      "@@||test.com^$generichide",
      "@@||anothertest.com^$elemhide",
      "@@^something^$elemhide",
      "@@^anything^$generichide"
    ], []);

    // WebRTC
    testRules(test, ["foo$webrtc"], []);

    // Popup
    testRules(test, ["bar$popup"], []);

    // Unicode
    testRules(test, ["$domain=🐈.cat"], []);
    testRules(test, ["||🐈"], []);
    testRules(test, ["🐈$domain=🐈.cat"], []);
    testRules(test, ["🐈%F0%9F%90%88$domain=🐈.cat"], []);

    // Invalid filter option
    testRules(test, ["||test.com$match_case"], []);

    // Regexp matching
    testRules(test, ["/\\.foo\\.com/.*[a-zA-Z0-9]{4}/"], []);

    test.done();
  },

  testFilterOptions(test)
  {
    testRules(test, ["1$domain=foo.com"], ["foo.com"],
              rules => rules[0]["condition"]["domains"]);
    testRules(test, ["2$third-party"], "thirdParty",
              rules => rules[0]["condition"]["domainType"]);

    testRules(test, ["||test.com"], undefined,
              rules => rules[0]["condition"]["isUrlFilterCaseSensitive"]);
    testRules(test, ["||test.com$match-case"], undefined,
              rules => rules[0]["condition"]["isUrlFilterCaseSensitive"]);
    testRules(test, ["||test.com/foo"], false,
              rules => rules[0]["condition"]["isUrlFilterCaseSensitive"]);
    testRules(test, ["||test.com/foo$match-case"], undefined,
              rules => rules[0]["condition"]["isUrlFilterCaseSensitive"]);
    testRules(test, ["||test.com/Foo"], false,
              rules => rules[0]["condition"]["isUrlFilterCaseSensitive"]);
    testRules(test, ["||test.com/Foo$match-case"], undefined,
              rules => rules[0]["condition"]["isUrlFilterCaseSensitive"]);

    // Test subdomain exceptions.
    testRules(test, ["1$domain=foo.com|~bar.foo.com"], [
      {
        id: 1,
        condition: {
          urlFilter: "1",
          isUrlFilterCaseSensitive: false,
          domains: ["foo.com"],
          excludedDomains: ["bar.foo.com"]
        },
        action: {type: "block"}
      }
    ]);

    test.done();
  },

  testWebSocket(test)
  {
    testRules(test, ["foo$websocket"], [
      {
        id: 1,
        condition: {
          urlFilter: "foo",
          isUrlFilterCaseSensitive: false,
          resourceTypes: ["websocket"]
        },
        action: {type: "block"}
      }
    ]);

    test.done();
  }
};
