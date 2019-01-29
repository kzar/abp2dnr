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
const {ContentBlockerList} = require("../lib/abp2chromerules.js");

function testRules(test, filters, expected, transformFunction)
{
  let blockerList = new ContentBlockerList();
  for (let filter of filters)
    blockerList.addFilter(Filter.fromText(filter));

  let rules = blockerList.generateRules();
  if (transformFunction)
      rules = transformFunction(rules);

  test.deepEqual(rules, expected);
}

exports.generateRules = {
  testRequestFilters: function(test)
  {
    testRules(test, [
      "/foo", "||test.com^", "http://example.com/foo", "^foo^"
    ], [
      {
        id: 1,
        condition: {
          urlFilter: "/foo",
          isUrlFilterCaseSensitive: false,
          resourceTypes: ["image", "stylesheet", "script", "font",
                          "media", "raw"]
        },
        action: {type: "block"}
      },
      {
        id: 2,
        condition: {
          urlFilter: "||test.com^",
          isUrlFilterCaseSensitive: false,
          resourceTypes: ["image", "stylesheet", "script", "font",
                          "media", "raw", "document"]
        },
        action: {type: "block"}
      },
      {
        id: 3,
        condition: {
          urlFilter: "http://example.com/foo",
          isUrlFilterCaseSensitive: false,
          resourceTypes: ["image", "stylesheet", "script", "font",
                          "media", "raw", "document"]
        },
        action: {type: "block"}
      },
      {
        id: 4,
        condition: {
          "urlFilter": "^[^:]+:(//)?.*http://example\\.com/foo",
          isUrlFilterCaseSensitive: false,
          "resourceTypes": ["image", "stylesheet", "script", "font",
                            "media", "raw", "document"]
        },
        action: {type: "block"}
      },
      {
        id: 5,
        condition: {
          "urlFilter": "^foo",
          isUrlFilterCaseSensitive: false,
          "resourceTypes": ["image", "stylesheet", "script", "font",
                            "media", "raw"]
        },
        action: {type: "block"}
      }
    ]);

    testRules(test, ["||example.com"], [
      {
        id: 1,
        condition: {
          "urlFilter": "||example.com",
          "resourceTypes": ["image", "stylesheet", "script", "font",
                            "media", "raw", "document"]
        },
        action: {type: "block"}
      }
    ]);

    // Rules which would match no resource-types shouldn't be generated.
    testRules(test, ["foo$document", "||foo.com$document"], []);

    test.done();
  },

  testRequestFilterExceptions: function(test)
  {
    testRules(test, ["@@example.com"], [
      {
        id: 1,
        condition: {
          "urlFilter": "example.com",
          "resourceTypes": ["image", "stylesheet", "script", "font",
                            "media", "raw", "document"]},
       action: {type: "allow"}}
    ]);

    testRules(test, ["@@||example.com"], [
      {
        id: 1,
        condition: {
          "urlFilter": "||example.com",
          "resourceTypes": ["image", "stylesheet", "script", "font",
                            "media", "raw", "document"]
        },
       action: {type: "allow"}}
    ]);

    test.done();
  },

  testDomainWhitelisting: function(test)
  {
    testRules(test, ["@@||example.com^$document"], [
      {
        id: 1,
        condition: {
          "domains": ["*example.com"]
        },
        action: {type: "allow"}
      }
    ]);
    testRules(test, ["@@||example.com^$document,image"], [
      {
        id: 1,
        condition: {
          "domains": ["*example.com"],
          "resourceTypes": ["document", "image"]
        },
        action: {type: "allow"}
      }
    ]);
    testRules(test, ["@@||example.com/path^$font,document"], [
      {
        id: 1,
        condition: {
          "domains": ["*example.com"],
          "resourceTypes": ["document", "font"]
        },
        action: {type: "allow"}
      }
    ]);

    test.done();
  },

  testGenericblockExceptions: function(test)
  {
    testRules(test, ["^ad.jpg|", "@@||example.com^$genericblock"],
              [[undefined, ["*example.com"]]],
              rules => rules.map(rule => [rule.condition["domains"],
                                          rule.condition["excludedDomains"]]));
    testRules(test, ["^ad.jpg|$domain=test.com",
                     "@@||example.com^$genericblock"],
              [[["*test.com"], undefined]],
              rules => rules.map(rule => [rule.condition["domains"],
                                          rule.condition["excludedDomains"]]));
    testRules(test, ["^ad.jpg|$domain=~test.com",
                     "@@||example.com^$genericblock"],
              [[undefined, ["*test.com", "*example.com"]]],
              rules => rules.map(rule => [rule.condition["domains"],
                                          rule.condition["excludedDomains"]]));

    test.done();
  },

  testRuleOrdering: function(test)
  {
    testRules(
      test,
      ["/ads.jpg", "@@example.com", "test.com#@#foo", "##bar"],
      ["block", "allow"],
      rules => rules.map(rule => rule.action.type)
    );
    testRules(
      test,
      ["@@example.com", "##bar", "/ads.jpg", "test.com#@#foo"],
      ["block", "allow"],
      rules => rules.map(rule => rule.action.type)
    );

    test.done();
  },

  testRequestTypeMapping: function(test)
  {
    // FIXME - What about WEBRTC, OBJECT_SUBREQUEST and POPUP?

    testRules(
      test,
      ["1", "2$image", "3$stylesheet", "4$script", "5$font", "6$media",
       "7$object", "8$xmlhttprequest", "9$websocket", "10$ping",
       "11$subdocument", "12$other", "13$IMAGE", "14$script,PING", "15$~image"],
      [undefined, // FIXME - Should use default, or is that incorrect?
       ["image"],
       ["stylesheet"],
       ["script"],
       ["font"],
       ["media"],
       ["object"],
       ["xmlhttprequest"],
       ["websocket"],
       ["ping"],
       ["sub_frame"],
       ["other"],
       ["image"],
       ["script", "ping"],
       ["stylesheet", "script", "font", "media", "object", "xmlhttprequest",
        "websocket", "ping", "sub_frame", "other"]],
      rules => rules.map(rule => rule.condition["resourceTypes"])
    );

    test.done();
  },

  testUnsupportedfilters: function(test)
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

    test.done();
  },

  testFilterOptions: function(test)
  {
    testRules(test, ["1$domain=foo.com"], ["*foo.com"],
              rules => rules[0]["condition"]["domains"]);
    testRules(test, ["2$third-party"], "thirdParty",
              rules => rules[0]["condition"]["domainType"]);

    testRules(test, ["||test.com"], false,
              rules => rules[0]["condition"]["isUrlFilterCaseSensitive"]);
    testRules(test, ["||test.com$match_case"], undefined,
              rules => rules[0]["condition"]["isUrlFilterCaseSensitive"]);

    // Test subdomain exceptions.
    testRules(test, ["1$domain=foo.com|~bar.foo.com"],
              ["foo.com", "www.foo.com"],
              rules => rules[0]["condition"]["domains"]);
    testRules(test, ["1$domain=foo.com|~www.foo.com"],
              ["foo.com"],
              rules => rules[0]["condition"]["domains"]);

    test.done();
  },

  testUnicode: function(test)
  {
    testRules(test, ["$domain=🐈.cat"], ["*xn--zn8h.cat"],
              rules => rules[0]["condition"]["domains"]);
    testRules(test, ["||🐈"], "||xn--zn8h",
              rules => rules[0]["condition"]["urlFilter"]);
    testRules(test, ["🐈$domain=🐈.cat"], "^[^:]+:(//)?.*%F0%9F%90%88",
              rules => rules[0]["condition"]["urlFilter"]);
    testRules(test, ["🐈%F0%9F%90%88$domain=🐈.cat"],
              "^[^:]+:(//)?.*%F0%9F%90%88%F0%9F%90%88",
              rules => rules[0]["condition"]["urlFilter"]);

    test.done();
  },

  testWebSocket: function(test)
  {
    testRules(test, ["foo$websocket"], [
      {
        id: 1,
        condition: {
          "urlFilter": "foo",
          "isUrlFilterCaseSensitive": false,
          "resourceTypes": ["websocket"]
        },
        action: {type: "block"}
      }
    ]);

    test.done();
  },
};
