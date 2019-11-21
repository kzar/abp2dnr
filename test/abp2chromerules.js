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

const assert = require("assert");

const {Filter} = require("adblockpluscore/lib/filterClasses");
const {generateRules} = require("../lib/abp2chromerules.js");

function testRules(filters, expected, transformFunction)
{
  let rules = generateRules(filters.map(Filter.fromText));

  if (transformFunction)
    rules = transformFunction(rules);

  assert.deepEqual(rules, expected);
}

describe("generateRules", function()
{
  describe("Request filters", function()
  {
    it("should generate request blocking rules", function()
    {
      testRules(["||example.com"], [
        {
          id: 1,
          condition: {
            urlFilter: "||example.com"
          },
          action: {type: "block"}
        }
      ]);

      testRules([
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
    });

    it("shouldn't generate blocking rules matching no request type", function()
    {
      testRules(["foo$document", "||foo.com$document"], []);
    });
  });

  describe("Request whitelisting filters", function()
  {
    it("should generate case-insensitive whitelisting filters", function()
    {
      testRules(["@@example.com"], [
        {
          id: 1,
          condition: {
            urlFilter: "example.com",
            isUrlFilterCaseSensitive: false
          },
          action: {type: "allow"}}
      ]);
    });

    it("should generate case sensitive whitelisting filters", function()
    {
      testRules(["@@||example.com"], [
        {
          id: 1,
          condition: {
            urlFilter: "||example.com"
          },
          action: {type: "allow"}}
      ]);
    });
  });

  describe("Domain whitelisting", function()
  {
    it("should generate domain whitelisting rules", function()
    {
      testRules(["@@||example.com^$document"], [
        {
          id: 1,
          condition: {
            domains: ["example.com"]
          },
          action: {type: "allow"}
        }
      ]);
      testRules(["@@||example.com^$document,image"], [
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
      testRules(["@@||bar.com^$document,image", "@@||foo.com^$document"], [
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
    });

    it("should generate whitelisting rules for URLs", function()
    {
      testRules(["@@||example.com/path^$font,document"], [
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
    });

    it("should whitelist domains correctly", function()
    {
      testRules(["@@https://a.com$document",
                 "@@https://b.com$document",
                 "@@https://c.com$document",
                 "@@https://d.com$document",
                 "@@https://e.com$document"],
        [
          {
            id: 1,
            condition: {
              domains: ["a.com", "b.com", "c.com", "d.com", "e.com"]
            },
            action: {type: "allow"}
          }
        ]
      );
      testRules(["@@https://a.com*$document",
                 "@@https://b.com^$document",
                 "@@https://c.com?$document",
                 "@@https://d.com/$document",
                 "@@https://e.com|$document"],
        [
          {
            id: 1,
            condition: {
              domains: ["a.com", "b.com", "c.com", "d.com", "e.com"]
            },
            action: {type: "allow"}
          }
        ]
      );
      testRules(["@@https://a.com*/$document",
                 "@@https://b.com^a$document",
                 "@@https://c.com?A$document",
                 "@@https://d.com/1$document",
                 "@@https://e.com|2$document"], []);
    });
  });

  describe("$genericblock exceptions", function()
  {
    it("should handle $genericblock exceptions", function()
    {
      testRules(
        ["^ad.jpg|", "@@||example.com^$genericblock"],
        [[undefined, ["example.com"]]],
        rules => rules.map(rule => [rule.condition["domains"],
                                    rule.condition["excludedDomains"]]));
      testRules(
        ["^ad.jpg|$domain=test.com", "@@||example.com^$genericblock"],
        [[["test.com"], undefined]],
        rules => rules.map(rule => [rule.condition["domains"],
                                    rule.condition["excludedDomains"]]));
      testRules(
        ["^ad.jpg|$domain=~test.com", "@@||example.com^$genericblock"],
        [[undefined, ["test.com", "example.com"]]],
        rules => rules.map(rule => [rule.condition["domains"],
                                    rule.condition["excludedDomains"]]));

      testRules(
        ["^ad.jpg|", "@@||example.com^$genericblock", "@@ad.jpg"],
        [[undefined, ["example.com"]], [undefined, undefined]],
        rules => rules.map(rule => [rule.condition["domains"],
                                    rule.condition["excludedDomains"]])
      );
    });
  });

  describe("Request type mapping", function()
  {
    it("should properly map request types", function()
    {
      testRules(
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
         ["csp_report", "other"],
         ["image"],
         ["ping", "script"],
         ["csp_report", "font", "media", "object", "other", "ping", "script",
          "stylesheet", "sub_frame", "websocket", "xmlhttprequest"]],
        rules => rules.map(
          rule =>
          {
            let resourceTypes = rule.condition.resourceTypes;
            return resourceTypes && resourceTypes.sort();
          }
        )
      );
    });
  });

  describe("Unsupported filters", function()
  {
    it("should ignore $sitekey filters", function()
    {
      testRules(["foo$sitekey=bar"], []);
    });

    it("should ignore element hiding filters", function()
    {
      testRules(["##.whatever"], []);
      testRules(["test.com##.whatever"], []);
    });

    it("should ignore element hiding exception filters", function()
    {
      testRules([
        "##.whatever",
        "test.com,anothertest.com###something",
        "@@||special.test.com^$elemhide",
        "@@||test.com^$generichide",
        "@@||anothertest.com^$elemhide",
        "@@^something^$elemhide",
        "@@^anything^$generichide"
      ], []);
    });

    it("should ignore WebRTC filters", function()
    {
      testRules(["foo$webrtc"], []);
    });

    it("should ignore filters for popup windows", function()
    {
      testRules(["bar$popup"], []);
    });

    it("should ignore filters which contain unicode characeters", function()
    {
      testRules(["$domain=🐈.cat"], []);
      testRules(["||🐈"], []);
      testRules(["🐈$domain=🐈.cat"], []);
      testRules(["🐈%F0%9F%90%88$domain=🐈.cat"], []);
    });

    it("should ignore filters with invalid filter options", function()
    {
      testRules(["||test.com$match_case"], []);
    });

    it("should ignore RegExp matching filters", function()
    {
      testRules(["/\\.foo\\.com/.*[a-zA-Z0-9]{4}/"], []);
    });

    it("should ignore filters containing extended CSS selectors", function()
    {
      testRules(
        ["test.com#?#.s-result-item:-abp-has(h5.s-sponsored-header)"], []
      );
    });

    it("should ignore snippet filters", function()
    {
      testRules(["test.com#$#abort-on-property-read atob"], []);
    });

    it("shouldn't do anything if there are no filters at all!", function()
    {
      testRules([], []);
    });
  });

  describe("Filter options", function()
  {
    it("should honour the $domain option", function()
    {
      testRules(["1$domain=foo.com"], ["foo.com"],
                rules => rules[0]["condition"]["domains"]);
    });
    it("should honour the $third-party option", function()
    {
      testRules(["2$third-party"], "thirdParty",
                rules => rules[0]["condition"]["domainType"]);
    });

    it("should honour the $match-case option", function()
    {
      testRules(["||test.com"], undefined,
                rules => rules[0]["condition"]["isUrlFilterCaseSensitive"]);
      testRules(["||test.com$match-case"], undefined,
                rules => rules[0]["condition"]["isUrlFilterCaseSensitive"]);
      testRules(["||test.com/foo"], false,
                rules => rules[0]["condition"]["isUrlFilterCaseSensitive"]);
      testRules(["||test.com/foo$match-case"], undefined,
                rules => rules[0]["condition"]["isUrlFilterCaseSensitive"]);
      testRules(["||test.com/Foo"], false,
                rules => rules[0]["condition"]["isUrlFilterCaseSensitive"]);
      testRules(["||test.com/Foo$match-case"], undefined,
                rules => rules[0]["condition"]["isUrlFilterCaseSensitive"]);
    });

    it("should unget advanced $domain and $match-case usage right", function()
    {
      testRules(
        ["/Foo$domain=Domain.com", "/Foo$match-case,domain=Domain.com",
         "||fOO.com", "||fOO.com$match-case",
         "||fOO.com/1", "||fOO.com/A", "||fOO.com/A$match-case"],
        [{urlFilter: "/foo",
          isUrlFilterCaseSensitive: false,
          domains: ["domain.com"]},
         {urlFilter: "/Foo", domains: ["domain.com"]},
         {urlFilter: "||foo.com"},
         {urlFilter: "||foo.com"},
         {urlFilter: "||foo.com/1"},
         {urlFilter: "||foo.com/a", isUrlFilterCaseSensitive: false},
         {urlFilter: "||foo.com/A"}
        ],
         rules => rules.map(rule => rule["condition"])
      );
    });

    it("should honour subdomain exceptions", function()
    {
      testRules(["1$domain=foo.com|~bar.foo.com"], [
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
    });
  });

  describe("Rewrite filters", function()
  {
    it("should generate redirection rules for abp-resources", function()
    {
      testRules(
        ["||bar.com/ad.js$script,domain=foo.com,rewrite=abp-resource:blank-js"],
        [
          {
            id: 1,
            priority: 1,
            condition: {
              urlFilter: "||bar.com/ad.js",
              isUrlFilterCaseSensitive: false,
              domains: ["foo.com"],
              resourceTypes: ["script"]
            },
            action: {
              type: "redirect",
              redirectUrl: "data:application/javascript,"
            }
          }
        ]
      );
    });

    it("should not generate any other redirection rules", function()
    {
      testRules(
        ["||foo.com/news.css$stylesheet,domain=foo.com,rewrite=foo.css"], []
      );

      testRules(["/(server.com/assets/file.php)?.*$/$rewrite=$1"], []);
      testRules(
        ["/(server.com/assets/file.php)?.*$/$rewrite=https://test.com"], []
      );
      testRules(["foo$rewrite=$1"], []);
      testRules(
        ["||example.com/ad.js$script,domain=foo.com,rewrite=abp-resource:foo"],
        []
      );
      testRules(["foo$rewrite=http://google.com"], []);
    });
  });

  describe("Web sockets", function()
  {
    it("should generate websocket blocking rules", function()
    {
      testRules(["foo$websocket"], [
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
    });
  });
});
