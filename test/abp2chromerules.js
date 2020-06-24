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
const {ChromeRules} = require("../lib/abp2chromerules.js");

function testRules(filters, expectedProcessReturn,
                   expected, transformFunction, ruleOffset,
                   checkValidRE2)
{
  let processReturn = [];
  let chromeRules;

  if (checkValidRE2)
    chromeRules = new ChromeRules(ruleOffset || 1, checkValidRE2);
  else if (ruleOffset)
    chromeRules = new ChromeRules(ruleOffset);
  else
    chromeRules = new ChromeRules();

  for (let filter of filters)
    processReturn.push(chromeRules.processFilter(Filter.fromText(filter)));

  assert.deepEqual(processReturn, expectedProcessReturn);

  let rules = chromeRules.generateRules(ruleOffset);
  if (transformFunction)
    rules = transformFunction(rules);
  assert.deepEqual(rules, expected);
}

describe("ChromeRules", function()
{
  describe("Request filters", function()
  {
    it("should generate request blocking rules", function()
    {
      testRules(["||example.com"], [[1]], [
        {
          id: 1,
          priority: 1,
          condition: {
            urlFilter: "||example.com"
          },
          action: {type: "block"}
        }
      ]);

      testRules([
        "/foo", "||test.com^", "http://example.com/foo", "^foo^"
      ], [[1], [2], [3], [4]], [
        {
          id: 1,
          priority: 1,
          condition: {
            urlFilter: "/foo",
            isUrlFilterCaseSensitive: false
          },
          action: {type: "block"}
        },
        {
          id: 2,
          priority: 1,
          condition: {
            urlFilter: "||test.com^"
          },
          action: {type: "block"}
        },
        {
          id: 3,
          priority: 1,
          condition: {
            urlFilter: "http://example.com/foo",
            isUrlFilterCaseSensitive: false
          },
          action: {type: "block"}
        },
        {
          id: 4,
          priority: 1,
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
      testRules(["foo$document", "||foo.com$document"], [false, false], []);
    });

    it("should strip redundant ||* prefix", function()
    {
      testRules(
        ["||*example.js$script"], [[1]], [
          {
            id: 1,
            priority: 1,
            condition: {
              urlFilter: "example.js",
              resourceTypes: ["script"],
              isUrlFilterCaseSensitive: false
            },
            action: {type: "block"}
          }
        ]
      );
    });

    it("should ignore regular expression filters by default", function()
    {
      testRules(["/\\.example\\.com/.*[a-z0-9]{4}/$script"], [false], []);
    });

    it("should handle regexp filters using checkValidRE2 function", function()
    {
      testRules(
        ["/\\.example\\.com/.*[a-z0-9]{4}/$script",
         "/Test/$match-case",
         "/(?!unsupported)/",
         "@@/Regexp/"], [[1], [2], false, [3]], [
          {
            id: 1,
            priority: 1,
            condition: {
              isUrlFilterCaseSensitive: false,
              regexFilter: "\\.example\\.com\\/.*[a-z0-9]{4}",
              resourceTypes: ["script"]
            },
            action: {
              type: "block"
            }
          },
          {
            id: 2,
            priority: 1,
            condition: {
              regexFilter: "Test"
            },
            action: {
              type: "block"
            }
          },
          {
            id: 3,
            priority: 1,
            condition: {
              isUrlFilterCaseSensitive: false,
              regexFilter: "regexp"
            },
            action: {
              type: "allow"
            }
          }
         ],
         rules => rules,
         null,
         regexp => !regexp.includes("(?")
      );
    });
  });

  describe("Request allowlisting filters", function()
  {
    it("should generate case-insensitive allowlisting filters", function()
    {
      testRules(["@@example.com"], [[1]], [
        {
          id: 1,
          priority: 1,
          condition: {
            urlFilter: "example.com",
            isUrlFilterCaseSensitive: false
          },
          action: {type: "allow"}
        }
      ]);
    });

    it("should generate case sensitive allowlisting filters", function()
    {
      testRules(["@@||example.com"], [[1]], [
        {
          id: 1,
          priority: 1,
          condition: {
            urlFilter: "||example.com"
          },
          action: {type: "allow"}
        }
      ]);
    });

    it("should only include urlFilter where appropriate", function()
    {
      testRules(
        ["@@||example.com", "@@$media,domain=example.com"],
        [[1], [2]],
        ["||example.com", undefined],
        rules => rules.map(rule => rule.condition.urlFilter)
      );
    });

    it("should strip redundant ||* prefix", function()
    {
      testRules(
        ["@@||*example.js$script"], [[1]], [
          {
            id: 1,
            priority: 1,
            condition: {
              urlFilter: "example.js",
              resourceTypes: ["script"],
              isUrlFilterCaseSensitive: false
            },
            action: {type: "allow"}
          }
        ]
      );
    });
  });

  describe("Domain allowlisting", function()
  {
    it("should generate domain allowlisting rules", function()
    {
      testRules(["@@||example.com^$document"], [[1]], [
        {
          id: 1,
          priority: 1,
          condition: {
            urlFilter: "||example.com^",
            resourceTypes: ["main_frame"]
          },
          action: {type: "allowAllRequests"}
        }
      ]);
      testRules(["@@||example.com^$document,image"], [[1, 2]], [
        {
          id: 1,
          priority: 1,
          condition: {
            urlFilter: "||example.com^",
            resourceTypes: ["main_frame"]
          },
          action: {type: "allowAllRequests"}
        },
        {
          id: 2,
          priority: 1,
          condition: {
            urlFilter: "||example.com^",
            resourceTypes: ["image"]
          },
          action: {type: "allow"}
        }
      ]);
      testRules(
        ["@@||bar.com^$document,image", "@@||foo.com^$document"],
        [[1, 2], [3]], [
          {
            id: 1,
            priority: 1,
            condition: {
              urlFilter: "||bar.com^",
              resourceTypes: ["main_frame"]
            },
            action: {type: "allowAllRequests"}
          },
          {
            id: 2,
            priority: 1,
            condition: {
              urlFilter: "||bar.com^",
              resourceTypes: ["image"]
            },
            action: {type: "allow"}
          },
          {
            id: 3,
            priority: 1,
            condition: {
              urlFilter: "||foo.com^",
              resourceTypes: ["main_frame"]
            },
            action: {type: "allowAllRequests"}
          }
        ]
      );
    });

    it("should generate allowlisting rules for URLs", function()
    {
      testRules(["@@||example.com/path^$font"], [[1]], [
        {
          id: 1,
          priority: 1,
          condition: {
            urlFilter: "||example.com/path^",
            isUrlFilterCaseSensitive: false,
            resourceTypes: ["font"]
          },
          action: {type: "allow"}
        }
      ]);
    });

    it("should generate allowAllRequest allowlisting rules", function()
    {
      testRules(["@@||example.com/path$document"], [[1]], [
        {
          id: 1,
          priority: 1,
          condition: {
            urlFilter: "||example.com/path",
            isUrlFilterCaseSensitive: false,
            resourceTypes: ["main_frame"]
          },
          action: {type: "allowAllRequests"}
        }
      ]);

      testRules(["@@||example.com/path$subdocument"], [[1]], [
        {
          id: 1,
          priority: 1,
          condition: {
            urlFilter: "||example.com/path",
            isUrlFilterCaseSensitive: false,
            resourceTypes: ["sub_frame"]
          },
          action: {type: "allow"}
        }
      ]);

      testRules(["@@||example.com/path$document,subdocument"], [[1]], [
        {
          id: 1,
          priority: 1,
          condition: {
            urlFilter: "||example.com/path",
            isUrlFilterCaseSensitive: false,
            resourceTypes: ["main_frame", "sub_frame"]
          },
          action: {type: "allowAllRequests"}
        }
      ]);

      testRules(["@@||example.com$document,subdocument"], [[1]], [
        {
          id: 1,
          priority: 1,
          condition: {
            urlFilter: "||example.com",
            resourceTypes: ["main_frame", "sub_frame"]
          },
          action: {type: "allowAllRequests"}
        }
      ]);

      testRules(["@@||example.com"], [[1]], [
        {
          id: 1,
          priority: 1,
          condition: {
            urlFilter: "||example.com"
          },
          action: {type: "allow"}
        }
      ]);

      testRules(["@@||example.com/path"], [[1]], [
        {
          id: 1,
          priority: 1,
          condition: {
            urlFilter: "||example.com/path",
            isUrlFilterCaseSensitive: false
          },
          action: {type: "allow"}
        }
      ]);
    });

    it("should allowlist domains correctly", function()
    {
      testRules(["@@https://a.com$document",
                 "@@https://b.com$document",
                 "@@https://c.com$document",
                 "@@https://d.com$document",
                 "@@https://e.com$document"],
                [[1], [2], [3], [4], [5]],
        [
          {
            id: 1,
            priority: 1,
            condition: {
              urlFilter: "https://a.com",
              resourceTypes: ["main_frame"]
            },
            action: {type: "allowAllRequests"}
          },
          {
            id: 2,
            priority: 1,
            condition: {
              urlFilter: "https://b.com",
              resourceTypes: ["main_frame"]
            },
            action: {type: "allowAllRequests"}
          },
          {
            id: 3,
            priority: 1,
            condition: {
              urlFilter: "https://c.com",
              resourceTypes: ["main_frame"]
            },
            action: {type: "allowAllRequests"}
          },
          {
            id: 4,
            priority: 1,
            condition: {
              urlFilter: "https://d.com",
              resourceTypes: ["main_frame"]
            },
            action: {type: "allowAllRequests"}
          },
          {
            id: 5,
            priority: 1,
            condition: {
              urlFilter: "https://e.com",
              resourceTypes: ["main_frame"]
            },
            action: {type: "allowAllRequests"}
          }
        ]
      );
      testRules(["@@https://a.com*$document",
                 "@@https://b.com^$document",
                 "@@https://c.com?$document",
                 "@@https://d.com/$document",
                 "@@https://e.com|$document"],
                [[1], [2], [3], [4], [5]],
        [
          {
            id: 1,
            priority: 1,
            condition: {
              urlFilter: "https://a.com",
              resourceTypes: ["main_frame"]
            },
            action: {type: "allowAllRequests"}
          },
          {
            id: 2,
            priority: 1,
            condition: {
              urlFilter: "https://b.com^",
              resourceTypes: ["main_frame"]
            },
            action: {type: "allowAllRequests"}
          },
          {
            id: 3,
            priority: 1,
            condition: {
              urlFilter: "https://c.com?",
              resourceTypes: ["main_frame"]
            },
            action: {type: "allowAllRequests"}
          },
          {
            id: 4,
            priority: 1,
            condition: {
              urlFilter: "https://d.com/",
              resourceTypes: ["main_frame"]
            },
            action: {type: "allowAllRequests"}
          },
          {
            id: 5,
            priority: 1,
            condition: {
              urlFilter: "https://e.com|",
              resourceTypes: ["main_frame"]
            },
            action: {type: "allowAllRequests"}
          }
        ]
      );
      testRules(
        ["@@https://a.com*/$document", "@@https://b.com^a$document",
         "@@https://c.com?A$document", "@@https://d.com/1$document",
         "@@https://e.com|2$document"],
         [[1], [2], [3], [4], [5]],
        [
          {
            id: 1,
            priority: 1,
            condition: {
              urlFilter: "https://a.com*/",
              resourceTypes: ["main_frame"]
            },
            action: {type: "allowAllRequests"}
          },
          {
            id: 2,
            priority: 1,
            condition: {
              urlFilter: "https://b.com^a",
              resourceTypes: ["main_frame"],
              isUrlFilterCaseSensitive: false
            },
            action: {type: "allowAllRequests"}
          },
          {
            id: 3,
            priority: 1,
            condition: {
              urlFilter: "https://c.com?a",
              resourceTypes: ["main_frame"],
              isUrlFilterCaseSensitive: false
            },
            action: {type: "allowAllRequests"}
          },
          {
            id: 4,
            priority: 1,
            condition: {
              urlFilter: "https://d.com/1",
              resourceTypes: ["main_frame"]
            },
            action: {type: "allowAllRequests"}
          },
          {
            id: 5,
            priority: 1,
            condition: {
              urlFilter: "https://e.com|2",
              resourceTypes: ["main_frame"]
            },
            action: {type: "allowAllRequests"}
          }
        ]
      );
    });
  });

  describe("$genericblock exceptions", function()
  {
    it("should handle $genericblock exceptions", function()
    {
      testRules(
        ["^ad.jpg|", "@@||example.com^$genericblock"],
        [[1], true],
        [[undefined, ["example.com"]]],
        rules => rules.map(rule => [rule.condition["domains"],
                                    rule.condition["excludedDomains"]]));
      testRules(
        ["^ad.jpg|$domain=test.com", "@@||example.com^$genericblock"],
        [[1], true],
        [[["test.com"], undefined]],
        rules => rules.map(rule => [rule.condition["domains"],
                                    rule.condition["excludedDomains"]]));
      testRules(
        ["^ad.jpg|$domain=~test.com", "@@||example.com^$genericblock"],
        [[1], true],
        [[undefined, ["test.com", "example.com"]]],
        rules => rules.map(rule => [rule.condition["domains"],
                                    rule.condition["excludedDomains"]]));

      testRules(
        ["^ad.jpg|", "@@||example.com^$genericblock", "@@ad.jpg$image"],
        [[1], true, [2]],
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
        [[1], [2], [3], [4], [5], [6], [7], [8],
         [9], [10], [11], [12], [13], [14], [15], [16]],
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
    it("should ignore comment filters", function()
    {
      testRules(["! this is a comment"], [false], []);
    });

    it("should ignore $sitekey filters", function()
    {
      testRules(["foo$sitekey=bar"], [false], []);
    });

    it("should ignore element hiding filters", function()
    {
      testRules(["##.whatever"], [false], []);
      testRules(["test.com##.whatever"], [false], []);
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
      ], [false, false, false, false, false, false, false], []);
    });

    it("should ignore WebRTC filters", function()
    {
      testRules(["foo$webrtc"], [false], []);
    });

    it("should ignore filters for popup windows", function()
    {
      testRules(["bar$popup"], [false], []);
    });

    it("should ignore filters which contain unicode characeters", function()
    {
      testRules(["$domain=🐈.cat"], [false], []);
      testRules(["||🐈"], [false], []);
      testRules(["🐈$domain=🐈.cat"], [false], []);
      testRules(["🐈%F0%9F%90%88$domain=🐈.cat"], [false], []);
    });

    it("should ignore filters with invalid filter options", function()
    {
      testRules(["||test.com$match_case"], [false], []);
    });

    it("should ignore filters containing extended CSS selectors", function()
    {
      testRules(
        ["test.com#?#.s-result-item:-abp-has(h5.s-sponsored-header)"],
        [false], []
      );
    });

    it("should ignore snippet filters", function()
    {
      testRules(["test.com#$#abort-on-property-read atob"], [false], []);
    });

    it("shouldn't do anything if there are no filters at all!", function()
    {
      testRules([], [], []);
    });
  });

  describe("Filter options", function()
  {
    it("should honour the $domain option", function()
    {
      testRules(["1$domain=foo.com"], [[1]], ["foo.com"],
                rules => rules[0]["condition"]["domains"]);
    });
    it("should honour the $third-party option", function()
    {
      testRules(["2$third-party"], [[1]], "thirdParty",
                rules => rules[0]["condition"]["domainType"]);
    });

    it("should honour the $match-case option", function()
    {
      testRules(["||test.com"], [[1]], undefined,
                rules => rules[0]["condition"]["isUrlFilterCaseSensitive"]);
      testRules(["||test.com$match-case"], [[1]], undefined,
                rules => rules[0]["condition"]["isUrlFilterCaseSensitive"]);
      testRules(["||test.com/foo"], [[1]], false,
                rules => rules[0]["condition"]["isUrlFilterCaseSensitive"]);
      testRules(["||test.com/foo$match-case"], [[1]], undefined,
                rules => rules[0]["condition"]["isUrlFilterCaseSensitive"]);
      testRules(["||test.com/Foo"], [[1]], false,
                rules => rules[0]["condition"]["isUrlFilterCaseSensitive"]);
      testRules(["||test.com/Foo$match-case"], [[1]], undefined,
                rules => rules[0]["condition"]["isUrlFilterCaseSensitive"]);
    });

    it("should get advanced $domain and $match-case usage right", function()
    {
      testRules(
        ["/Foo$domain=Domain.com", "/Foo$match-case,domain=Domain.com",
         "||fOO.com", "||fOO.com$match-case",
         "||fOO.com/1", "||fOO.com/A", "||fOO.com/A$match-case"],
        [[1], [2], [3], [4], [5], [6], [7]],
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
      testRules(["1$domain=foo.com|~bar.foo.com"], [[1]], [
        {
          id: 1,
          priority: 1,
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
        [[1]],
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
              redirect: {url: "data:application/javascript,"}
            }
          }
        ]
      );
    });

    it("should not generate any other redirection rules", function()
    {
      testRules(
        ["||foo.com/news.css$stylesheet,domain=foo.com,rewrite=foo.css"],
        [false], []
      );
      testRules(
        ["/(server.com/assets/file.php)?.*$/$rewrite=$1"],
        [false], []
      );
      testRules(
        ["/(server.com/assets/file.php)?.*$/$rewrite=https://test.com"],
        [false], []
      );
      testRules(
        ["foo$rewrite=$1"],
        [false], []
      );
      testRules(
        ["||example.com/ad.js$script,domain=foo.com,rewrite=abp-resource:foo"],
        [false], []
      );
      testRules(
        ["foo$rewrite=http://google.com"],
        [false], []
      );
    });
  });

  describe("Web sockets", function()
  {
    it("should generate websocket blocking rules", function()
    {
      testRules(["foo$websocket"], [[1]], [
        {
          id: 1,
          priority: 1,
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

  describe("Rule offset", function()
  {
    let filters = ["||example.com", "||foo.com"];
    let getIds = rules => rules.map(rule => rule.id);

    it("should honour the firstId parameter", function()
    {
      testRules(filters, [[1], [2]], [1, 2], getIds);
      testRules(filters, [[1], [2]], [1, 2], getIds, 1);
      testRules(filters, [[2], [3]], [2, 3], getIds, 2);
      testRules(filters, [[1000], [1001]], [1000, 1001], getIds, 1000);
    });
  });
});
