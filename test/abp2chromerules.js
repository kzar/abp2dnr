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
const {ChromeRules,
       STANDARD_PRIORITY,
       CSP_PRIORITY,
       ALLOW_ALL_REQUESTS_PRIORITY} = require("../lib/abp2chromerules.js");

async function testRules(filters, expectedProcessReturn,
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
  {
    processReturn.push(
      await chromeRules.processFilter(Filter.fromText(filter))
    );
  }

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
    it("should generate request blocking rules", async () =>
    {
      await testRules(["||example.com"], [[1]], [
        {
          id: 1,
          priority: STANDARD_PRIORITY,
          condition: {
            urlFilter: "||example.com"
          },
          action: {type: "block"}
        }
      ]);

      await testRules([
        "/foo", "||test.com^", "http://example.com/foo", "^foo^"
      ], [[1], [2], [3], [4]], [
        {
          id: 1,
          priority: STANDARD_PRIORITY,
          condition: {
            urlFilter: "/foo",
            isUrlFilterCaseSensitive: false
          },
          action: {type: "block"}
        },
        {
          id: 2,
          priority: STANDARD_PRIORITY,
          condition: {
            urlFilter: "||test.com^"
          },
          action: {type: "block"}
        },
        {
          id: 3,
          priority: STANDARD_PRIORITY,
          condition: {
            urlFilter: "http://example.com/foo",
            isUrlFilterCaseSensitive: false
          },
          action: {type: "block"}
        },
        {
          id: 4,
          priority: STANDARD_PRIORITY,
          condition: {
            urlFilter: "^foo^",
            isUrlFilterCaseSensitive: false
          },
          action: {type: "block"}
        }
      ]);
    });

    it("shouldn't generate blocking rules matching no request type", async () =>
    {
      await testRules(
        ["foo$document", "||foo.com$document"], [false, false], []
      );
    });

    it("should strip redundant ||* prefix", async () =>
    {
      await testRules(
        ["||*example.js$script"], [[1]], [
          {
            id: 1,
            priority: STANDARD_PRIORITY,
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

    it("should ignore regular expression filters by default", async () =>
    {
      await testRules(["/\\.example\\.com/.*[a-z0-9]{4}/$script"], [false], []);
    });

    it("should handle regexp filters using isSupportedRegex", async () =>
    {
      await testRules(
        ["/\\.example\\.com/.*[a-z0-9]{4}/$script",
         "/Test/$match-case",
         "/(?!unsupported)/",
         "@@/Regexp/"], [[1], [2], false, [3]], [
          {
            id: 1,
            priority: STANDARD_PRIORITY,
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
            priority: STANDARD_PRIORITY,
            condition: {
              regexFilter: "Test"
            },
            action: {
              type: "block"
            }
          },
          {
            id: 3,
            priority: STANDARD_PRIORITY,
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
         ({regex}) => ({isSupported: !regex.includes("(?")})
      );
    });
  });

  describe("Request allowlisting filters", function()
  {
    it("should generate case-insensitive allowlisting filters", async () =>
    {
      await testRules(["@@example.com"], [[1]], [
        {
          id: 1,
          priority: STANDARD_PRIORITY,
          condition: {
            urlFilter: "example.com",
            isUrlFilterCaseSensitive: false
          },
          action: {type: "allow"}
        }
      ]);
    });

    it("should generate case sensitive allowlisting filters", async () =>
    {
      await testRules(["@@||example.com"], [[1]], [
        {
          id: 1,
          priority: STANDARD_PRIORITY,
          condition: {
            urlFilter: "||example.com"
          },
          action: {type: "allow"}
        }
      ]);
    });

    it("should only include urlFilter where appropriate", async () =>
    {
      await testRules(
        ["@@||example.com", "@@$media,domain=example.com"],
        [[1], [2]],
        ["||example.com", undefined],
        rules => rules.map(rule => rule.condition.urlFilter)
      );
    });

    it("should strip redundant ||* prefix", async () =>
    {
      await testRules(
        ["@@||*example.js$script"], [[1]], [
          {
            id: 1,
            priority: STANDARD_PRIORITY,
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
    it("should generate domain allowlisting rules", async () =>
    {
      await testRules(["@@||example.com^$document"], [[1]], [
        {
          id: 1,
          priority: ALLOW_ALL_REQUESTS_PRIORITY,
          condition: {
            urlFilter: "||example.com^",
            resourceTypes: ["main_frame", "sub_frame"]
          },
          action: {type: "allowAllRequests"}
        }
      ]);
      await testRules(["@@||example.com^$document,image"], [[1, 2]], [
        {
          id: 1,
          priority: ALLOW_ALL_REQUESTS_PRIORITY,
          condition: {
            urlFilter: "||example.com^",
            resourceTypes: ["main_frame", "sub_frame"]
          },
          action: {type: "allowAllRequests"}
        },
        {
          id: 2,
          priority: STANDARD_PRIORITY,
          condition: {
            urlFilter: "||example.com^",
            resourceTypes: ["image"]
          },
          action: {type: "allow"}
        }
      ]);
      await testRules(
        ["@@||bar.com^$document,image", "@@||foo.com^$document"],
        [[1, 2], [3]], [
          {
            id: 1,
            priority: ALLOW_ALL_REQUESTS_PRIORITY,
            condition: {
              urlFilter: "||bar.com^",
              resourceTypes: ["main_frame", "sub_frame"]
            },
            action: {type: "allowAllRequests"}
          },
          {
            id: 2,
            priority: STANDARD_PRIORITY,
            condition: {
              urlFilter: "||bar.com^",
              resourceTypes: ["image"]
            },
            action: {type: "allow"}
          },
          {
            id: 3,
            priority: ALLOW_ALL_REQUESTS_PRIORITY,
            condition: {
              urlFilter: "||foo.com^",
              resourceTypes: ["main_frame", "sub_frame"]
            },
            action: {type: "allowAllRequests"}
          }
        ]
      );
    });

    it("should generate allowlisting rules for URLs", async () =>
    {
      await testRules(["@@||example.com/path^$font"], [[1]], [
        {
          id: 1,
          priority: STANDARD_PRIORITY,
          condition: {
            urlFilter: "||example.com/path^",
            isUrlFilterCaseSensitive: false,
            resourceTypes: ["font"]
          },
          action: {type: "allow"}
        }
      ]);
    });

    it("should generate allowAllRequest allowlisting rules", async () =>
    {
      await testRules(["@@||example.com/path$document"], [[1]], [
        {
          id: 1,
          priority: ALLOW_ALL_REQUESTS_PRIORITY,
          condition: {
            urlFilter: "||example.com/path",
            isUrlFilterCaseSensitive: false,
            resourceTypes: ["main_frame", "sub_frame"]
          },
          action: {type: "allowAllRequests"}
        }
      ]);

      await testRules(["@@||example.com/path$subdocument"], [[1]], [
        {
          id: 1,
          priority: STANDARD_PRIORITY,
          condition: {
            urlFilter: "||example.com/path",
            isUrlFilterCaseSensitive: false,
            resourceTypes: ["sub_frame"]
          },
          action: {type: "allow"}
        }
      ]);

      await testRules(["@@||example.com/path$document,subdocument"], [[1]], [
        {
          id: 1,
          priority: ALLOW_ALL_REQUESTS_PRIORITY,
          condition: {
            urlFilter: "||example.com/path",
            isUrlFilterCaseSensitive: false,
            resourceTypes: ["main_frame", "sub_frame"]
          },
          action: {type: "allowAllRequests"}
        }
      ]);

      await testRules(["@@||example.com$document,subdocument"], [[1]], [
        {
          id: 1,
          priority: ALLOW_ALL_REQUESTS_PRIORITY,
          condition: {
            urlFilter: "||example.com",
            resourceTypes: ["main_frame", "sub_frame"]
          },
          action: {type: "allowAllRequests"}
        }
      ]);

      await testRules(["@@||example.com"], [[1]], [
        {
          id: 1,
          priority: STANDARD_PRIORITY,
          condition: {
            urlFilter: "||example.com"
          },
          action: {type: "allow"}
        }
      ]);

      await testRules(["@@||example.com/path"], [[1]], [
        {
          id: 1,
          priority: STANDARD_PRIORITY,
          condition: {
            urlFilter: "||example.com/path",
            isUrlFilterCaseSensitive: false
          },
          action: {type: "allow"}
        }
      ]);
    });

    it("should allowlist domains correctly", async () =>
    {
      await testRules(["@@https://a.com$document",
                       "@@https://b.com$document",
                       "@@https://c.com$document",
                       "@@https://d.com$document",
                       "@@https://e.com$document"],
                       [[1], [2], [3], [4], [5]],
        [
          {
            id: 1,
            priority: ALLOW_ALL_REQUESTS_PRIORITY,
            condition: {
              urlFilter: "https://a.com",
              resourceTypes: ["main_frame", "sub_frame"]
            },
            action: {type: "allowAllRequests"}
          },
          {
            id: 2,
            priority: ALLOW_ALL_REQUESTS_PRIORITY,
            condition: {
              urlFilter: "https://b.com",
              resourceTypes: ["main_frame", "sub_frame"]
            },
            action: {type: "allowAllRequests"}
          },
          {
            id: 3,
            priority: ALLOW_ALL_REQUESTS_PRIORITY,
            condition: {
              urlFilter: "https://c.com",
              resourceTypes: ["main_frame", "sub_frame"]
            },
            action: {type: "allowAllRequests"}
          },
          {
            id: 4,
            priority: ALLOW_ALL_REQUESTS_PRIORITY,
            condition: {
              urlFilter: "https://d.com",
              resourceTypes: ["main_frame", "sub_frame"]
            },
            action: {type: "allowAllRequests"}
          },
          {
            id: 5,
            priority: ALLOW_ALL_REQUESTS_PRIORITY,
            condition: {
              urlFilter: "https://e.com",
              resourceTypes: ["main_frame", "sub_frame"]
            },
            action: {type: "allowAllRequests"}
          }
        ]
      );
      await testRules(["@@https://a.com*$document",
                       "@@https://b.com^$document",
                       "@@https://c.com?$document",
                       "@@https://d.com/$document",
                       "@@https://e.com|$document"],
                       [[1], [2], [3], [4], [5]],
        [
          {
            id: 1,
            priority: ALLOW_ALL_REQUESTS_PRIORITY,
            condition: {
              urlFilter: "https://a.com",
              resourceTypes: ["main_frame", "sub_frame"]
            },
            action: {type: "allowAllRequests"}
          },
          {
            id: 2,
            priority: ALLOW_ALL_REQUESTS_PRIORITY,
            condition: {
              urlFilter: "https://b.com^",
              resourceTypes: ["main_frame", "sub_frame"]
            },
            action: {type: "allowAllRequests"}
          },
          {
            id: 3,
            priority: ALLOW_ALL_REQUESTS_PRIORITY,
            condition: {
              urlFilter: "https://c.com?",
              resourceTypes: ["main_frame", "sub_frame"]
            },
            action: {type: "allowAllRequests"}
          },
          {
            id: 4,
            priority: ALLOW_ALL_REQUESTS_PRIORITY,
            condition: {
              urlFilter: "https://d.com/",
              resourceTypes: ["main_frame", "sub_frame"]
            },
            action: {type: "allowAllRequests"}
          },
          {
            id: 5,
            priority: ALLOW_ALL_REQUESTS_PRIORITY,
            condition: {
              urlFilter: "https://e.com|",
              resourceTypes: ["main_frame", "sub_frame"]
            },
            action: {type: "allowAllRequests"}
          }
        ]
      );
      await testRules(
        ["@@https://a.com*/$document", "@@https://b.com^a$document",
         "@@https://c.com?A$document", "@@https://d.com/1$document",
         "@@https://e.com|2$document"],
         [[1], [2], [3], [4], [5]],
        [
          {
            id: 1,
            priority: ALLOW_ALL_REQUESTS_PRIORITY,
            condition: {
              urlFilter: "https://a.com*/",
              resourceTypes: ["main_frame", "sub_frame"]
            },
            action: {type: "allowAllRequests"}
          },
          {
            id: 2,
            priority: ALLOW_ALL_REQUESTS_PRIORITY,
            condition: {
              urlFilter: "https://b.com^a",
              resourceTypes: ["main_frame", "sub_frame"],
              isUrlFilterCaseSensitive: false
            },
            action: {type: "allowAllRequests"}
          },
          {
            id: 3,
            priority: ALLOW_ALL_REQUESTS_PRIORITY,
            condition: {
              urlFilter: "https://c.com?a",
              resourceTypes: ["main_frame", "sub_frame"],
              isUrlFilterCaseSensitive: false
            },
            action: {type: "allowAllRequests"}
          },
          {
            id: 4,
            priority: ALLOW_ALL_REQUESTS_PRIORITY,
            condition: {
              urlFilter: "https://d.com/1",
              resourceTypes: ["main_frame", "sub_frame"]
            },
            action: {type: "allowAllRequests"}
          },
          {
            id: 5,
            priority: ALLOW_ALL_REQUESTS_PRIORITY,
            condition: {
              urlFilter: "https://e.com|2",
              resourceTypes: ["main_frame", "sub_frame"]
            },
            action: {type: "allowAllRequests"}
          }
        ]
      );
    });
  });

  describe("$genericblock exceptions", function()
  {
    it("should handle $genericblock exceptions", async () =>
    {
      await testRules(
        ["^ad.jpg|", "@@||example.com^$genericblock"],
        [[1], true],
        [[undefined, ["example.com"]]],
        rules => rules.map(rule => [rule.condition["domains"],
                                    rule.condition["excludedDomains"]]));
      await testRules(
        ["^ad.jpg|$domain=test.com", "@@||example.com^$genericblock"],
        [[1], true],
        [[["test.com"], undefined]],
        rules => rules.map(rule => [rule.condition["domains"],
                                    rule.condition["excludedDomains"]]));
      await testRules(
        ["^ad.jpg|$domain=~test.com", "@@||example.com^$genericblock"],
        [[1], true],
        [[undefined, ["test.com", "example.com"]]],
        rules => rules.map(rule => [rule.condition["domains"],
                                    rule.condition["excludedDomains"]]));

      await testRules(
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
    it("should properly map request types", async () =>
    {
      await testRules(
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
    it("should ignore comment filters", async () =>
    {
      await testRules(["! this is a comment"], [false], []);
    });

    it("should ignore $sitekey filters", async () =>
    {
      await testRules(["foo$sitekey=bar"], [false], []);
    });

    it("should ignore element hiding filters", async () =>
    {
      await testRules(["##.whatever"], [false], []);
      await testRules(["test.com##.whatever"], [false], []);
    });

    it("should ignore element hiding exception filters", async () =>
    {
      await testRules([
        "##.whatever",
        "test.com,anothertest.com###something",
        "@@||special.test.com^$elemhide",
        "@@||test.com^$generichide",
        "@@||anothertest.com^$elemhide",
        "@@^something^$elemhide",
        "@@^anything^$generichide"
      ], [false, false, false, false, false, false, false], []);
    });

    it("should ignore WebRTC filters", async () =>
    {
      await testRules(["foo$webrtc"], [false], []);
    });

    it("should ignore filters for popup windows", async () =>
    {
      await testRules(["bar$popup"], [false], []);
    });

    it("should ignore filters which contain unicode characeters", async () =>
    {
      await testRules(["$domain=🐈.cat"], [false], []);
      await testRules(["||🐈"], [false], []);
      await testRules(["🐈$domain=🐈.cat"], [false], []);
      await testRules(["🐈%F0%9F%90%88$domain=🐈.cat"], [false], []);
    });

    it("should ignore filters with invalid filter options", async () =>
    {
      await testRules(["||test.com$match_case"], [false], []);
    });

    it("should ignore filters containing extended CSS selectors", async () =>
    {
      await testRules(
        ["test.com#?#.s-result-item:-abp-has(h5.s-sponsored-header)"],
        [false], []
      );
    });

    it("should ignore snippet filters", async () =>
    {
      await testRules(["test.com#$#abort-on-property-read atob"], [false], []);
    });

    it("shouldn't do anything if there are no filters at all!", async () =>
    {
      await testRules([], [], []);
    });
  });

  describe("Filter options", function()
  {
    it("should honour the $domain option", async () =>
    {
      await testRules(["1$domain=foo.com"], [[1]], ["foo.com"],
                rules => rules[0]["condition"]["domains"]);
    });
    it("should honour the $third-party option", async () =>
    {
      await testRules(["2$third-party"], [[1]], "thirdParty",
                rules => rules[0]["condition"]["domainType"]);
    });

    it("should honour the $match-case option", async () =>
    {
      await testRules(["||test.com"], [[1]], undefined,
                rules => rules[0]["condition"]["isUrlFilterCaseSensitive"]);
      await testRules(["||test.com$match-case"], [[1]], undefined,
                rules => rules[0]["condition"]["isUrlFilterCaseSensitive"]);
      await testRules(["||test.com/foo"], [[1]], false,
                rules => rules[0]["condition"]["isUrlFilterCaseSensitive"]);
      await testRules(["||test.com/foo$match-case"], [[1]], undefined,
                rules => rules[0]["condition"]["isUrlFilterCaseSensitive"]);
      await testRules(["||test.com/Foo"], [[1]], false,
                rules => rules[0]["condition"]["isUrlFilterCaseSensitive"]);
      await testRules(["||test.com/Foo$match-case"], [[1]], undefined,
                rules => rules[0]["condition"]["isUrlFilterCaseSensitive"]);
    });

    it("should get advanced $domain and $match-case usage right", async () =>
    {
      await testRules(
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

    it("should honour subdomain exceptions", async () =>
    {
      await testRules(["1$domain=foo.com|~bar.foo.com"], [[1]], [
        {
          id: 1,
          priority: STANDARD_PRIORITY,
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
    it("should generate redirection rules for abp-resources", async () =>
    {
      await testRules(
        ["||bar.com/ad.js$script,domain=foo.com,rewrite=abp-resource:blank-js"],
        [[1]],
        [
          {
            id: 1,
            priority: STANDARD_PRIORITY,
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

    it("should not generate any other redirection rules", async () =>
    {
      await testRules(
        ["||foo.com/news.css$stylesheet,domain=foo.com,rewrite=foo.css"],
        [false], []
      );
      await testRules(
        ["/(server.com/assets/file.php)?.*$/$rewrite=$1"],
        [false], []
      );
      await testRules(
        ["/(server.com/assets/file.php)?.*$/$rewrite=https://test.com"],
        [false], []
      );
      await testRules(
        ["foo$rewrite=$1"],
        [false], []
      );
      await testRules(
        ["||example.com/ad.js$script,domain=foo.com,rewrite=abp-resource:foo"],
        [false], []
      );
      await testRules(
        ["foo$rewrite=http://google.com"],
        [false], []
      );
    });
  });

  describe("Web sockets", function()
  {
    it("should generate websocket blocking rules", async () =>
    {
      await testRules(["foo$websocket"], [[1]], [
        {
          id: 1,
          priority: STANDARD_PRIORITY,
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

  describe("CSP filters", function()
  {
    it("should generate modifyHeader/allow rules for CSP " +
       "filters", async () =>
    {
      await testRules(["foo$csp=img-src 'none'"], [[1]], [
        {
          id: 1,
          priority: CSP_PRIORITY,
          condition: {
            urlFilter: "foo",
            resourceTypes: ["main_frame", "sub_frame"],
            isUrlFilterCaseSensitive: false
          },
          action: {
            type: "modifyHeaders",
            responseHeaders: [{
              header: "Content-Security-Policy",
              operation: "append",
              value: "img-src 'none'"
            }]
          }
        }
      ]);

      await testRules(["@@||testpages.adblockplus.org^$csp"], [[1]], [
        {
          id: 1,
          priority: CSP_PRIORITY,
          condition: {
            urlFilter: "||testpages.adblockplus.org^",
            resourceTypes: ["main_frame", "sub_frame"]
          },
          action: {
            type: "allow"
          }
        }
      ]);
    });
  });

  describe("Rule offset", function()
  {
    let filters = ["||example.com", "||foo.com"];
    let getIds = rules => rules.map(rule => rule.id);

    it("should honour the firstId parameter", async () =>
    {
      await testRules(filters, [[1], [2]], [1, 2], getIds);
      await testRules(filters, [[1], [2]], [1, 2], getIds, 1);
      await testRules(filters, [[2], [3]], [2, 3], getIds, 2);
      await testRules(filters, [[1000], [1001]], [1000, 1001], getIds, 1000);
    });
  });
});
