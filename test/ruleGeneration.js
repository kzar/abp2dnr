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
const {convertFilter,
       compressRules,
       GENERIC_PRIORITY,
       GENERIC_ALLOW_ALL_PRIORITY,
       SPECIFIC_PRIORITY,
       SPECIFIC_ALLOW_ALL_PRIORITY} = require("../lib/abp2dnr.js");

async function testRules(filters, expected, transformRulesetFunction,
                         transformRuleFunction, isRegexSupported)
{
  let rules = [];

  for (let filter of filters)
  {
    for (let rule of await convertFilter(Filter.fromText(filter),
                                         isRegexSupported))
    {
      rules.push(rule);
    }
  }

  if (transformRulesetFunction)
    rules = transformRulesetFunction(rules);

  if (transformRuleFunction)
    rules = rules.map(transformRuleFunction);

  assert.deepEqual(rules, expected);
}

describe("Rule generation", function()
{
  describe("Priorities", function()
  {
    it("should have priorities correct relative to each other", () =>
    {
      assert.ok(GENERIC_PRIORITY > 0);
      assert.ok(GENERIC_PRIORITY < GENERIC_ALLOW_ALL_PRIORITY);
      assert.ok(GENERIC_ALLOW_ALL_PRIORITY < SPECIFIC_PRIORITY);
      assert.ok(SPECIFIC_PRIORITY < SPECIFIC_ALLOW_ALL_PRIORITY);
    });
  });

  describe("Request filters", function()
  {
    it("should generate request blocking rules", async () =>
    {
      await testRules(["||example.com"], [
        {
          priority: GENERIC_PRIORITY,
          condition: {
            urlFilter: "||example.com"
          },
          action: {type: "block"}
        }
      ]);

      await testRules([
        "/foo", "||test.com^", "http://example.com/foo", "^foo^"
      ], [
        {
          priority: GENERIC_PRIORITY,
          condition: {
            urlFilter: "/foo",
            isUrlFilterCaseSensitive: false
          },
          action: {type: "block"}
        },
        {
          priority: GENERIC_PRIORITY,
          condition: {
            urlFilter: "||test.com^"
          },
          action: {type: "block"}
        },
        {
          priority: GENERIC_PRIORITY,
          condition: {
            urlFilter: "http://example.com/foo",
            isUrlFilterCaseSensitive: false
          },
          action: {type: "block"}
        },
        {
          priority: GENERIC_PRIORITY,
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
        ["foo*$document", "||foo.com$document"], []
      );
    });

    it("should strip redundant ||* prefix", async () =>
    {
      await testRules(
        ["||*example.js$script"], [
          {
            priority: GENERIC_PRIORITY,
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
      await testRules(["/\\.example\\.com/.*[a-z0-9]{4}/$script"], []);
    });

    it("should handle regexp filters using isRegexSupported", async () =>
    {
      await testRules(
        ["/\\.example\\.com/.*[a-z0-9]{4}/$script",
         "/Test/$match-case",
         "/(?!unsupported)/",
         "@@/Regexp/"], [
          {
            priority: GENERIC_PRIORITY,
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
            priority: GENERIC_PRIORITY,
            condition: {
              regexFilter: "Test"
            },
            action: {
              type: "block"
            }
          },
          {
            priority: SPECIFIC_PRIORITY,
            condition: {
              isUrlFilterCaseSensitive: false,
              regexFilter: "regexp"
            },
            action: {
              type: "allow"
            }
          }
        ],
        null,
        null,
        ({regex}) => ({isSupported: !regex.includes("(?")})
      );
    });
  });

  describe("Request allowlisting filters", function()
  {
    it("should generate case-insensitive allowlisting filters", async () =>
    {
      await testRules(["@@example.com"], [
        {
          priority: SPECIFIC_PRIORITY,
          condition: {
            urlFilter: "example.com",
            isUrlFilterCaseSensitive: false
          },
          action: {type: "allow"}
        }
      ]);
    });

    it("should generate case-sensitive allowlisting filters", async () =>
    {
      await testRules(["@@||example.com"], [
        {
          priority: SPECIFIC_PRIORITY,
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
        ["||example.com", undefined],
        null,
        rule => rule.condition.urlFilter
      );
    });

    it("should strip redundant ||* prefix", async () =>
    {
      await testRules(
        ["@@||*example.js$script"], [
          {
            priority: SPECIFIC_PRIORITY,
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
      await testRules(["@@||example.com^$document"], [
        {
          priority: SPECIFIC_ALLOW_ALL_PRIORITY,
          condition: {
            urlFilter: "||example.com^",
            resourceTypes: ["main_frame", "sub_frame"]
          },
          action: {type: "allowAllRequests"}
        }
      ]);
      await testRules(["@@||example.com^$document,image"], [
        {
          priority: SPECIFIC_ALLOW_ALL_PRIORITY,
          condition: {
            urlFilter: "||example.com^",
            resourceTypes: ["main_frame", "sub_frame"]
          },
          action: {type: "allowAllRequests"}
        },
        {
          priority: SPECIFIC_PRIORITY,
          condition: {
            urlFilter: "||example.com^",
            resourceTypes: ["image"]
          },
          action: {type: "allow"}
        }
      ]);
      await testRules(
        ["@@||bar.com^$document,image", "@@||foo.com^$document"],
        [
          {
            priority: SPECIFIC_ALLOW_ALL_PRIORITY,
            condition: {
              urlFilter: "||bar.com^",
              resourceTypes: ["main_frame", "sub_frame"]
            },
            action: {type: "allowAllRequests"}
          },
          {
            priority: SPECIFIC_PRIORITY,
            condition: {
              urlFilter: "||bar.com^",
              resourceTypes: ["image"]
            },
            action: {type: "allow"}
          },
          {
            priority: SPECIFIC_ALLOW_ALL_PRIORITY,
            condition: {
              urlFilter: "||foo.com^",
              resourceTypes: ["main_frame", "sub_frame"]
            },
            action: {type: "allowAllRequests"}
          }
        ]
      );
      await testRules(
        ["@@foo*$document,domain=a.com|~b.com|c.com,image"],
        [
          {
            priority: SPECIFIC_ALLOW_ALL_PRIORITY,
            condition: {
              urlFilter: "foo",
              isUrlFilterCaseSensitive: false,
              resourceTypes: ["main_frame"],
              requestDomains: ["a.com", "c.com"],
              excludedRequestDomains: ["b.com"]
            },
            action: {type: "allowAllRequests"}
          },
          {
            priority: SPECIFIC_ALLOW_ALL_PRIORITY,
            condition: {
              urlFilter: "foo",
              isUrlFilterCaseSensitive: false,
              resourceTypes: ["sub_frame"],
              initiatorDomains: ["a.com", "c.com"],
              excludedInitiatorDomains: ["b.com"]
            },
            action: {type: "allowAllRequests"}
          },
          {
            priority: SPECIFIC_PRIORITY,
            condition: {
              urlFilter: "foo",
              isUrlFilterCaseSensitive: false,
              resourceTypes: ["image"],
              initiatorDomains: ["a.com", "c.com"],
              excludedInitiatorDomains: ["b.com"]
            },
            action: {type: "allow"}
          }
        ]
      );
    });

    it("should generate allowlisting rules for URLs", async () =>
    {
      await testRules(["@@||example.com/path^$font"], [
        {
          priority: SPECIFIC_PRIORITY,
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
      await testRules(["@@||example.com/path$document"], [
        {
          priority: SPECIFIC_ALLOW_ALL_PRIORITY,
          condition: {
            urlFilter: "||example.com/path",
            isUrlFilterCaseSensitive: false,
            resourceTypes: ["main_frame", "sub_frame"]
          },
          action: {type: "allowAllRequests"}
        }
      ]);

      await testRules(["@@||example.com/path$subdocument"], [
        {
          priority: SPECIFIC_PRIORITY,
          condition: {
            urlFilter: "||example.com/path",
            isUrlFilterCaseSensitive: false,
            resourceTypes: ["sub_frame"]
          },
          action: {type: "allow"}
        }
      ]);

      await testRules(["@@||example.com/path$document,subdocument"], [
        {
          priority: SPECIFIC_ALLOW_ALL_PRIORITY,
          condition: {
            urlFilter: "||example.com/path",
            isUrlFilterCaseSensitive: false,
            resourceTypes: ["main_frame", "sub_frame"]
          },
          action: {type: "allowAllRequests"}
        }
      ]);

      await testRules(["@@||example.com$document,subdocument"], [
        {
          priority: SPECIFIC_ALLOW_ALL_PRIORITY,
          condition: {
            urlFilter: "||example.com",
            resourceTypes: ["main_frame", "sub_frame"]
          },
          action: {type: "allowAllRequests"}
        }
      ]);

      await testRules(["@@||example.com"], [
        {
          priority: SPECIFIC_PRIORITY,
          condition: {
            urlFilter: "||example.com"
          },
          action: {type: "allow"}
        }
      ]);

      await testRules(["@@||example.com/path"], [
        {
          priority: SPECIFIC_PRIORITY,
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
                       "@@https://e.com$document"], [
        {
          priority: SPECIFIC_ALLOW_ALL_PRIORITY,
          condition: {
            urlFilter: "https://a.com",
            resourceTypes: ["main_frame", "sub_frame"]
          },
          action: {type: "allowAllRequests"}
        },
        {
          priority: SPECIFIC_ALLOW_ALL_PRIORITY,
          condition: {
            urlFilter: "https://b.com",
            resourceTypes: ["main_frame", "sub_frame"]
          },
          action: {type: "allowAllRequests"}
        },
        {
          priority: SPECIFIC_ALLOW_ALL_PRIORITY,
          condition: {
            urlFilter: "https://c.com",
            resourceTypes: ["main_frame", "sub_frame"]
          },
          action: {type: "allowAllRequests"}
        },
        {
          priority: SPECIFIC_ALLOW_ALL_PRIORITY,
          condition: {
            urlFilter: "https://d.com",
            resourceTypes: ["main_frame", "sub_frame"]
          },
          action: {type: "allowAllRequests"}
        },
        {
          priority: SPECIFIC_ALLOW_ALL_PRIORITY,
          condition: {
            urlFilter: "https://e.com",
            resourceTypes: ["main_frame", "sub_frame"]
          },
          action: {type: "allowAllRequests"}
        }
      ]);
      await testRules(["@@https://a.com*$document",
                       "@@https://b.com^$document",
                       "@@https://c.com?$document",
                       "@@https://d.com/$document",
                       "@@https://e.com|$document"], [
        {
          priority: SPECIFIC_ALLOW_ALL_PRIORITY,
          condition: {
            urlFilter: "https://a.com",
            resourceTypes: ["main_frame", "sub_frame"]
          },
          action: {type: "allowAllRequests"}
        },
        {
          priority: SPECIFIC_ALLOW_ALL_PRIORITY,
          condition: {
            urlFilter: "https://b.com^",
            resourceTypes: ["main_frame", "sub_frame"]
          },
          action: {type: "allowAllRequests"}
        },
        {
          priority: SPECIFIC_ALLOW_ALL_PRIORITY,
          condition: {
            urlFilter: "https://c.com?",
            resourceTypes: ["main_frame", "sub_frame"]
          },
          action: {type: "allowAllRequests"}
        },
        {
          priority: SPECIFIC_ALLOW_ALL_PRIORITY,
          condition: {
            urlFilter: "https://d.com/",
            resourceTypes: ["main_frame", "sub_frame"]
          },
          action: {type: "allowAllRequests"}
        },
        {
          priority: SPECIFIC_ALLOW_ALL_PRIORITY,
          condition: {
            urlFilter: "https://e.com|",
            resourceTypes: ["main_frame", "sub_frame"]
          },
          action: {type: "allowAllRequests"}
        }
      ]);
      await testRules(
        ["@@https://a.com*/$document", "@@https://b.com^a$document",
         "@@https://c.com?A$document", "@@https://d.com/1$document",
         "@@https://e.com|2$document"],
        [
          {
            priority: SPECIFIC_ALLOW_ALL_PRIORITY,
            condition: {
              urlFilter: "https://a.com*/",
              resourceTypes: ["main_frame", "sub_frame"]
            },
            action: {type: "allowAllRequests"}
          },
          {
            priority: SPECIFIC_ALLOW_ALL_PRIORITY,
            condition: {
              urlFilter: "https://b.com^a",
              resourceTypes: ["main_frame", "sub_frame"],
              isUrlFilterCaseSensitive: false
            },
            action: {type: "allowAllRequests"}
          },
          {
            priority: SPECIFIC_ALLOW_ALL_PRIORITY,
            condition: {
              urlFilter: "https://c.com?a",
              resourceTypes: ["main_frame", "sub_frame"],
              isUrlFilterCaseSensitive: false
            },
            action: {type: "allowAllRequests"}
          },
          {
            priority: SPECIFIC_ALLOW_ALL_PRIORITY,
            condition: {
              urlFilter: "https://d.com/1",
              resourceTypes: ["main_frame", "sub_frame"]
            },
            action: {type: "allowAllRequests"}
          },
          {
            priority: SPECIFIC_ALLOW_ALL_PRIORITY,
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
        ["@@foo*$genericblock", "@@foo*$genericblock,script"], [
          {
            action: {
              type: "allowAllRequests"
            },
            priority: GENERIC_ALLOW_ALL_PRIORITY,
            condition: {
              urlFilter: "foo",
              resourceTypes: ["main_frame", "sub_frame"],
              isUrlFilterCaseSensitive: false
            }
          },
          {
            action: {
              type: "allowAllRequests"
            },
            priority: GENERIC_ALLOW_ALL_PRIORITY,
            condition: {
              urlFilter: "foo",
              resourceTypes: ["main_frame", "sub_frame"],
              isUrlFilterCaseSensitive: false
            }
          },
          {
            action: {
              type: "allow"
            },
            condition: {
              isUrlFilterCaseSensitive: false,
              resourceTypes: ["script"],
              urlFilter: "foo"
            },
            priority: GENERIC_PRIORITY
          }
        ]
      );

      // Specific blocking rules should get the specific priority and
      // non-genericblock allowing rules should get the specific priority.
      // That way, genericblock allowing rules only prevent generic blocking.
      await testRules(
        ["@@||example.com^$genericblock",
         "@@||foobar.com^$genericblock,domain=foo.com",
         "@@ad.jpg$image",
         "@@bar.com$domain=foo.com",
         "@@ad.png$document",
         "@@flib.com$document,domain=foo.com"],
        [["||example.com^", GENERIC_ALLOW_ALL_PRIORITY],
         ["||foobar.com^", GENERIC_ALLOW_ALL_PRIORITY],
         ["||foobar.com^", GENERIC_ALLOW_ALL_PRIORITY],
         ["ad.jpg", SPECIFIC_PRIORITY],
         ["bar.com", SPECIFIC_PRIORITY],
         ["ad.png", SPECIFIC_ALLOW_ALL_PRIORITY],
         ["flib.com", SPECIFIC_ALLOW_ALL_PRIORITY],
         ["flib.com", SPECIFIC_ALLOW_ALL_PRIORITY]],
        null,
        rule => [rule.condition.urlFilter, rule.priority]
      );

      await testRules(
        ["a*",
         "^b.jpg|$domain=foo.com",
         "^c.jpg|",
         "^d.jpg|$domain=~test.com",
         "^e.jpg|$domain=test.com"],
        [["a", GENERIC_PRIORITY],
         ["^b.jpg|", SPECIFIC_PRIORITY],
         ["^c.jpg|", GENERIC_PRIORITY],
         ["^d.jpg|", GENERIC_PRIORITY],
         ["^e.jpg|", SPECIFIC_PRIORITY]],
        null,
        rule => [rule.condition.urlFilter, rule.priority]
      );

      await testRules(
        ["a*$csp=foo",
         "b*$csp=foo,domain=foo.com",
         "@@c*$csp",
         "@@d*$csp,genericblock"],
        [["a", GENERIC_PRIORITY],
         ["b", SPECIFIC_PRIORITY],
         ["b", SPECIFIC_PRIORITY],
         ["c", SPECIFIC_PRIORITY],
         ["d", GENERIC_PRIORITY]],
        null,
        rule => [rule.condition.urlFilter, rule.priority]
      );
    });
  });

  describe("Request type mapping", function()
  {
    it("should properly map request types", async () =>
    {
      await testRules(
        ["1*", "2*$image", "3*$stylesheet", "4*$script", "5*$font", "6*$media",
         "7*$object", "8*$object_subrequest", "9*$xmlhttprequest",
         "10*$websocket", "11*$ping", "12*$subdocument", "13*$other",
         "14*$IMAGE", "15*$script,PING", "16*$~image"],
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
        null,
        rule =>
        {
          let resourceTypes = rule.condition.resourceTypes;
          return resourceTypes && resourceTypes.sort();
        }
      );
    });
  });

  describe("Unsupported filters", function()
  {
    it("should ignore comment filters", async () =>
    {
      await testRules(["! this is a comment"], []);
    });

    it("should ignore $sitekey filters", async () =>
    {
      await testRules(["foo*$sitekey=bar"], []);
    });

    it("should ignore element hiding filters", async () =>
    {
      await testRules(["##.whatever"], []);
      await testRules(["test.com##.whatever"], []);
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
      ], []);
    });

    it("should ignore WebRTC filters", async () =>
    {
      await testRules(["foo*$webrtc"], []);
    });

    it("should ignore filters for popup windows", async () =>
    {
      await testRules(["bar*$popup"], []);
    });

    it("should ignore filters which contain Unicode characters", async () =>
    {
      await testRules(["$domain=🐈.cat"], []);
      await testRules(["||🐈"], []);
      await testRules(["🐈*$domain=🐈.cat"], []);
      await testRules(["🐈%F0%9F%90%88*$domain=🐈.cat"], []);
    });

    it("should ignore filters with invalid filter options", async () =>
    {
      await testRules(["||test.com$match_case"], []);
    });

    it("should ignore filters containing extended CSS selectors", async () =>
    {
      await testRules(
        ["test.com#?#.s-result-item:-abp-has(h5.s-sponsored-header)"],
        []
      );
    });

    it("should ignore snippet filters", async () =>
    {
      await testRules(["test.com#$#abort-on-property-read atob"], []);
    });

    it("shouldn't do anything if there are no filters at all!", async () =>
    {
      await testRules([], []);
    });
  });

  describe("Filter options", function()
  {
    it("should honour the $domain option", async () =>
    {
      await testRules(["1*$domain=foo.com|~subdomain.foo.com",
                       "@@2*$domain=bar.com|~subdomain.bar.com,document"],
                      [[["foo.com"], ["subdomain.foo.com"],
                        undefined, undefined],
                       [undefined, undefined,
                        ["bar.com"], ["subdomain.bar.com"]],
                       [["bar.com"], ["subdomain.bar.com"],
                        undefined, undefined]],
                      null,
                      rule => [
                        rule.condition.initiatorDomains,
                        rule.condition.excludedInitiatorDomains,
                        rule.condition.requestDomains,
                        rule.condition.excludedRequestDomains
                      ]);
    });
    it("should honour the $third-party option", async () =>
    {
      await testRules(["2*$third-party"], ["thirdParty"], null,
                      rule => rule.condition.domainType);
    });

    it("should honour the $match-case option", async () =>
    {
      await testRules(
        ["||test.com"], [undefined], null,
        rule => rule.condition.isUrlFilterCaseSensitive
      );
      await testRules(
        ["||test.com$match-case"], [undefined], null,
        rule => rule.condition.isUrlFilterCaseSensitive
      );
      await testRules(
        ["||test.com/foo"], [false], null,
        rule => rule.condition.isUrlFilterCaseSensitive
      );
      await testRules(
        ["||test.com/foo$match-case"], [undefined], null,
        rule => rule.condition.isUrlFilterCaseSensitive
      );
      await testRules(
        ["||test.com/Foo"], [false], null,
        rule => rule.condition.isUrlFilterCaseSensitive
      );
      await testRules(
        ["||test.com/Foo$match-case"], [undefined], null,
        rule => rule.condition.isUrlFilterCaseSensitive
      );
    });

    it("should get advanced $domain and $match-case usage right", async () =>
    {
      await testRules(
        ["/Foo$domain=Domain.com", "/Foo$match-case,domain=Domain.com",
         "||fOO.com", "||fOO.com$match-case",
         "||fOO.com/1", "||fOO.com/A", "||fOO.com/A$match-case"],
        [{urlFilter: "/foo",
          isUrlFilterCaseSensitive: false,
          initiatorDomains: ["domain.com"]},
         {urlFilter: "/Foo", initiatorDomains: ["domain.com"]},
         {urlFilter: "||foo.com"},
         {urlFilter: "||foo.com"},
         {urlFilter: "||foo.com/1"},
         {urlFilter: "||foo.com/a", isUrlFilterCaseSensitive: false},
         {urlFilter: "||foo.com/A"}
        ],
        null,
        rule => rule.condition
      );
    });

    it("should honour subdomain exceptions", async () =>
    {
      await testRules(["1*$domain=foo.com|~bar.foo.com"], [
        {
          priority: SPECIFIC_PRIORITY,
          condition: {
            urlFilter: "1",
            isUrlFilterCaseSensitive: false,
            initiatorDomains: ["foo.com"],
            excludedInitiatorDomains: ["bar.foo.com"]
          },
          action: {type: "block"}
        }
      ]);

      await testRules(["@@2*$domain=foo.com|~bar.foo.com,document"], [
        {
          priority: SPECIFIC_ALLOW_ALL_PRIORITY,
          condition: {
            urlFilter: "2",
            isUrlFilterCaseSensitive: false,
            requestDomains: ["foo.com"],
            excludedRequestDomains: ["bar.foo.com"],
            resourceTypes: ["main_frame"]
          },
          action: {type: "allowAllRequests"}
        },
        {
          priority: SPECIFIC_ALLOW_ALL_PRIORITY,
          condition: {
            urlFilter: "2",
            isUrlFilterCaseSensitive: false,
            initiatorDomains: ["foo.com"],
            excludedInitiatorDomains: ["bar.foo.com"],
            resourceTypes: ["sub_frame"]
          },
          action: {type: "allowAllRequests"}
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
        [
          {
            priority: SPECIFIC_PRIORITY,
            condition: {
              urlFilter: "||bar.com/ad.js",
              isUrlFilterCaseSensitive: false,
              initiatorDomains: ["foo.com"],
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
        []
      );
      await testRules(
        ["/(server.com/assets/file.php)?.*$/$rewrite=$1"],
        []
      );
      await testRules(
        ["/(server.com/assets/file.php)?.*$/$rewrite=https://test.com"],
        []
      );
      await testRules(
        ["foo*$rewrite=$1"],
        []
      );
      await testRules(
        ["||example.com/ad.js$script,domain=foo.com,rewrite=abp-resource:foo"],
        []
      );
      await testRules(
        ["foo*$rewrite=http://google.com"],
        []
      );
    });
  });

  describe("Web sockets", function()
  {
    it("should generate websocket blocking rules", async () =>
    {
      await testRules(["foo*$websocket"], [
        {
          priority: GENERIC_PRIORITY,
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
      await testRules(["foo*$csp=img-src 'none'"], [
        {
          priority: GENERIC_PRIORITY,
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

      await testRules(["@@||testpages.adblockplus.org^$csp"], [
        {
          priority: SPECIFIC_PRIORITY,
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

    it("should target request domain for main_frame requests, initiator " +
       "domain for sub_frame requests", async () =>
    {
      await testRules(
        ["$csp=img-src 'none',domain=~foo.com",
         "ad$csp=img-src 'none',domain=foo.com"], [
          {
            priority: GENERIC_PRIORITY,
            condition: {
              excludedRequestDomains: ["foo.com"],
              resourceTypes: ["main_frame"]
            },
            action: {
              responseHeaders: [
                {
                  header: "Content-Security-Policy",
                  operation: "append",
                  value: "img-src 'none'"
                }
              ],
              type: "modifyHeaders"
            }
          },
          {
            priority: GENERIC_PRIORITY,
            condition: {
              excludedInitiatorDomains: ["foo.com"],
              resourceTypes: ["sub_frame"]
            },
            action: {
              responseHeaders: [
                {
                  header: "Content-Security-Policy",
                  operation: "append",
                  value: "img-src 'none'"
                }
              ],
              type: "modifyHeaders"
            }
          },
          {
            priority: SPECIFIC_PRIORITY,
            condition: {
              isUrlFilterCaseSensitive: false,
              requestDomains: ["foo.com"],
              resourceTypes: ["main_frame"],
              urlFilter: "ad"
            },
            action: {
              responseHeaders: [
                {
                  header: "Content-Security-Policy",
                  operation: "append",
                  value: "img-src 'none'"
                }
              ],
              type: "modifyHeaders"
            }
          },
          {
            priority: SPECIFIC_PRIORITY,
            condition: {
              initiatorDomains: ["foo.com"],
              isUrlFilterCaseSensitive: false,
              resourceTypes: ["sub_frame"],
              urlFilter: "ad"
            },
            action: {
              responseHeaders: [
                {
                  header: "Content-Security-Policy",
                  operation: "append",
                  value: "img-src 'none'"
                }
              ],
              type: "modifyHeaders"
            }
          }
        ]
      );

      await testRules(
        ["ad$csp=img-src 'none',domain=a.com|b.com|c.com"],
        [
          {
            priority: SPECIFIC_PRIORITY,
            condition: {
              urlFilter: "ad",
              isUrlFilterCaseSensitive: false,
              resourceTypes: ["main_frame"],
              requestDomains: ["a.com", "b.com", "c.com"]
            },
            action: {
              type: "modifyHeaders",
              responseHeaders: [{
                header: "Content-Security-Policy",
                operation: "append",
                value: "img-src 'none'"
              }]
            }
          },
          {
            priority: SPECIFIC_PRIORITY,
            condition: {
              urlFilter: "ad",
              isUrlFilterCaseSensitive: false,
              resourceTypes: ["sub_frame"],
              initiatorDomains: ["a.com", "b.com", "c.com"]
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
        ]
      );
    });
  });
});

describe("compressRules", function()
{
  it("should combine rules where possible", async () =>
  {
    let ruleSortString = rule =>
      rule.action.type + rule.condition.urlFilter +
      (rule.condition.requestDomains || []).toString() + rule.priority;

    let sortRule = (a, b) =>
    {
      a = ruleSortString(a);
      b = ruleSortString(b);

      if (a == b)
        return 0;

      return a < b ? -1 : 1;
    };

    await testRules(
      ["||a.com^", "||b.com^", "||c.com^", "@@||d.com^", "||e.com^$image",
       "||f.com^$domain=a.com,csp=img-src 'none'",
       "||g.com^$csp=img-src 'none',domain=a.com",
       "||h.com$image", "||i.com^$image", "||j.com^$script", "||k.com^hello"],
      [{
        priority: GENERIC_PRIORITY,
        condition: {
          requestDomains: ["a.com", "b.com", "c.com"]
        },
        action: {
          type: "block"
        }
      }, {
        priority: SPECIFIC_PRIORITY,
        condition: {
          urlFilter: "||d.com^"
        },
        action: {
          type: "allow"
        }
      }, {
        priority: GENERIC_PRIORITY,
        condition: {
          requestDomains: ["e.com", "i.com"],
          resourceTypes: ["image"]
        },
        action: {
          type: "block"
        }
      }, {
        priority: SPECIFIC_PRIORITY,
        condition: {
          resourceTypes: ["sub_frame"],
          initiatorDomains: ["a.com"],
          requestDomains: ["f.com", "g.com"]
        },
        action: {
          type: "modifyHeaders",
          responseHeaders: [{
            header: "Content-Security-Policy",
            operation: "append",
            value: "img-src 'none'"
          }]
        }
      }, {
        priority: SPECIFIC_PRIORITY,
        condition: {
          urlFilter: "||f.com^",
          resourceTypes: ["main_frame"],
          requestDomains: ["a.com"]
        },
        action: {
          type: "modifyHeaders",
          responseHeaders: [{
            header: "Content-Security-Policy",
            operation: "append",
            value: "img-src 'none'"
          }]
        }
      }, {
        priority: SPECIFIC_PRIORITY,
        condition: {
          urlFilter: "||g.com^",
          resourceTypes: ["main_frame"],
          requestDomains: ["a.com"]
        },
        action: {
          type: "modifyHeaders",
          responseHeaders: [{
            header: "Content-Security-Policy",
            operation: "append",
            value: "img-src 'none'"
          }]
        }
      }, {
        priority: GENERIC_PRIORITY,
        condition: {
          urlFilter: "||h.com",
          resourceTypes: ["image"]
        },
        action: {
          type: "block"
        }
      }, {
        priority: GENERIC_PRIORITY,
        condition: {
          urlFilter: "||j.com^",
          resourceTypes: ["script"]
        },
        action: {
          type: "block"
        }
      }, {
        priority: GENERIC_PRIORITY,
        condition: {
          isUrlFilterCaseSensitive: false,
          urlFilter: "||k.com^hello"
        },
        action: {
          type: "block"
        }
      }].sort(sortRule),
      rules => compressRules(rules).sort(sortRule)
    );
  });
});
