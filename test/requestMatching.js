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
const {compressRules, convertFilter} = require("../lib/abp2dnr.js");

// Note: Rules are automatically cleared between tests, so the current rule ID
//       could also be cleared at the same time. It doesn't matter much however,
//       and this way there's no chance of accidentally using the same ID twice
//       in a test.
let currentRuleId = 1;

async function addFilters(browser, filters)
{
  let isRegexSupported = browser.isRegexSupported.bind(browser);
  let rules = [];
  for (let filter of filters)
  {
    for (let rule of await convertFilter(Filter.fromText(filter),
                                         isRegexSupported))
    {
      rules.push(rule);
    }
  }
  rules = compressRules(rules);
  for (let rule of rules)
    rule.id = currentRuleId++;
  return await browser.addRules(rules);
}

async function testRequestOutcome(browser, requestDetails,
                                  verboseAction = false)
{
  let allowAllRequestMatch = null;

  // First check if the initiating website matches an allowAllRequests rule.
  if (requestDetails.initiator && requestDetails.type !== "main_frame")
  {
    let matchingRules = await browser.testMatchOutcome({
      url: requestDetails.initiator,
      type: "main_frame"
    });
    if (matchingRules.length > 0 &&
        matchingRules[0].action.type === "allowAllRequests")
    {
      allowAllRequestMatch = matchingRules;
    }
  }

  // Then check if the request itself matches any rules.
  let matchingRules = await browser.testMatchOutcome(requestDetails);

  // Check if the initiating website's allowAllRequest rule takes priority.
  if (allowAllRequestMatch && allowAllRequestMatch.length > 0 && (
    matchingRules.length === 0 ||
    matchingRules[0].priority <= allowAllRequestMatch[0].priority
  ))
  {
    matchingRules = allowAllRequestMatch;
  }

  if (verboseAction)
    return matchingRules.map(({action}) => action);

  if (matchingRules.length === 0 ||
      matchingRules[0].action.type === "allowAllRequests")
    return "allow";

  return matchingRules.map(({action: {type}}) => type).join(",");
}

describe("Request matching", function()
{
  it("should perform basic request blocking", async function()
  {
    assert.equal(
      await testRequestOutcome(this.browser, {
        url: "https://example.invalid/advert",
        type: "image"
      }),
      "allow"
    );

    await addFilters(this.browser, ["advert"]);

    assert.deepEqual(
      await testRequestOutcome(this.browser, {
        url: "https://example.invalid/advert",
        type: "image"
      }),
      "block"
    );
  });

  it("should match domains correctly", async function()
  {
    assert.deepEqual(
      await testRequestOutcome(this.browser, {
        url: "https://subdomain.example.invalid",
        type: "image"
      }),
      "allow"
    );

    await addFilters(this.browser, ["||subdomain.example.invalid"]);

    assert.deepEqual(
      await testRequestOutcome(this.browser, {
        url: "https://example.invalid",
        type: "image"
      }),
      "allow"
    );

    assert.deepEqual(
      await testRequestOutcome(this.browser, {
        url: "https://othersubdomain.example.invalid",
        type: "image"
      }),
      "allow"
    );

    assert.deepEqual(
      await testRequestOutcome(this.browser, {
        url: "https://subdomain.example.invalid",
        type: "image"
      }),
      "block"
    );

    assert.deepEqual(
      await testRequestOutcome(this.browser, {
        url: "https://subsubdomain.subdomain.example.invalid",
        type: "image"
      }),
      "block"
    );
  });

  it("should match request types correctly", async function()
  {
    await addFilters(this.browser, [
      "flib$image,script", "flob$~stylesheet"
    ]);

    assert.deepEqual(
      await testRequestOutcome(this.browser, {
        url: "https://example.invalid/flib",
        type: "image"
      }),
      "block"
    );

    assert.deepEqual(
      await testRequestOutcome(this.browser, {
        url: "https://example.invalid/flib",
        type: "script"
      }),
      "block"
    );

    assert.deepEqual(
      await testRequestOutcome(this.browser, {
        url: "https://example.invalid/flib",
        type: "stylesheet"
      }),
      "allow"
    );

    assert.deepEqual(
      await testRequestOutcome(this.browser, {
        url: "https://example.invalid/flib",
        type: "sub_frame"
      }),
      "allow"
    );

    assert.deepEqual(
      await testRequestOutcome(this.browser, {
        url: "https://example.invalid/flob",
        type: "stylesheet"
      }),
      "allow"
    );

    assert.deepEqual(
      await testRequestOutcome(this.browser, {
        url: "https://example.invalid/flob",
        type: "script"
      }),
      "block"
    );

    assert.deepEqual(
      await testRequestOutcome(this.browser, {
        url: "https://example.invalid/flob",
        type: "image"
      }),
      "block"
    );

    assert.deepEqual(
      await testRequestOutcome(this.browser, {
        url: "https://example.invalid/flob",
        type: "stylesheet"
      }),
      "allow"
    );
  });

  it("should not block allowlisted requests", async function()
  {
    await addFilters(this.browser, [
      "||example.invalid", "@@||allowed.example.invalid"
    ]);

    assert.deepEqual(
      await testRequestOutcome(this.browser, {
        url: "https://example.invalid",
        type: "image"
      }),
      "block"
    );

    assert.deepEqual(
      await testRequestOutcome(this.browser, {
        url: "https://subdomain.example.invalid",
        type: "image"
      }),
      "block"
    );

    assert.deepEqual(
      await testRequestOutcome(this.browser, {
        url: "https://not-allowed.example.invalid",
        type: "image"
      }),
      "block"
    );

    assert.deepEqual(
      await testRequestOutcome(this.browser, {
        url: "https://allowed.example.invalid",
        type: "image"
      }),
      "allow"
    );

    assert.deepEqual(
      await testRequestOutcome(this.browser, {
        url: "https://subdomain.allowed.example.invalid",
        type: "image"
      }),
      "allow"
    );
  });

  it("should block by initiator domain correctly", async function()
  {
    await addFilters(this.browser, [
      "advert$domain=initiator.invalid|other-initiator.invalid",
      "tracker$domain=~tracker.invalid"
    ]);

    assert.deepEqual(
      await testRequestOutcome(this.browser, {
        url: "https://example.invalid/advert",
        type: "image"
      }),
      "allow"
    );

    assert.deepEqual(
      await testRequestOutcome(this.browser, {
        url: "https://initiator.invalid/advert",
        type: "image"
      }),
      "allow"
    );

    assert.deepEqual(
      await testRequestOutcome(this.browser, {
        url: "https://example.invalid/advert",
        initiator: "https://example.invalid",
        type: "image"
      }),
      "allow"
    );

    assert.deepEqual(
      await testRequestOutcome(this.browser, {
        url: "https://example.invalid/advert",
        initiator: "https://initiator.invalid",
        type: "image"
      }),
      "block"
    );

    assert.deepEqual(
      await testRequestOutcome(this.browser, {
        url: "https://example.invalid/advert",
        initiator: "https://other-initiator.invalid",
        type: "image"
      }),
      "block"
    );

    assert.deepEqual(
      await testRequestOutcome(this.browser, {
        url: "https://example.invalid/advert",
        initiator: "https://subdomain.other-initiator.invalid",
        type: "image"
      }),
      "block"
    );

    assert.deepEqual(
      await testRequestOutcome(this.browser, {
        url: "https://example.invalid/advert",
        initiator: "https://wrong-initiator.invalid",
        type: "image"
      }),
      "allow"
    );

    assert.deepEqual(
      await testRequestOutcome(this.browser, {
        url: "https://example.invalid/tracker",
        type: "image"
      }),
      "block"
    );

    assert.deepEqual(
      await testRequestOutcome(this.browser, {
        url: "https://example.invalid/tracker",
        initiator: "https://example.invalid",
        type: "image"
      }),
      "block"
    );

    assert.deepEqual(
      await testRequestOutcome(this.browser, {
        url: "https://example.invalid/tracker",
        initiator: "https://tracker.invalid",
        type: "image"
      }),
      "allow"
    );
  });

  it("should not block $genericblock allowlisted requests", async function()
  {
    await addFilters(this.browser, [
      "foo*", "bar$domain=~other.invalid", "flib$domain=example.invalid",
      "@@$genericblock,domain=example.invalid"
    ]);

    assert.deepEqual(
      await testRequestOutcome(this.browser, {
        url: "https://request-domain.invalid/foo",
        initiator: "https://other.invalid",
        type: "image"
      }),
      "block"
    );

    assert.deepEqual(
      await testRequestOutcome(this.browser, {
        url: "https://request-domain.invalid/bar",
        initiator: "https://other.invalid",
        type: "image"
      }),
      "allow"
    );

    assert.deepEqual(
      await testRequestOutcome(this.browser, {
        url: "https://request-domain.invalid/bar",
        initiator: "https://other2.invalid",
        type: "image"
      }),
      "block"
    );

    assert.deepEqual(
      await testRequestOutcome(this.browser, {
        url: "https://request-domain.invalid/flib",
        initiator: "https://other.invalid",
        type: "image"
      }),
      "allow"
    );

    assert.deepEqual(
      await testRequestOutcome(this.browser, {
        url: "https://request-domain.invalid/foo",
        initiator: "https://example.invalid",
        type: "image"
      }),
      "allow"
    );

    assert.deepEqual(
      await testRequestOutcome(this.browser, {
        url: "https://request-domain.invalid/bar",
        initiator: "https://example.invalid",
        type: "image"
      }),
      "allow"
    );

    assert.deepEqual(
      await testRequestOutcome(this.browser, {
        url: "https://request-domain.invalid/flib",
        initiator: "https://example.invalid",
        type: "image"
      }),
      "block"
    );
  });

  it("should apply $csp filters correctly", async function()
  {
    await addFilters(this.browser, [
      "||example.invalid$csp=script-src: 'none'"
    ]);

    assert.deepEqual(
      await testRequestOutcome(this.browser, {
        url: "https://example.invalid",
        type: "main_frame"
      }, true),
      [
        {
          type: "modifyHeaders",
          responseHeaders: [
            {
              header: "Content-Security-Policy",
              operation: "append",
              value: "script-src: 'none'"
            }
          ]
        }
      ]
    );

    assert.deepEqual(
      await testRequestOutcome(this.browser, {
        url: "https://example.invalid",
        type: "sub_frame"
      }, true),
      [
        {
          type: "modifyHeaders",
          responseHeaders: [
            {
              header: "Content-Security-Policy",
              operation: "append",
              value: "script-src: 'none'"
            }
          ]
        }
      ]
    );

    assert.deepEqual(
      await testRequestOutcome(this.browser, {
        url: "https://other-example.invalid",
        type: "main_frame"
      }),
      "allow"
    );

    assert.deepEqual(
      await testRequestOutcome(this.browser, {
        url: "https://example.invalid",
        type: "script"
      }),
      "allow"
    );
  });

  it("should redirect requests matching rewrite filters", async function()
  {
    await addFilters(this.browser, [
      "||example.invalid/foo$domain=bar.invalid,rewrite=abp-resource:blank-js"
    ]);

    assert.deepEqual(
      await testRequestOutcome(this.browser, {
        url: "https://example.invalid/foo",
        initiator: "https://bar.invalid",
        type: "script"
      }, true),
      [
        {
          type: "redirect",
          redirect: {
            url: "data:application/javascript,"
          }
        }
      ]
    );
  });


  it("should block third-party requests correctly", async function()
  {
    await addFilters(this.browser, [
      "foo*$third-party", "bar*$~third-party"
    ]);

    assert.deepEqual(
      await testRequestOutcome(this.browser, {
        url: "https://example.invalid/foo",
        initiator: "https://example.invalid",
        type: "image"
      }),
      "allow"
    );

    assert.deepEqual(
      await testRequestOutcome(this.browser, {
        url: "https://example.invalid/foo",
        initiator: "https://other.invalid",
        type: "image"
      }),
      "block"
    );

    assert.deepEqual(
      await testRequestOutcome(this.browser, {
        url: "https://example.invalid/bar",
        initiator: "https://example.invalid",
        type: "image"
      }),
      "block"
    );

    assert.deepEqual(
      await testRequestOutcome(this.browser, {
        url: "https://example.invalid/bar",
        initiator: "https://other.invalid",
        type: "image"
      }),
      "allow"
    );
  });

  it("should block requests matching regular expressions", async function()
  {
    await addFilters(this.browser, [
      "/foo\\d+bar/"
    ]);

    assert.deepEqual(
      await testRequestOutcome(this.browser, {
        url: "https://example.invalid/foobar",
        type: "image"
      }),
      "allow"
    );

    assert.deepEqual(
      await testRequestOutcome(this.browser, {
        url: "https://example.invalid/foo-bar",
        type: "image"
      }),
      "allow"
    );

    assert.deepEqual(
      await testRequestOutcome(this.browser, {
        url: "https://example.invalid/foo123bar",
        type: "image"
      }),
      "block"
    );
  });
});
