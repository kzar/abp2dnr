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
  let id = 1;
  for (let rule of rules)
    rule.id = id++;
  return await browser.addRules(rules);
}

async function testRequestOutcome(browser, requestDetails,
                                  verboseAction = false)
{
  let matchingRules = await browser.testMatchOutcome(requestDetails);

  if (verboseAction)
    return matchingRules.map(({action}) => action);

  if (matchingRules.length === 0)
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
});
