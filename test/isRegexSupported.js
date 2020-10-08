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

const {isRegexSupported} = require("../build/Release/isRegexSupported");

describe("isRegexSupported", function()
{
  it("should throw if arguments are invalid", async () =>
  {
    assert.throws(() => { isRegexSupported(); });
    assert.throws(() => { isRegexSupported(1); });
    assert.throws(() => { isRegexSupported(1, 2, 3); });
    assert.throws(() => { isRegexSupported({}); });
    assert.throws(() => { isRegexSupported({foo: "bar"}); });
    assert.throws(() => { isRegexSupported({regex: "bar"}, 1); });
  });

  it("should accept a valid regular expression", async () =>
  {
    assert.deepEqual(isRegexSupported({
      regex: "[0-9]+"
    }), {isSupported: true});
  });

  it("should accept a valid regular expression with options", async () =>
  {
    assert.deepEqual(isRegexSupported({
      regex: "[0-9]+",
      isCaseSensitive: false,
      requireCapturing: true
    }), {isSupported: true});
  });

  it("should reject an invalid regular expression", async () =>
  {
    assert.deepEqual(isRegexSupported({
      regex: "[a-9]+"
    }), {isSupported: false, reason: "syntaxError"});
  });

  it("should reject an invalid regular expression with options", async () =>
  {
    assert.deepEqual(isRegexSupported({
      regex: "[a-9]+",
      isCaseSensitive: false,
      requireCapturing: true
    }), {isSupported: false, reason: "syntaxError"});
  });

  it("should reject long regular expression", async () =>
  {
    assert.deepEqual(isRegexSupported({
      regex: "[0-9]+".repeat(1000)
    }), {isSupported: false, reason: "memoryLimitExceeded"});
  });

  it("should reject long regular expression with options", async () =>
  {
    assert.deepEqual(isRegexSupported({
      regex: "(a)".repeat(50)
    }), {isSupported: true});
    assert.deepEqual(isRegexSupported({
      regex: "(a)".repeat(50),
      requireCapturing: false
    }), {isSupported: true});
    assert.deepEqual(isRegexSupported({
      regex: "(a)".repeat(50),
      requireCapturing: true
    }), {isSupported: false, reason: "memoryLimitExceeded"});
  });
});
