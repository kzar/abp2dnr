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

const {pipeline, Transform} = require("stream");
const {StringDecoder} = require("string_decoder");

const {Filter} = require("adblockpluscore/lib/filterClasses");
const split2 = require("split2");

const {PuppeteerInterface} = require("ddg2dnr/puppeteerInterface");
const {convertFilter, compressRules} = require("./lib/abp2dnr");

function rulesetStream(stream)
{
  let rules = [];

  let browser = new PuppeteerInterface();
  let isRegexSupported = browser.isRegexSupported.bind(browser);
  let decoder = new StringDecoder("utf-8");

  let transform = new Transform();
  transform._transform = async (line, encoding, cb) =>
  {
    if (encoding == "buffer")
      line = decoder.write(line);

    if (/^\s*[^[\s]/.test(line))
    {
      let filter = Filter.fromText(Filter.normalize(line));
      for (let rule of await convertFilter(filter, isRegexSupported))
        rules.push(rule);
    }

    cb(null);
  };
  transform._flush = cb =>
  {
    browser.closeBrowser();

    if (!rules.length)
    {
      cb(null, "[]\n");
      return;
    }

    let output = "[\n";
    let id = 1;
    for (let rule of compressRules(rules))
    {
      if (id > 1)
        output += ",\n";
      rule.id = id++;
      output += JSON.stringify(rule, null, "\t");
    }
    output += "\n]\n";
    cb(null, output);
  };
  return transform;
}

pipeline(
  process.stdin,
  split2(),
  rulesetStream(),
  process.stdout,
  error => { }
);
