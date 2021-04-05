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

const {isRegexSupported} = require("./build/Release/isRegexSupported");
const {convertFilter} = require("./lib/abp2dnr");

function rulesetStream(stream)
{
  let arrayStarted = false;
  let firstEmitted = false;
  let nextId = 1;
  let decoder = new StringDecoder("utf-8");

  let transform = new Transform();
  transform._transform = async (line, encoding, cb) =>
  {
    let output = "";

    if (!arrayStarted)
    {
      output += "[\n";
      arrayStarted = true;
    }

    if (encoding == "buffer")
      line = decoder.write(line);

    if (/^\s*[^[\s]/.test(line))
    {
      let filter = Filter.fromText(Filter.normalize(line));
      for (let rule of await convertFilter(filter, isRegexSupported))
      {
        rule.id = nextId++;

        if (firstEmitted)
          output += ",\n";
        else
          firstEmitted = true;

        output += JSON.stringify(rule, null, "\t");
      }
    }

    cb(null, output);
  };
  transform._flush = (cb) =>
  {
    cb(null, arrayStarted ? "\n]\n" : "[]\n");
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
