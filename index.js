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

const {Transform, Readable} = require("stream");
const {StringDecoder} = require("string_decoder");

const split2 = require("split2");

const {Filter} = require("adblockpluscore/lib/filterClasses");
const {generateRules} = require("./lib/abp2chromerules");

function generateRulesStream(stream)
{
  let decoder = new StringDecoder("utf-8");
  let filters = [];

  let transform = new Transform();
  transform._transform = (line, encoding, cb) =>
  {
    if (encoding == "buffer")
      line = decoder.write(line);

    if (/^\s*[^[\s]/.test(line))
      filters.push(Filter.fromText(Filter.normalize(line)));

    cb(null);
  };
  transform._flush = (cb) =>
  {
    let rules = generateRules(filters);
    let output = [];

    // If the rule set is too huge, JSON.stringify throws
    // "RangeError: Invalid string length" on Node.js. As a workaround, print
    // each rule individually.
    output.push("[");

    if (rules.length)
    {
      for (let i = 0; i < rules.length - 1; i++)
        output.push(JSON.stringify(rules[i], null, "\t") + ",");
      output.push(JSON.stringify(rules[rules.length - 1], null, "\t"));
    }
    output.push("]");


    cb(null, output.join("\n"));
  };

  return transform;
}

function generateRulesGulp()
{
  let transform = new Transform({objectMode: true});
  transform._transform = (file, encoding, cb) =>
  {
    let stream = file.contents;
    if (file.isBuffer())
    {
      stream = new Readable();
      stream.push(file.contents);
      stream.push(null);
    }

    file.contents = stream.pipe(split2())
                          .pipe(generateRulesStream());
    cb(null, file);
  };
  return transform;
}

exports.generateRules = generateRules;
exports.generateRulesStream = generateRulesStream;
exports.generateRulesGulp = generateRulesGulp;
