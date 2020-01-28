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

const {Readable} = require("stream");

const assert = require("assert");

const {chromeRulesStream, chromeRulesGulp} = require("../index.js");

const exampleRules = [{
  action: {
    type: "block"
  },
  priority: 1,
  condition: {
    isUrlFilterCaseSensitive: false,
    urlFilter: "ab"
  },
  id: 1
}, {
  action: {
    type: "block"
  },
  priority: 1,
  condition: {
    isUrlFilterCaseSensitive: false,
    urlFilter: "cd"
  },
  id: 2
}];

// https://stackoverflow.com/a/58256873/1226469
function getStream(stream)
{
  return new Promise(resolve =>
  {
    let chunks = [];
    stream.on("data", chunk => { chunks.push(chunk); });
    stream.on("end", () => { resolve(chunks); });
  });
}

function generateRulesStream(filters)
{
  let stream = new Readable();
  for (let filter of filters)
    stream.push(filter);
  stream.push(null);

  return getStream(stream.pipe(chromeRulesStream()))
           .then(chunks => Buffer.concat(chunks).toString())
           .then(JSON.parse);
}

describe("chromeRulesStream", function()
{
  it("should generate blocking rules", function()
  {
    return generateRulesStream(["ab", "cd"]).then(rules =>
    {
      assert.deepEqual(rules, exampleRules);
    });
  });

  it("should handle empty stream", function()
  {
    return generateRulesStream([]).then(rules =>
    {
      assert.deepEqual(rules, []);
    });
  });

  it("should skip headers and ignore trailing whitespace", function()
  {
    return generateRulesStream(
      ["[hello]", "!world", "  !world", "   ab   "]
    ).then(rules =>
    {
      assert.deepEqual(rules, [exampleRules[0]]);
    });
  });
});

describe("chromeRulesGulp", function()
{
  it("should handle Gulp streams not in stream mode", function()
  {
    let contents = new Readable();
    contents.push("ab\ncd");
    contents.push(null);

    let stream = new Readable({objectMode: true});
    stream.push({isBuffer: () => false, contents});
    stream.push(null);

    return getStream(stream.pipe(chromeRulesGulp())).then(files =>
    {
      return getStream(files[0].contents)
               .then(chunks => Buffer.concat(chunks).toString())
               .then(JSON.parse)
               .then(rules =>
               {
                 assert.deepEqual(rules, exampleRules);
               });
    });
  });

  it("should handle Gulp streams in buffer mode", function()
  {
    let stream = new Readable({objectMode: true});
    stream.push({isBuffer: () => true, contents: Buffer.from("ab\ncd")});
    stream.push(null);

    return getStream(stream.pipe(chromeRulesGulp())).then(files =>
    {
      return getStream(files[0].contents)
               .then(chunks => Buffer.concat(chunks).toString())
               .then(JSON.parse)
               .then(rules =>
               {
                 assert.deepEqual(rules, exampleRules);
               });
    });
  });
});
