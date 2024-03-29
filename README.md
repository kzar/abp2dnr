# abp2dnr

This is a script to convert [Adblock Plus filter lists](https://adblockplus.org/filters)
to [chrome.declarativeNetRequest rulesets](https://developer.chrome.com/extensions/declarativeNetRequest)
as far as is possible.

See also [Chromium's built-in filter list converter](https://source.chromium.org/chromium/chromium/src/+/master:extensions/browser/api/declarative_net_request/filter_list_converter/).

## Requirements

Before you begin, make sure to install [Node.js](2) version 16 or higher.

Then the required packages can be installed via Git and [npm](https://npmjs.org):

```bash
npm install
```

The declarativeNetRequest rulesets generated by this script require
Chrome >= 101 to function correctly.
([See this announcement for context](https://groups.google.com/u/1/a/chromium.org/g/chromium-extensions/c/4971ZS9cI7E).)

## Usage

### Command line interface

Create a declarativeNetRequest ruleset `output.json` from an Adblock Plus
filter list `input.txt`:

```bash
node abp2dnr.js < input.txt > output.json
```

#### JavaScript API

Behind that, there's a JavaScript  API which the command line interface uses. It
works something like this:

```javascript
const {convertFilter, compressRules} = require("./lib/abp2dnr");

let rules = []

// Convert the filters to declarativeNetRequest rules.
for (let filter of filters)
  rules.push(await convertFilter(filter));

// Optionally combine rules where possible.
rules = compressRules(rules)

// Assign the rules an ID (must not be before compressRules()).
let id = 1;
for (let rule of rules)
  rule.id = id++;
```

It's important to note that `convertFilter` expects a `Filter` Object and _not_
a string containing the filter's text. To parse filter text you'll need to
do something like this first:

```javascript
const {Filter} = require("adblockpluscore/lib/filterClasses");
Filter.fromText(Filter.normalize(filterText));
```

## Tests

Unit tests live in the `tests/` directory. You can run them by typing this command:

```bash
npm test
```

## Linting

You can lint the code by typing this command:

```bash
npm run lint
```
