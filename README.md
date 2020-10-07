# abp2dnr

This is a script to convert [Adblock Plus filter lists](https://adblockplus.org/filters)
to [chrome.declarativeNetRequest rulesets](https://developer.chrome.com/extensions/declarativeNetRequest)
as far as is possible.

## Requirements

Before you begin, make sure to install [Node.js](2) (version 10 or higher).

Then the required packages can be installed via [npm](https://npmjs.org):

    npm install

## Usage

### Command line interface

Create a `chrome.declarativeNetRequest` rule list `output.json` from the
Adblock Plus filter list `input.txt`:

    node abp2dnr.js < input.txt > output.json

#### API

Behind that, there's an API which the command line interface uses. It works
something like this:

    const {Ruleset} = require("./lib/abp2dnr");

    let rulset = new Ruleset();
    for (let filter in filters)
      await ruleset.processFilter(filter);

    let rules = ruleset.generateRules();

It's important to note that `Ruleset.prototype.processFilter` expects a
`Filter` Object and _not_ a string containing the filter's text. To parse
filter text you'll need to do something like this first:

    const {Filter} = require("adblockpluscore/lib/filterClasses");
    Filter.fromText(Filter.normalize(filterText));

## Tests

Unit tests live in the `tests/` directory. You can run them by typing this command:

    npm test

## Linting

You can lint the code by typing this command:

    npm run lint
