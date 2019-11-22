# abp2chromerules

This is a script to convert [Adblock Plus filter lists](https://adblockplus.org/filters)
to [chrome.declarativeNetRequest rules](https://developer.chrome.com/extensions/declarativeNetRequest)
as far as is possible.

## Requirements

Before you begin, make sure to install [Node.js](2) (version 10 or higher).

Then the required packages can be installed via [npm](https://npmjs.org):

    npm install

## Usage

### Command line interface

Create a `chrome.declarativeNetRequest` rule list `output.json` from the
Adblock Plus filter list `input.txt`:

    node abp2chromerules.js < input.txt > output.json

### Gulp interface

There's a Gulp `.pipe` interface. Add this repository as a dependency in
your package.json, then do something like this in your gulpfile:

    const {chromeRulesGulp} = require("abp2chromerules");
    gulp.src("easylist.txt")
        .pipe(chromeRulesGulp())
        .pipe(gulp.dest("output/"));

Note: We don't take care of concatenating filter files, or renaming the output
file. I suggest using something like [gulp-concat](https://www.npmjs.com/package/gulp-concat)
for that.

### Other interfaces

#### Stream

There's a stream transformer, which you can use a stream of filter text into
blocking rules. See abp2chromerules.js for a simple example of how it works.

Note:
 - The streaming interface expects the stream is split into line chunks,
   make sure to use [split2](https://www.npmjs.com/package/gulp-concat) or
   similar.
 - The output is only produced when the stream is ending, this is something we
   might improve in the future, though that might not be possible in practice.

#### Regular API

Behind that, there's the regular API which the stream transformer uses. It works
something like this:

    const {ChromeRules} = require("./lib/abp2chromerules");

    let chromeRules = new ChromeRules();
    for (let filter in filters)
      chromeRules.processFilter(filter);

    let rules = chromeRules.generateRules();

It's important to note that `ChromeRules.prototype.processFilter` expects a
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
