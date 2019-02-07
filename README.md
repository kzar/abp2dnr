# abp2chromerules

This is a script to convert [Adblock Plus filter lists](https://adblockplus.org/filters)
to [chrome.declarativeNetRequest rules](https://developer.chrome.com/extensions/declarativeNetRequest)
as far as is possible.

## Requirements

The required packages can be installed via [npm](https://npmjs.org):

    npm install

## Usage

Create a `chrome.declarativeNetRequest` rule list `output.json` from the Adblock Plus filter list `input.txt`:

    node abp2chromerules.js < input.txt > output.json

## Tests

Unit tests live in the `tests/` directory. You can run them by typing this command:

    npm test

## Linting

You can lint the code by typing this command:

    npm run lint

## Adblock Plus core code

To parse the Adblock Plus filters, we reuse parts of the core Adblock Plus code,
those files are inside the adblockpluscore directory.

If you need to refresh those files, run these commands (adjusting the paths as appropriate):

    cp adblockpluscore/data/resources.json abp2blocklist/adblockpluscore/data/
    cp adblockpluscore/lib/common.js abp2blocklist/adblockpluscore/lib/
    cp adblockpluscore/lib/coreUtils.js abp2blocklist/adblockpluscore/lib/
    grep -vi filterNotifier adblockpluscore/lib/filterClasses.js > abp2chromerules/adblockpluscore/lib/filterClasses.js
