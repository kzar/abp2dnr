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
