# abp2chromerules

This is a script to convert [Adblock Plus filter lists](https://adblockplus.org/filters)
to [chrome.declarativeNetRequest rules](https://developer.chrome.com/extensions/declarativeNetRequest).

Note that `chrome.declarativeNetRequest` is quite limited. Hence, not all filters
can be converted (in a compatible way), and some differences compared to Adblock
Plus for other browsers are expected.

## Requirements

The required packages can be installed via [NPM](https://npmjs.org):

```
npm install
```

### filterClasses.js

The filterClasses (also common and coreUtils) in `node_modules/filterClasses.js`
are taken from the `adblockpluscore` repository, with small modifications made.

If you need to refresh those files, run these commands (adjusting the paths as appropriate):

```
cp adblockpluscore/lib/common.js ../abp2blocklist/node_modules/
cp adblockpluscore/lib/coreUtils.js ../abp2blocklist/node_modules/
grep -vi filterNotifier adblockpluscore/lib/filterClasses.js > abp2chromerules/node_modules/filterClasses.js
```

## Usage

Create a `chrome.declarativeNetRequest` rule list `output.json` from the Adblock Plus filter list `input.txt`:
```
node abp2chromerules.js < input.txt > output.json
```

## Tests

Unit tests live in the `tests/` directory. To run the unit tests ensure you have
already installed the required packages (see above) and then type this command:

```
npm test
```

## Linting

You can lint the code using [ESLint](http://eslint.org):

    npm run lint

_Note: You'll need to install the [eslint-config-eyeo][1] configuration first._

[1]: https://hg.adblockplus.org/codingtools/file/tip/eslint-config-eyeo
