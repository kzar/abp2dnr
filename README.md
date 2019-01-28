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

The filterClasses module in `node_modules/filterClasses.js` is generated from
the module in the `adblockpluscore` repository. It has been generated using
JS Hydra, and small modifications made. If you need to re-generate the file run
this command (adjusting the paths as appropriate):

```
python buildtools/jshydra/abp_rewrite.py adblockpluscore/lib/filterClasses.js | grep -vi filterNotifier > ../abp2chromerules/node_modules/filterClasses.js
```
You will then need to remove any references to the `utils` module from the
generated file by hand.


## Usage

Create a chrome.declarativeNetRequest rule list `output.json` from the Adblock Plus filter list `input.txt`:
```
node abp2chromerules.js < input.txt > output.json
```
