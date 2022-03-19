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

/** @module abp2dnr */

"use strict";

// Differentiate generic rules from specific ones in order to support the
// conversion of $genericblock exception filters. Also take care to give
// "allowAllRequests" rules a higher priority, otherwise "allow" rules take
// precedence.
const GENERIC_PRIORITY = 1000;
const GENERIC_ALLOW_ALL_PRIORITY = 1001;
const SPECIFIC_PRIORITY = 2000;
const SPECIFIC_ALLOW_ALL_PRIORITY = 2001;

// Generally, filters don't apply to main_frame requests. But there are some
// special cases ($csp and $document allowlisting) where filters translate to
// rules that apply to both main_frame and sub_frame requests. These rules need
// to be handled differently, so let's use a Symbol for that edge-case. A symbol
// is cheaper and easier to compare with than `["main_frame", "sub_frame"]`.
const MAIN_FRAME_SUB_FRAME = Symbol();

// Regular expression for the prefix, hostname and suffix of a filter.
const URLFILTER_PARTS_REGEXP = /^(\|\||[a-zA-Z]*:\/\/)([^*^?/|]*)(.*)$/;

const {
  CommentFilter,
  ContentFilter,
  Filter,
  InvalidFilter,
  AllowingFilter
} = require("adblockpluscore/lib/filterClasses");

const rewriteResources = require("adblockpluscore/data/resources");

const {contentTypes} = require("adblockpluscore/lib/contentTypes");

const requestTypes = new Map([
  [contentTypes.OTHER, ["other", "csp_report"]],
  [contentTypes.SCRIPT, ["script"]],
  [contentTypes.IMAGE, ["image"]],
  [contentTypes.STYLESHEET, ["stylesheet"]],
  [contentTypes.OBJECT, ["object"]],
  [contentTypes.SUBDOCUMENT, ["sub_frame"]],
  [contentTypes.WEBSOCKET, ["websocket"]],
  [contentTypes.PING, ["ping"]],
  [contentTypes.XMLHTTPREQUEST, ["xmlhttprequest"]],
  [contentTypes.MEDIA, ["media"]],
  [contentTypes.FONT, ["font"]]
]);

const supportedRequestTypes = Array.from(requestTypes.keys())
                                   .reduce(((srt, t) => srt | t));

// Chrome can't distinguish between OBJECT_SUBREQUEST and OBJECT requests.
contentTypes.OBJECT_SUBREQUEST = contentTypes.OBJECT;

function getResourceTypes(filterContentType)
{
  // The default is to match everything except main_frame requests, which is
  // fine.
  if ((filterContentType & supportedRequestTypes) == supportedRequestTypes)
  {
    return;
  }

  let result = [];

  for (let [mask, types] of requestTypes)
  {
    if (filterContentType & mask)
      result = result.concat(types);
  }

  return result;
}

function getDomains(filterDomains)
{
  let domains = [];
  let excludedDomains = [];
  let isGenericFilter = true;

  if (filterDomains)
  {
    for (let [domain, enabled] of filterDomains)
    {
      if (domain == "")
        isGenericFilter = enabled;
      else
        (enabled ? domains : excludedDomains).push(domain);
    }
  }

  return {domains, excludedDomains, isGenericFilter};
}

function getConditions(filter, urlFilter, resourceTypes, matchCase)
{
  let mainFrameSubFrame = false;
  let conditions = [];
  let condition = {};

  if (urlFilter)
    condition.urlFilter = urlFilter;
  else if (filter.regexp)
    condition.regexFilter = filter.regexp.source;

  if (resourceTypes)
  {
    if (resourceTypes === MAIN_FRAME_SUB_FRAME)
      mainFrameSubFrame = true;
    else
      condition.resourceTypes = resourceTypes;
  }

  if (!matchCase && (condition.urlFilter || condition.regexFilter))
    condition.isUrlFilterCaseSensitive = false;

  if (filter.thirdParty != null)
    condition.domainType = filter.thirdParty ? "thirdParty" : "firstParty";

  let {domains, excludedDomains, isGenericFilter} = getDomains(filter.domains);

  // The $domain filter option applies to the initiator domain generally, but
  // the request domain for main_frame requests. If this rule applies to
  // main_frame requests and has a domain condition, take care to generate
  // a separate rule condition that will match main_frame requests correctly.
  if (mainFrameSubFrame)
  {
    if (domains.length || excludedDomains.length)
    {
      let mainFrameCondition = JSON.parse(JSON.stringify(condition));
      if (domains.length)
        mainFrameCondition.requestDomains = domains;
      if (excludedDomains.length)
        mainFrameCondition.excludedRequestDomains = excludedDomains;
      mainFrameCondition.resourceTypes = ["main_frame"];
      conditions.push(mainFrameCondition);

      condition.resourceTypes = ["sub_frame"];
    }
    else
      condition.resourceTypes = ["main_frame", "sub_frame"];
  }

  if (domains.length)
    condition.initiatorDomains = domains;
  if (excludedDomains.length)
    condition.excludedInitiatorDomains = excludedDomains;

  conditions.push(condition);
  return [conditions, isGenericFilter];
}

function generateRedirectRules(filter, urlFilter, matchCase)
{
  let url = rewriteResources[filter.rewrite];

  // Ignore filters with unknown abp-resources.
  if (!url)
    return [];

  let resourceTypes = getResourceTypes(filter.contentType);

  // Ignore filters with only unsupported resource types.
  if (resourceTypes && resourceTypes.length == 0)
    return [];

  let [conditions, isGenericFilter] = getConditions(
    filter, urlFilter, resourceTypes, matchCase
  );
  let priority = isGenericFilter ? GENERIC_PRIORITY : SPECIFIC_PRIORITY;

  return conditions.map(condition => ({
    priority,
    condition,
    action: {
      type: "redirect",
      redirect: {url}
    }
  }));
}

function generateCSPRules(filter, urlFilter, matchCase)
{
  let [conditions, isGenericFilter] = getConditions(
    filter, urlFilter, MAIN_FRAME_SUB_FRAME, matchCase
  );
  let priority = filter.contentType & contentTypes.GENERICBLOCK ?
                   GENERIC_PRIORITY : SPECIFIC_PRIORITY;

  return conditions.map(condition =>
  {
    if (filter instanceof AllowingFilter)
    {
      // Note: This is not a perfect translation of a $csp allowlisting filter,
      //       since it could also prevent $subdocument blocking filters from
      //       blocking frames on the page.
      return {
        action: {
          type: "allow"
        },
        condition,
        priority
      };
    }

    return {
      action: {
        type: "modifyHeaders",
        responseHeaders: [{
          header: "Content-Security-Policy",
          operation: "append",
          value: filter.csp
        }]
      },
      condition,
      priority: isGenericFilter ? GENERIC_PRIORITY : SPECIFIC_PRIORITY
    };
  });
}

function generateBlockRules(filter, urlFilter, matchCase)
{
  let resourceTypes = getResourceTypes(filter.contentType);

  // Ignore filters with only unsupported resource types.
  if (resourceTypes && resourceTypes.length == 0)
    return [];

  let [conditions, isGenericFilter] = getConditions(
    filter, urlFilter, resourceTypes, matchCase
  );
  let priority = isGenericFilter ? GENERIC_PRIORITY : SPECIFIC_PRIORITY;

  return conditions.map(condition => ({
    priority,
    condition,
    action: {
      type: "block"
    }
  }));
}

function generateAllowRules(filter, urlFilter, matchCase)
{
  let rules = [];
  let {contentType} = filter;

  let genericBlock = contentType & contentTypes.GENERICBLOCK;

  if (contentType & contentTypes.DOCUMENT || genericBlock)
  {
    contentType &= ~contentTypes.SUBDOCUMENT;

    let priority = genericBlock ?
                    GENERIC_ALLOW_ALL_PRIORITY : SPECIFIC_ALLOW_ALL_PRIORITY;
    for (let condition of getConditions(filter, urlFilter,
                                        MAIN_FRAME_SUB_FRAME, matchCase)[0])
    {
      rules.push({
        priority,
        condition,
        action: {
          type: "allowAllRequests"
        }
      });
    }
  }

  let resourceTypes = getResourceTypes(contentType);
  if (!resourceTypes || resourceTypes.length)
  {
    let priority = genericBlock ? GENERIC_PRIORITY : SPECIFIC_PRIORITY;
    for (let condition of getConditions(filter, urlFilter,
                                        resourceTypes, matchCase)[0])
    {
      rules.push({
        priority,
        condition,
        action: {
          type: "allow"
        }
      });
    }
  }

  return rules;
}

/**
 * Processes the given Adblock Plus filter, converting it into
 * chrome.declarativeNetRequet rule(s) if possible.
 * @param {Filter} filter
 *   Filter to process
 * @param {function} [isRegexSupported]
 *   For regular expression filter support, provide this function which
 *   checks if the given regular expression is supported by the
 *   declarativeNetRequest API. If omitted, regular expression filters will be
 *   ignored.
 *   See https://developer.chrome.com/extensions/declarativeNetRequest#method-isRegexSupported
 *   for the expected function signature.
 * @returns {Object[]}
 *   The generated rules.
 *   Note: The rules do not have an ID assigned, take care to assign IDs before
 *         using them.
 */
async function convertFilter(filter, isRegexSupported)
{
  filter = Filter.fromText(filter.text);

  // Ignore non-filters.
  if (!(filter instanceof Filter))
    return [];
  // Ignore comment and invalid filters.
  if (filter instanceof CommentFilter || filter instanceof InvalidFilter)
    return [];
  // Ignore filters containing Unicode
  // See https://issues.adblockplus.org/ticket/6647
  if (/[^\x00-\x7F]/.test(filter.text))
    return [];
  // Ignore $sitekey filters.
  if (filter.sitekeys)
    return [];
  // Ignore content (e.g. element hiding) filters.
  if (filter instanceof ContentFilter)
    return [];

  let {matchCase, pattern: urlFilter} = filter;
  let hostname;

  if (urlFilter)
  {
    // Split out the hostname part (if any) of the filter, then decide if it can
    // be matched as lowercase or not.
    // Note: Filters that only contain a hostname could make use of the
    //       requestDomain rule condition instead of having a ||hostname^
    //       urlFilter. That's worth doing when combining such rules
    //       (see `compressRules`), since the declarativeNetRequest can
    //       efficiently match against long lists of domains[1].
    // 1 - https://source.chromium.org/chromium/chromium/src/+/main:components/url_pattern_index/url_pattern_index.cc;l=566-619
    let match = URLFILTER_PARTS_REGEXP.exec(filter.pattern);
    if (match)
    {
      hostname = match[2].toLowerCase();

      urlFilter = match[1] + hostname + match[3];
      matchCase = matchCase ||
                  match[3].length < 2 ||
                  !/[a-zA-Z]/.test(match[3]);
    }

    // Strip redundant ||* prefixes from filters, since the
    // declarativeNetRequest API rejects those.
    if (urlFilter.startsWith("||*"))
      urlFilter = urlFilter.substr(3);
  }
  else if (filter.regexp &&
           !(isRegexSupported &&
             (await isRegexSupported({
               regex: filter.regexp.source,
               isCaseSensitive: matchCase
             })).isSupported))
  {
    return [];
  }

  let result;

  if (filter.contentType & contentTypes.CSP)
    result = generateCSPRules(filter, urlFilter, matchCase);
  else if (filter instanceof AllowingFilter)
    result = generateAllowRules(filter, urlFilter, matchCase);
  else if (filter.rewrite)
    result = generateRedirectRules(filter, urlFilter, matchCase);
  else
    result = generateBlockRules(filter, urlFilter, matchCase);

  return result;
}

/**
 * Take an array of declarativeNetRequest rules, combine where
 * possible and return the hopefully shorter array of rules.
 * Notes:
 *  - Ensure that the rules passsed in do not have IDs.
 *  - Using this function will invalidate any filter to rule mapping that you
 *    may have.
 *  - Ordering of the rules is not preserved and the rule Objects may be
 *    mutated or replaced.
 *  - The implementation of this algorithm is rather crude and could certainly
 *    be improved given more time.
 * @param {Object[]} rules
 *   The array of rules to shrink.
 * @returns {Object[]}
 */
function compressRules(rules)
{
  let compressedRules = [];
  let requestDomainsByStringifiedRule = new Map();
  let urlFilterByStringifiedRule = new Map();

  for (let rule of rules)
  {
    if (rule.condition &&
        rule.condition.urlFilter &&
        !rule.condition.requestDomains &&
        !rule.condition.excludedRequestDomains)
    {
      let match = URLFILTER_PARTS_REGEXP.exec(rule.condition.urlFilter);
      if (match && match[1] == "||" && match[2] && match[3] == "^")
      {
        let {urlFilter} = rule.condition;
        delete rule.condition.urlFilter;

        let key = JSON.stringify(rule);
        urlFilterByStringifiedRule.set(key, urlFilter);

        let requestDomains = requestDomainsByStringifiedRule.get(key);
        if (!requestDomains)
        {
          requestDomains = [];
          requestDomainsByStringifiedRule.set(key, requestDomains);
        }
        requestDomains.push(match[2].toLowerCase());
        continue;
      }
    }

    compressedRules.push(rule);
  }

  for (let [stringifiedRule, domains] of requestDomainsByStringifiedRule)
  {
    let rule = JSON.parse(stringifiedRule);
    if (domains.length > 1)
      rule.condition.requestDomains = domains;
    else
      rule.condition.urlFilter =
        urlFilterByStringifiedRule.get(stringifiedRule);

    compressedRules.push(rule);
  }

  return compressedRules;
}

exports.convertFilter = convertFilter;
exports.compressRules = compressRules;
exports.GENERIC_PRIORITY = GENERIC_PRIORITY;
exports.GENERIC_ALLOW_ALL_PRIORITY = GENERIC_ALLOW_ALL_PRIORITY;
exports.SPECIFIC_PRIORITY = SPECIFIC_PRIORITY;
exports.SPECIFIC_ALLOW_ALL_PRIORITY = SPECIFIC_ALLOW_ALL_PRIORITY;
