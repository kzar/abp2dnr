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

// We differentiate generic rules from specific ones in order to support the
// conversion of $genericblock exception filters. Since with the
// declarativeNetRequest API "allow" rules take priority over "allowAllRequest"
// rules, we also need to take care to give "allowAllRequest" rules a slighlty
// higher priority.
const GENERIC_PRIORITY = 1000;
const GENERIC_ALLOW_ALL_PRIORITY = 1001;
const SPECIFIC_PRIORITY = 2000;
const SPECIFIC_ALLOW_ALL_PRIORITY = 2001;

const {
  CommentFilter,
  ContentFilter,
  Filter,
  InvalidFilter,
  WhitelistFilter: AllowlistFilter
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
  // The default is to match everything except "main_frame", which is fine.
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

function getCondition(filter, urlFilter, resourceTypes, matchCase)
{
  let condition = {};

  if (urlFilter)
    condition.urlFilter = urlFilter;
  else if (filter.regexp)
    condition.regexFilter = filter.regexp.source;

  if (resourceTypes)
    condition.resourceTypes = resourceTypes;

  if (!matchCase)
    condition.isUrlFilterCaseSensitive = false;

  if (filter.thirdParty != null)
    condition.domainType = filter.thirdParty ? "thirdParty" : "firstParty";

  let {domains, excludedDomains, isGenericFilter} = getDomains(filter.domains);

  if (domains.length)
    condition.domains = domains;
  if (excludedDomains.length)
    condition.excludedDomains = excludedDomains;

  return [condition, isGenericFilter];
}

function generateRedirectRules(filter, urlFilter, matchCase)
{
  let url = rewriteResources[filter.rewrite];

  // We can't generate rules for unknown abp-resources...
  if (!url)
    return [];

  let resourceTypes = getResourceTypes(filter.contentType);

  // We can't generate rules for filters which don't include any supported
  // resource types.
  if (resourceTypes && resourceTypes.length == 0)
    return [];

  let [condition, isGenericFilter] = getCondition(
    filter, urlFilter, resourceTypes, matchCase
  );

  return [{
    priority: isGenericFilter ? GENERIC_PRIORITY : SPECIFIC_PRIORITY,
    condition,
    action: {
      type: "redirect",
      redirect: {url}
    }
  }];
}

function generateCSPRules(filter, urlFilter, matchCase)
{
  let [condition, isGenericFilter] = getCondition(
    filter, urlFilter, ["main_frame", "sub_frame"], matchCase
  );

  if (filter instanceof AllowlistFilter)
  {
    // The DNR makes no distinction between CSP rules and main_frame/sub_frame
    // rules. Ideally, we would give CSP rules a different priority therefore,
    // to ensure that a $csp exception filter would not accidentally allowlist
    // the whole website. Unfortunately, I don't think that's possible if we are
    // to also support the distinction between specific and generic rules.
    //   Luckily, we are adding an "allow" rule (not "allowAllRequest") here and
    // there is no such thing as a blocking filter which applies to the
    // $document (main_frame), so we don't have to worry about that. There is
    // such a thing as a $subdocument blocking filter though, which a $csp
    // exception filter should not usually affect.
    //   As a compromise in order to support both $csp and $genericblock, we
    // accept that $csp exception filters might wrongly prevent frame-blocking
    // filters from matching. If this compromise proves problematic, we might
    // need to reconsider this in the future.
    return [{
      action: {
        type: "allow"
      },
      condition,
      priority: filter.contentType & contentTypes.GENERICBLOCK ?
                  GENERIC_PRIORITY : SPECIFIC_PRIORITY
    }];
  }

  return [{
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
  }];
}

function generateBlockRules(filter, urlFilter, matchCase)
{
  let resourceTypes = getResourceTypes(filter.contentType);

  // We can't generate rules for filters which don't include any supported
  // resource types.
  if (resourceTypes && resourceTypes.length == 0)
    return [];

  let [condition, isGenericFilter] = getCondition(
    filter, urlFilter, resourceTypes, matchCase
  );

  return [{
    priority: isGenericFilter ? GENERIC_PRIORITY : SPECIFIC_PRIORITY,
    condition,
    action: {
      type: "block"
    }
  }];
}

function generateAllowRules(filter, urlFilter, matchCase)
{
  let rules = [];
  let {contentType} = filter;

  let genericBlock = contentType & contentTypes.GENERICBLOCK;

  if (contentType & contentTypes.DOCUMENT || genericBlock)
  {
    contentType &= ~contentTypes.SUBDOCUMENT;

    rules.push({
      priority: genericBlock ?
                  GENERIC_ALLOW_ALL_PRIORITY : SPECIFIC_ALLOW_ALL_PRIORITY,
      condition: getCondition(filter, urlFilter,
                              ["main_frame", "sub_frame"], matchCase)[0],
      action: {
        type: "allowAllRequests"
      }
    });
  }

  let resourceTypes = getResourceTypes(contentType);
  if (!resourceTypes || resourceTypes.length)
  {
    rules.push({
      priority: genericBlock ? GENERIC_PRIORITY : SPECIFIC_PRIORITY,
      condition: getCondition(filter, urlFilter, resourceTypes, matchCase)[0],
      action: {
        type: "allow"
      }
    });
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
 *   We return an array of generated rules, if any.
 *   Note: We don't assign the returned rules an ID, so take care to do that
 *         before you use the rules.
 */
async function convertFilter(filter, isRegexSupported)
{
  filter = Filter.fromText(filter.text);

  // We can't do anything with a non-filter filter.
  if (!(filter instanceof Filter))
    return [];
  // We can't do anything with comments or invalid filters.
  if (filter instanceof CommentFilter || filter instanceof InvalidFilter)
    return [];
  // We expect filters to use Punycode for domains these days, so let's just
  // skip filters which don't. See #6647.
  if (/[^\x00-\x7F]/.test(filter.text))
    return [];
  // The declarativeNetRequest API doesn't support $sitekey allowlisting...
  if (filter.sitekeys)
    return [];
  // ... nor element hiding...
  if (filter instanceof ContentFilter)
    return [];

  let {matchCase, pattern: urlFilter} = filter;
  let hostname;

  if (urlFilter)
  {
    // We need to split out the hostname part (if any) of the filter, then
    // decide if it can be matched as lowercase or not.
    let match = /^(\|\||[a-zA-Z]*:\/\/)([^*^?/|]*)(.*)$/.exec(filter.pattern);
    if (match)
    {
      hostname = match[2].toLowerCase();

      urlFilter = match[1] + hostname + match[3];
      matchCase = matchCase ||
                  match[3].length < 2 ||
                  !/[a-zA-Z]/.test(match[3]);
    }

    // The declarativeNetRequest API does not like the urlFilter to have a
    // redundant ||* prefix, so let's strip that now.
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
  else if (filter instanceof AllowlistFilter)
    result = generateAllowRules(filter, urlFilter, matchCase);
  else if (filter.rewrite)
    result = generateRedirectRules(filter, urlFilter, matchCase);
  else
    result = generateBlockRules(filter, urlFilter, matchCase);

  return result;
}

exports.convertFilter = convertFilter;
exports.GENERIC_PRIORITY = GENERIC_PRIORITY;
exports.GENERIC_ALLOW_ALL_PRIORITY = GENERIC_ALLOW_ALL_PRIORITY;
exports.SPECIFIC_PRIORITY = SPECIFIC_PRIORITY;
exports.SPECIFIC_ALLOW_ALL_PRIORITY = SPECIFIC_ALLOW_ALL_PRIORITY;
