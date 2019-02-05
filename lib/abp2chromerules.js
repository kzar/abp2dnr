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

/** @module abp2chromerules */

"use strict";

let {RegExpFilter, ContentFilter,
     WhitelistFilter, BlockingFilter} = require("filterClasses");

const typeMap = RegExpFilter.typeMap;

const contentTypes = new Map([
  [typeMap.IMAGE, ["image"]],
  [typeMap.STYLESHEET, ["stylesheet"]],
  [typeMap.SCRIPT, ["script"]],
  [typeMap.FONT, ["font"]],
  [typeMap.MEDIA, ["media"]],
  [typeMap.OBJECT, ["object"]],
  [typeMap.XMLHTTPREQUEST, ["xmlhttprequest"]],
  [typeMap.WEBSOCKET, ["websocket"]],
  [typeMap.PING, ["ping"]],
  [typeMap.SUBDOCUMENT, ["sub_frame"]],
  [typeMap.OTHER, ["other", "csp_report"]]
]);

const whitelistableRequestTypes = Array.from(contentTypes.keys())
                                       .reduce(((wt, ct) => wt | ct));

// Chrome can't distinguish between OBJECT_SUBREQUEST and OBJECT requests.
typeMap.OBJECT_SUBREQUEST = typeMap.OBJECT;

function getResourceTypes(contentType)
{
  // The default is to match everything except "main_frame", which is fine.
  if (contentType == RegExpFilter.prototype.contentType)
    return;

  let result = [];

  for (let [mask, types] of contentTypes)
  {
    if (contentType & mask)
      result = result.concat(types);
  }

  return result;
}

function generateRule(filter, id, genericBlockExceptionDomains)
{
  let blockingFilter = filter instanceof BlockingFilter;
  let rule = {
    id,
    condition: {urlFilter: filter.pattern},
    action: {type: blockingFilter ? "block" : "allow"}
  };

  let resourceTypes = getResourceTypes(filter.contentType);
  if (resourceTypes)
  {
    // Looks like we can't generate a rule since none of the supported content
    // types were found.
    if (resourceTypes.length == 0)
      return;

    rule.condition.resourceTypes = resourceTypes;
  }

  // For rules containing only a hostname we know that we're matching against
  // a lowercase string unless the matchCase option was passed.
  if (filter.canSafelyMatchAsLowercase && !filter.matchCase)
    rule.condition.urlFilter = rule.condition.urlFilter.toLowerCase();

  if (!filter.canSafelyMatchAsLowercase && !filter.matchCase)
    rule.condition.isUrlFilterCaseSensitive = false;

  let domains = [];
  let excludedDomains = [];
  let genericFilter = true;
  if (filter.domains)
  {
    for (let [domain, enabled] of filter.domains)
    {
      if (domain == "")
        genericFilter = enabled;
      else
        (enabled ? domains : excludedDomains).push(domain.toLowerCase());
    }
  }

  if (genericFilter && blockingFilter && genericBlockExceptionDomains.length)
    excludedDomains = excludedDomains.concat(genericBlockExceptionDomains);

  if (domains.length)
    rule.condition.domains = domains;
  if (excludedDomains.length)
    rule.condition.excludedDomains = excludedDomains;

  if (filter.thirdParty != null)
    rule.condition.domainType = filter.thirdParty ? "thirdParty" : "firstParty";

  return rule;
}

function processFilters(filters)
{
  let specificOnlyDomains = [];
  let whitelistedDomains = [];
  let processedFilters = [];

  for (let filter of filters)
  {
    // We expect filters to use Punycode for domains these days, so let's just
    // skip filters which don't. See #6647.
    if (/[^\x00-\x7F]/.test(filter.text))
      continue;

    // The declarativeNetRequest doesn't support $sitekey whitelisting...
    if (filter.sitekeys)
      continue;
    // ... nor element hiding...
    if (filter instanceof ContentFilter)
      continue;
    // ... nor regular expression based matching.
    if (filter.pattern == null)
      continue;

    // We need to split out the hostname part (if any) of the filter, then
    // decide if it can be matched as lowercase or not.
    let justHostname = false;
    let match = /^(\|\||[a-zA-Z]*:\/\/)([^*^?/|]*)(.*)$/.exec(filter.pattern);
    if (match)
    {
      filter.hostname = match[2];
      justHostname = match[3].length < 2;
      filter.canSafelyMatchAsLowercase = justHostname || !/[a-zA-Z]/.test(match[3]);
    }

    if (filter instanceof WhitelistFilter)
    {
      if (filter.contentType & typeMap.DOCUMENT && justHostname)
        whitelistedDomains.push(filter.hostname);

      if (filter.contentType & typeMap.GENERICBLOCK && filter.hostname)
        specificOnlyDomains.push(filter.hostname);

      if (filter.contentType & whitelistableRequestTypes)
        processedFilters.push(filter);
    }
    else
      processedFilters.push(filter);
  }

  return [specificOnlyDomains, whitelistedDomains, processedFilters];
}

/**
 * Generates chrome.declarativeNetRequest rules from the given
 * Adblock Plus filters.
 * @param {Filter[]} filters Filters to convert
 * @returns {Object[]} The generated rules
 *
 */
function generateRules(filters)
{
  let [specificOnlyDomains, whitelistedDomains,
       processedFilters] = processFilters(filters);

  let nextId = 1;
  let rules = [];

  if (whitelistedDomains.length)
  {
    rules.push({
      id: nextId++,
      condition: {
        domains: whitelistedDomains
      },
      action: {type: "allow"}
    });
  }

  for (let filter of processedFilters)
  {
    let rule = generateRule(filter, nextId, specificOnlyDomains);
    if (rule)
    {
      rules.push(rule);
      nextId += 1;
    }
  }

  return rules;
}

exports.generateRules = generateRules;
