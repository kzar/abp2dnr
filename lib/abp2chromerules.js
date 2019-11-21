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

const {RegExpFilter, ContentFilter,
       WhitelistFilter} = require("adblockpluscore/lib/filterClasses");
const rewriteResources = require("adblockpluscore/data/resources");

const typeMap = RegExpFilter.typeMap;

const requestTypes = new Map([
  [typeMap.OTHER, ["other", "csp_report"]],
  [typeMap.SCRIPT, ["script"]],
  [typeMap.IMAGE, ["image"]],
  [typeMap.STYLESHEET, ["stylesheet"]],
  [typeMap.OBJECT, ["object"]],
  [typeMap.SUBDOCUMENT, ["sub_frame"]],
  [typeMap.WEBSOCKET, ["websocket"]],
  [typeMap.PING, ["ping"]],
  [typeMap.XMLHTTPREQUEST, ["xmlhttprequest"]],
  [typeMap.MEDIA, ["media"]],
  [typeMap.FONT, ["font"]]
]);

const supportedRequestTypes = Array.from(requestTypes.keys())
                                   .reduce(((wt, ct) => wt | ct));

// Chrome can't distinguish between OBJECT_SUBREQUEST and OBJECT requests.
typeMap.OBJECT_SUBREQUEST = typeMap.OBJECT;

function getResourceTypes(filterContentType)
{
  // The default is to match everything except "main_frame", which is fine.
  if ((filterContentType & supportedRequestTypes) == supportedRequestTypes)
    return;

  let result = [];

  for (let [mask, types] of requestTypes)
  {
    if (filterContentType & mask)
      result = result.concat(types);
  }

  return result;
}

function getDomains(filterDomains, isWhitelistFilter, specificOnlyDomains)
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

  if (isGenericFilter && !isWhitelistFilter && specificOnlyDomains.length)
    excludedDomains = excludedDomains.concat(specificOnlyDomains);

  return [domains, excludedDomains];
}

function generateRule(filterDetails, id, specificOnlyDomains)
{
  let {filter, urlFilter, matchCase} = filterDetails;

  let rule = {
    id, condition: {urlFilter},
    action: {type: filter instanceof WhitelistFilter ? "allow" : "block"}
  };

  if (filter.rewrite)
  {
    let {rewrite} = filter;

    // We don't know about this abp-resource, so we'll have to skip.
    if (!Object.prototype.hasOwnProperty.call(rewriteResources, rewrite))
      return;

    rule.priority = 1;
    rule.action.type = "redirect";
    rule.action.redirectUrl = rewriteResources[rewrite];
  }

  let resourceTypes = getResourceTypes(filter.contentType);
  if (resourceTypes)
  {
    // Looks like we can't generate a rule since none of the supported content
    // types were found.
    if (resourceTypes.length == 0)
      return;

    rule.condition.resourceTypes = resourceTypes;
  }

  if (!matchCase)
    rule.condition.isUrlFilterCaseSensitive = false;

  let [domains, excludedDomains] = getDomains(filter.domains,
                                              filter instanceof WhitelistFilter,
                                              specificOnlyDomains);
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

    // The declarativeNetRequest API doesn't support $sitekey whitelisting...
    if (filter.sitekeys)
      continue;
    // ... nor element hiding...
    if (filter instanceof ContentFilter)
      continue;
    // ... nor regular expression based matching.
    if (filter.pattern == null)
      continue;

    let filterDetails = {
      filter,
      urlFilter: filter.pattern,
      matchCase: filter.matchCase
    };

    // We need to split out the hostname part (if any) of the filter, then
    // decide if it can be matched as lowercase or not.
    let hostname;
    let justHostname = false;
    let match = /^(\|\||[a-zA-Z]*:\/\/)([^*^?/|]*)(.*)$/.exec(filter.pattern);
    if (match)
    {
      hostname = match[2].toLowerCase();
      filterDetails.urlFilter = match[1] + hostname + match[3];

      justHostname = match[3].length < 2;
      filterDetails.matchCase = filterDetails.matchCase ||
                                justHostname || !/[a-zA-Z]/.test(match[3]);
    }

    if (filter instanceof WhitelistFilter)
    {
      if (filter.contentType & typeMap.DOCUMENT && justHostname)
        whitelistedDomains.push(hostname);

      if (filter.contentType & typeMap.GENERICBLOCK && hostname)
        specificOnlyDomains.push(hostname);

      if (filter.contentType & supportedRequestTypes)
        processedFilters.push(filterDetails);
    }
    else
      processedFilters.push(filterDetails);
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

  for (let filterDetails of processedFilters)
  {
    let rule = generateRule(filterDetails, nextId, specificOnlyDomains);
    if (rule)
    {
      rules.push(rule);
      nextId += 1;
    }
  }

  return rules;
}

exports.generateRules = generateRules;
