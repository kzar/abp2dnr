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

const {URL} = require("url");

const {RegExpFilter, ContentFilter, WhitelistFilter} = require("filterClasses");
const rewriteResources = require("resources");

const typeMap = RegExpFilter.typeMap;

const contentTypes = new Map([
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

const supportedRequestTypes = Array.from(contentTypes.keys())
                                   .reduce(((wt, ct) => wt | ct));

// Chrome can't distinguish between OBJECT_SUBREQUEST and OBJECT requests.
typeMap.OBJECT_SUBREQUEST = typeMap.OBJECT;

function getResourceTypes(contentType)
{
  // The default is to match everything except "main_frame", which is fine.
  if ((contentType & supportedRequestTypes) == supportedRequestTypes)
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
  let whitelistFilter = filter instanceof WhitelistFilter;
  let rule = {
    id,
    condition: {urlFilter: filter.pattern},
    action: {type: whitelistFilter ? "allow" : "block"}
  };

  if (filter.rewrite)
  {
    let {rewrite} = filter;

    // We can't support placeholder values, so we'll have to skip this filter.
    if (/\$[\d]/.test(rewrite))
      return;

    let match = /^abp-resource:(.+)$/.exec(rewrite);
    if (match)
    {
      // We don't know about this abp-resource, so we'll have to skip.
      if (!rewriteResources.hasOwnProperty(match[1]))
        return;

      rewrite = rewriteResources[match[1]];
    }
    else
    {
      // We can't support relative redirections either.
      try
      {
        new URL(rewrite);
      }
      catch (e)
      {
        return;
      }
    }

    rule.priority = 1;
    rule.action.type = "redirect";
    rule.action.redirectUrl = rewrite;
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

  // Chrome's default is to match case sensitively, but the default with
  // Adblock Plus filters is the opposite. So for most rules we turn
  // case sensitive matching off, but as a small optimisation we can avoid
  // doing that if the filter only contains the hostname part.
  if (filter.justHostname)
    rule.condition.urlFilter = rule.condition.urlFilter.toLowerCase();
  if (!filter.matchCase && !filter.justHostname)
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
        (enabled ? domains : excludedDomains).push(domain);
    }
  }

  if (genericFilter && !whitelistFilter && genericBlockExceptionDomains.length)
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

    // The declarativeNetRequest API doesn't support $sitekey whitelisting...
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
    let match = /^(\|\||[a-zA-Z]*:\/\/)([^*^?/|]*)(.*)$/.exec(filter.pattern);
    if (match)
    {
      filter.hostname = match[2].toLowerCase();
      filter.justHostname = match[3].length < 2;
    }

    if (filter instanceof WhitelistFilter)
    {
      if (filter.contentType & typeMap.DOCUMENT && filter.justHostname)
        whitelistedDomains.push(filter.hostname);

      if (filter.contentType & typeMap.GENERICBLOCK && filter.hostname)
        specificOnlyDomains.push(filter.hostname);

      if (filter.contentType & supportedRequestTypes)
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
