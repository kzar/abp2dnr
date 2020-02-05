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

const {typeMap} = RegExpFilter;

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
                                   .reduce(((srt, t) => srt | t));

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

function rulesFromFilterDetails(filterDetails, specificOnlyDomains)
{
  let {filter, urlFilter, matchCase, resourceTypes} = filterDetails;

  const whitelistFilter = filter instanceof WhitelistFilter;

  let rule = {
    priority: 1,
    condition: {
      urlFilter
    },
    action: {
      type: whitelistFilter ? "allow" : "block"
    }
  };

  if (filter.rewrite)
  {
    rule.action.type = "redirect";
    rule.action.redirectUrl = rewriteResources[filter.rewrite];
  }

  if (resourceTypes)
    rule.condition.resourceTypes = resourceTypes;

  if (!matchCase)
    rule.condition.isUrlFilterCaseSensitive = false;

  let [domains, excludedDomains] = getDomains(filter.domains,
                                              whitelistFilter,
                                              specificOnlyDomains);
  if (domains.length)
    rule.condition.domains = domains;
  if (excludedDomains.length)
    rule.condition.excludedDomains = excludedDomains;

  if (filter.thirdParty != null)
    rule.condition.domainType = filter.thirdParty ? "thirdParty" : "firstParty";

  if (whitelistFilter && filter.contentType & typeMap.DOCUMENT)
  {
    let allowAllRule = JSON.parse(JSON.stringify(rule));

    allowAllRule.action.type = "allowAllRequests";
    allowAllRule.condition.resourceTypes = ["main_frame"];

    if (filter.contentType & typeMap.SUBDOCUMENT)
    {
      allowAllRule.condition.resourceTypes.push("sub_frame");

      if (!rule.condition.resourceTypes)
        rule.condition.excludedResourceTypes = ["main_frame", "sub_frame"];
      else
        rule.condition.resourceTypes = rule.condition.resourceTypes
                                           .filter(t => t != "sub_frame");
    }

    if (rule.condition.resourceTypes.length == 0 &&
        !rule.condition.excludedResourceTypes)
      return [allowAllRule];

    return [allowAllRule, rule];
  }

  return [rule];
}

function ChromeRules()
{
  this.specificOnlyDomains = [];
  this.processedFilters = [];
}

ChromeRules.prototype =
{
  /**
   * Processes the given Adblock Plus filter, storing any relevant information
   * ready for when we generate our chrome.declarativeNetRequest rules.
   * @param {Filter} filter
   *   Filter to process
   * @returns {boolean}
   *   false if the filter can't be converted, true if it might be converted.
   */
  processFilter(filter)
  {
    // We expect filters to use Punycode for domains these days, so let's just
    // skip filters which don't. See #6647.
    if (/[^\x00-\x7F]/.test(filter.text))
      return false;

    // The declarativeNetRequest API doesn't support $sitekey whitelisting...
    if (filter.sitekeys)
      return false;
    // ... nor element hiding...
    if (filter instanceof ContentFilter)
      return false;
    // ... nor regular expression based matching.
    if (filter.pattern == null)
      return false;

    // We can't generate rules for unknown abp-resources...
    if (filter.rewrite &&
        !Object.prototype.hasOwnProperty.call(rewriteResources, filter.rewrite))
      return false;

    let filterDetails = {
      filter,
      urlFilter: filter.pattern,
      matchCase: filter.matchCase,
      resourceTypes: getResourceTypes(filter.contentType)
    };

    // We can't generate rules for filters which don't include any supported
    // resource types.
    if (!(filter instanceof WhitelistFilter) &&
        filterDetails.resourceTypes &&
        filterDetails.resourceTypes.length == 0)
    {
      return false;
    }

    // We need to split out the hostname part (if any) of the filter, then
    // decide if it can be matched as lowercase or not.
    let hostname;
    let match = /^(\|\||[a-zA-Z]*:\/\/)([^*^?/|]*)(.*)$/.exec(filter.pattern);
    if (match)
    {
      hostname = match[2].toLowerCase();

      filterDetails.urlFilter = match[1] + hostname + match[3];
      filterDetails.matchCase = filterDetails.matchCase ||
                                match[3].length < 2 ||
                                !/[a-zA-Z]/.test(match[3]);
    }

    if (filter instanceof WhitelistFilter)
    {
      if (filter.contentType & typeMap.GENERICBLOCK && hostname)
        this.specificOnlyDomains.push(hostname);

      if (filter.contentType & supportedRequestTypes ||
          filter.contentType & typeMap.DOCUMENT)
        this.processedFilters.push(filterDetails);
    }
    else
      this.processedFilters.push(filterDetails);

    return true;
  },

  /**
   * Generates chrome.declarativeNetRequest rules from the given
   * Adblock Plus filters.
   * @param {number} [firstId=1] First available rule ID for generated rules.
   * @returns {Object[]} The generated rules
   *
   */
  generateRules(firstId = 1)
  {
    let nextId = firstId;
    let rules = [];

    for (let filterDetails of this.processedFilters)
    {
      let newRules = rulesFromFilterDetails(filterDetails,
                                            this.specificOnlyDomains);
      for (let rule of newRules)
        rule.id = nextId++;
      rules = rules.concat(newRules);
    }

    return rules;
  }
};

exports.ChromeRules = ChromeRules;
