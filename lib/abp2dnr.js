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

const STANDARD_PRIORITY = 1000;

// By default allow rules take proiority over allowAllRequests rules, we want
// the opposite.
const ALLOW_ALL_REQUESTS_PRIORITY = 1500;

// Since CSP filters correspond to main_frame/sub_frame rules, we need a way to
// differentiate those rules from other main_frame/sub_frame rules. Otherwise
// $csp exception filters would effectively allowlist the entire site.
const CSP_PRIORITY = 500;

const {
  CommentFilter,
  ContentFilter,
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
    return;

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
  if (isGenericFilter && !(filter instanceof AllowlistFilter))
    condition.excludeSpecificOnlyDomains = true;

  return condition;
}

function generateRedirectRules(filter, urlFilter, matchCase)
{
  let url = rewriteResources[filter.rewrite];

  // We can't generate rules for unknown abp-resources...
  if (!url)
    return false;

  let resourceTypes = getResourceTypes(filter.contentType);

  // We can't generate rules for filters which don't include any supported
  // resource types.
  if (resourceTypes && resourceTypes.length == 0)
    return false;

  return [{
    priority: STANDARD_PRIORITY,
    condition: getCondition(filter, urlFilter, resourceTypes, matchCase),
    action: {
      type: "redirect",
      redirect: {url}
    }
  }];
}

function generateCSPRules(filter, urlFilter, matchCase)
{
  let resourceTypes = ["main_frame", "sub_frame"];

  let action;

  if (filter instanceof AllowlistFilter)
  {
    action = {
      type: "allow"
    };
  }
  else
  {
    action = {
      type: "modifyHeaders",
      responseHeaders: [{
        header: "Content-Security-Policy",
        operation: "append",
        value: filter.csp
      }]
    };
  }

  return [{
    priority: CSP_PRIORITY,
    condition: getCondition(filter, urlFilter, resourceTypes, matchCase),
    action
  }];
}

function generateBlockRules(filter, urlFilter, matchCase)
{
  let resourceTypes = getResourceTypes(filter.contentType);

  // We can't generate rules for filters which don't include any supported
  // resource types.
  if (resourceTypes && resourceTypes.length == 0)
    return false;

  return [{
    priority: STANDARD_PRIORITY,
    condition: getCondition(filter, urlFilter, resourceTypes, matchCase),
    action: {
      type: "block"
    }
  }];
}

function generateAllowRules(filter, urlFilter, matchCase)
{
  let rules = [];
  let {contentType} = filter;

  if (contentType & contentTypes.DOCUMENT)
  {
    contentType &= ~contentTypes.SUBDOCUMENT;

    rules.push({
      priority: ALLOW_ALL_REQUESTS_PRIORITY,
      condition: getCondition(filter, urlFilter,
                              ["main_frame", "sub_frame"], matchCase),
      action: {
        type: "allowAllRequests"
      }
    });
  }

  let resourceTypes = getResourceTypes(contentType);
  if (!resourceTypes || resourceTypes.length)
  {
    rules.push({
      priority: STANDARD_PRIORITY,
      condition: getCondition(filter, urlFilter, resourceTypes, matchCase),
      action: {
        type: "allow"
      }
    });
  }

  if (rules.length > 0)
    return rules;
  return false;
}

/**
 * Constructor for Ruleset.
 * @constructor
 * @param {number} [firstId=1]
 *   The first available rule ID for generated rules.
 * @param {function} [isRegexSupported]
 *   For regular expression filter support, provide this function which returns
 *   true if the given regular expression is supported by the
 *   declarativeNetRequest API and false otherwise. If omitted, regular
 *   expression filters will be ignored.
 *   See https://developer.chrome.com/extensions/declarativeNetRequest#method-isRegexSupported
 *   for the expected function signature.
 */
function Ruleset(firstId = 1, isRegexSupported = null)
{
  this.nextId = firstId;
  this.isRegexSupported = isRegexSupported;
  this.specificOnlyDomains = [];
  this.rules = [];
}

Ruleset.prototype =
{
  /**
   * Processes the given Adblock Plus filter, performing most of the work in
   * converting it into chrome.declarativeNetRequet rule(s).
   * @param {Filter} filter
   *   Filter to process
   * @returns {boolean|number[]}
   *   - If possible, we'll return an array of the generated rule IDs.
   *   - If the filter is somehow used, but we don't have any corresponding
   *     rules, we'll return true.
   *   - If the filter isn't used at all we return false.
   */
  async processFilter(filter)
  {
    // We can't do anything with comments or invalid filters.
    if (filter instanceof CommentFilter || filter instanceof InvalidFilter)
      return false;
    // We expect filters to use Punycode for domains these days, so let's just
    // skip filters which don't. See #6647.
    if (/[^\x00-\x7F]/.test(filter.text))
      return false;
    // The declarativeNetRequest API doesn't support $sitekey allowlisting...
    if (filter.sitekeys)
      return false;
    // ... nor element hiding...
    if (filter instanceof ContentFilter)
      return false;

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
             !(this.isRegexSupported &&
               (await this.isRegexSupported({
                 regex: filter.regexp.source,
                 isCaseSensitive: matchCase
               })).isSupported))
    {
      return false;
    }

    let result;

    if (filter.contentType & contentTypes.CSP)
      result = generateCSPRules(filter, urlFilter, matchCase);
    else if (filter instanceof AllowlistFilter)
    {
      let genericDomainException = false;
      if (filter.contentType & contentTypes.GENERICBLOCK && hostname)
      {
        this.specificOnlyDomains.push(hostname);
        genericDomainException = true;
      }

      result = generateAllowRules(filter, urlFilter, matchCase) ||
               genericDomainException;
    }
    else if (filter.rewrite)
      result = generateRedirectRules(filter, urlFilter, matchCase);
    else
      result = generateBlockRules(filter, urlFilter, matchCase);

    if (Array.isArray(result))
    {
      let generatedRuleIds = [];

      for (let rule of result)
      {
        generatedRuleIds.push(rule.id = this.nextId++);
        this.rules.push(rule);
      }

      return generatedRuleIds;
    }

    return result;
  },

  /**
   * Generates chrome.declarativeNetRequest rules from the given
   * Adblock Plus filters.
   * @returns {Object[]} The generated rules
   */
  generateRules()
  {
    for (let rule of this.rules)
    {
      if (rule.condition.excludeSpecificOnlyDomains)
      {
        delete rule.condition.excludeSpecificOnlyDomains;

        if (this.specificOnlyDomains.length > 0)
        {
          if (rule.condition.excludedDomains)
          {
            rule.condition.excludedDomains =
              rule.condition.excludedDomains.concat(this.specificOnlyDomains);
          }
          else
            rule.condition.excludedDomains = this.specificOnlyDomains;
        }
      }
    }

    return this.rules;
  }
};

exports.Ruleset = Ruleset;

exports.STANDARD_PRIORITY = STANDARD_PRIORITY;
exports.CSP_PRIORITY = CSP_PRIORITY;
exports.ALLOW_ALL_REQUESTS_PRIORITY = ALLOW_ALL_REQUESTS_PRIORITY;
