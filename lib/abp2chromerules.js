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

let {RegExpFilter, WhitelistFilter, BlockingFilter} = require("filterClasses");

const typeMap = RegExpFilter.typeMap;

const whitelistableRequestTypes = typeMap.IMAGE |
                         typeMap.STYLESHEET |
                         typeMap.SCRIPT |
                         typeMap.FONT |
                         typeMap.MEDIA |
                         typeMap.OBJECT |
                         typeMap.XMLHTTPREQUEST |
                         typeMap.PING |
                         typeMap.SUBDOCUMENT |
                         typeMap.OTHER |
                         typeMap.WEBSOCKET;

// Chrome can't distinguish between OBJECT_SUBREQUEST and OBJECT requests.
RegExpFilter.typeMap.OBJECT_SUBREQUEST = RegExpFilter.typeMap.OBJECT;

/**
 * Parse the given filter "regexpSource" string. Producing a urlFilter suitable
 * for the declarativeNetRequest API, extracting the hostname (if any), and
 * deciding if case sensitive matching is required.
 *
 * @param   {string} text regexpSource property of a filter
 * @param   {string} urlScheme The URL scheme to use in the regular expression
 * @returns {object} An object containing a urlFilter string, a bool
 *                   indicating if the filter can be safely matched as lower
 *                   case, a hostname string (or undefined) and a bool
 *                   indicating if the source only contains a hostname or not:
 *                     {urlFilter: "...",
 *                      canSafelyMatchAsLowercase: true/false,
 *                      hostname: "...",
 *                      justHostname: true/false}
 */
// FIXME - Is this extra logic worth it for the optimisation of matching filters
//         with only a domain type case sensitive?!
function parseFilterRegexpSource(text, urlScheme)
{
  let urlFilter = [];

  let lastIndex = text.length - 1;
  let hostname;
  let hostnameStart = null;
  let hostnameFinished = false;
  let justHostname = false;
  let canSafelyMatchAsLowercase = false;

  for (let i = 0; i < text.length; i++)
  {
    let c = text[i];

    if (hostnameFinished)
      justHostname = false;

    // If we're currently inside the hostname, we keep track of it here,
    // and then add it to the urlFilter when its done.
    if (hostnameStart != null && !hostnameFinished)
    {
      let endingChar = (c == "*" || c == "^" ||
                        c == "?" || c == "/" || c == "|");
      if (!endingChar && i != lastIndex)
        continue;

      hostname = text.slice(hostnameStart, endingChar ? i : i + 1)
                     .toLowerCase();
      hostnameFinished = justHostname = true;
      urlFilter.push(hostname);
      if (!endingChar)
        break;
    }

    switch (c)
    {
      case "|":
        if (i == 1 && text[0] == "|")
        {
          hostnameStart = i + 1;
          canSafelyMatchAsLowercase = true;
          break;
        }
        break;
      case "/":
        if (!hostnameFinished &&
            text[i - 2] == ":" && text[i - 1] == "/")
        {
          hostnameStart = i + 1;
          canSafelyMatchAsLowercase = true;
        }
        break;
      default:
        if (hostnameFinished && (c >= "a" && c <= "z" ||
                                 c >= "A" && c <= "Z"))
          canSafelyMatchAsLowercase = false;
    }

    urlFilter.push(c);
  }

  return {
    urlFilter: urlFilter.join(""),
    canSafelyMatchAsLowercase,
    hostname,
    justHostname
  };
}

function getResourceTypes(contentType)
{
  // The default is to match everything except "main_frame", which is about
  // right. If the filter has the default content type bitmask, let's go with
  // that to reduce noise in the genreated rules file.
  if (contentType == RegExpFilter.prototype.contentType)
    return;

  let types = [];

  if (contentType & typeMap.IMAGE)
    types.push("image");
  if (contentType & typeMap.STYLESHEET)
    types.push("stylesheet");
  if (contentType & typeMap.SCRIPT)
    types.push("script");
  if (contentType & typeMap.FONT)
    types.push("font");
  if (contentType & typeMap.MEDIA)
    types.push("media");
  if (contentType & typeMap.OBJECT)
    types.push("object");
  if (contentType & typeMap.XMLHTTPREQUEST)
    types.push("xmlhttprequest");
  if (contentType & typeMap.WEBSOCKET)
    types.push("websocket");
  if (contentType & typeMap.PING)
    types.push("ping");
  if (contentType & typeMap.SUBDOCUMENT)
    types.push("sub_frame");
  if (contentType & (typeMap.OTHER))
  {
    types.push("other");
    types.push("csp_report");
  }

  return types;
}

function convertFilterAddRules(rules, filter, action,
                               genericBlockExceptionDomains)
{
  let parsed = parseFilterRegexpSource(filter.regexpSource);

  // For the special case of $document whitelisting filters with just a domain
  // we can generate an equivalent blocking rule exception using domains.
  // FIXME - We could instead generate one large rule for these, like Sebastian.
  if (filter instanceof WhitelistFilter &&
      filter.contentType & typeMap.DOCUMENT &&
      parsed.justHostname)
  {
    rules.push({
      id: rules.length + 1,
      condition: {
        domains: [parsed.hostname]
      },
      action: {type: "allow"}
    });
    // If the filter contains other supported options we'll need to generate
    // further rules for it, but if not we can simply return now.
    if (!(filter.contentType & whitelistableRequestTypes))
      return;
  }

  let trigger = {urlFilter: parsed.urlFilter};

  let resourceTypes = getResourceTypes(filter.contentType);

  if (resourceTypes)
  {
    // Looks like we can't generate a rule since none of the supported content
    // types were found.
    if (resourceTypes.length == 0)
      return;

    trigger["resourceTypes"] = resourceTypes;
  }

  // For rules containing only a hostname we know that we're matching against
  // a lowercase string unless the matchCase option was passed.
  if (parsed.canSafelyMatchAsLowercase && !filter.matchCase)
    trigger["urlFilter"] = trigger["urlFilter"].toLowerCase();

  if (!parsed.canSafelyMatchAsLowercase && !filter.matchCase)
    trigger["isUrlFilterCaseSensitive"] = false;

  let domains = [];
  let excludedDomains = [];
  for (let domain in filter.domains)
  {
    if (domain != "")
    {
      let enabled = filter.domains[domain];
      (enabled ? domains : excludedDomains).push(domain.toLowerCase());
    }
  }

  let genericBlockingRule = !filter.domains || filter.domains[""];

  if (genericBlockingRule && genericBlockExceptionDomains)
    excludedDomains = excludedDomains.concat(genericBlockExceptionDomains);

  if (domains.length)
    trigger["domains"] = domains;
  if (excludedDomains.length)
    trigger["excludedDomains"] = excludedDomains;

  if (filter.thirdParty != null)
    trigger["domainType"] = filter.thirdParty ? "thirdParty" : "firstParty";

  rules.push({
    id: rules.length + 1,
    condition: trigger,
    action: {type: action}
  });
}

let ContentBlockerList =
/**
 * Create a new Adblock Plus filter to content blocker list converter
 *
 * @constructor
 */
exports.ContentBlockerList = function()
{
  this.requestFilters = [];
  this.requestExceptions = [];
  this.genericblockExceptions = [];
};

/**
 * Add Adblock Plus filter to be converted
 *
 * @param {Filter} filter Filter to convert
 */
ContentBlockerList.prototype.addFilter = function(filter)
{
  // We expect filters to use Punycode for domains these days, so let's just
  // skip filters which don't. See #6647.
  if (/[^\x00-\x7F]/.test(filter.text))
    return;

  if (filter.sitekeys)
    return;
  if (filter instanceof RegExpFilter &&
      filter.regexpSource == null)
    return;

  if (filter instanceof BlockingFilter)
    this.requestFilters.push(filter);

  if (filter instanceof WhitelistFilter)
  {
    if (filter.contentType & (typeMap.DOCUMENT | whitelistableRequestTypes))
      this.requestExceptions.push(filter);

    if (filter.contentType & typeMap.GENERICBLOCK)
      this.genericblockExceptions.push(filter);
  }
};

/**
 * Generate content blocker list for all filters that were added
 * @returns {Object[]} The generated rules
 *
 */
ContentBlockerList.prototype.generateRules = function()
{
  let rules = [];

  let genericBlockExceptionDomains = [];
  for (let filter of this.genericblockExceptions)
  {
    let parsed = parseFilterRegexpSource(filter.regexpSource);
    if (parsed.hostname)
      genericBlockExceptionDomains.push(parsed.hostname);
  }

  for (let filter of this.requestFilters)
    convertFilterAddRules(rules, filter, "block", genericBlockExceptionDomains);

  for (let filter of this.requestExceptions)
    convertFilterAddRules(rules, filter, "allow");

  return rules;
};
