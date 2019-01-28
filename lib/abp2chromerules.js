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

/** @module abp2blocklist */

"use strict";

let filterClasses = require("filterClasses");
let punycode = require("punycode");

const typeMap = filterClasses.RegExpFilter.typeMap;

const whitelistableRequestTypes = typeMap.IMAGE |
                         typeMap.STYLESHEET |
                         typeMap.SCRIPT |
                         typeMap.FONT |
                         typeMap.MEDIA |
                         typeMap.POPUP |
                         typeMap.OBJECT |
                         typeMap.OBJECT_SUBREQUEST |
                         typeMap.XMLHTTPREQUEST |
                         typeMap.PING |
                         typeMap.SUBDOCUMENT |
                         typeMap.OTHER |
                         typeMap.WEBSOCKET |
                         typeMap.WEBRTC;


function parseDomains(domains, included, excluded)
{
  for (let domain in domains)
  {
    if (domain != "")
    {
      let enabled = domains[domain];
      domain = punycode.toASCII(domain.toLowerCase());

      if (!enabled)
        excluded.push(domain);
      else if (!domains[""])
        included.push(domain);
    }
  }
}

function findSubdomainsInList(domain, list)
{
  let subdomains = [];
  let suffixLength = domain.length + 1;

  for (let name of list)
  {
    if (name.length > suffixLength && name.slice(-suffixLength) == "." + domain)
      subdomains.push(name.slice(0, -suffixLength));
  }

  return subdomains;
}

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
function parseFilterRegexpSource(text, urlScheme)
{
  let urlFilter = [];

  // Convert the text into an array of Unicode characters.
  //
  // In the case of surrogate pairs (the smiley emoji, for example), one
  // Unicode code point is represented by two JavaScript characters together.
  // We want to iterate over Unicode code points rather than JavaScript
  // characters.
  let characters = Array.from(text);

  let lastIndex = characters.length - 1;
  let hostname;
  let hostnameStart = null;
  let hostnameFinished = false;
  let justHostname = false;
  let canSafelyMatchAsLowercase = false;

  for (let i = 0; i < characters.length; i++)
  {
    let c = characters[i];

    if (hostnameFinished)
      justHostname = false;

    // If we're currently inside the hostname we have to be careful not to
    // escape any characters until after we have converted it to punycode.
    if (hostnameStart != null && !hostnameFinished)
    {
      let endingChar = (c == "*" || c == "^" ||
                        c == "?" || c == "/" || c == "|");
      if (!endingChar && i != lastIndex)
        continue;

      hostname = punycode.toASCII(
        characters.slice(hostnameStart, endingChar ? i : i + 1).join("")
                  .toLowerCase()
      );
      hostnameFinished = justHostname = true;
      urlFilter.push(hostname);
      if (!endingChar)
        break;
    }

    switch (c)
    {
      case "|":
        if (i == 1 && characters[0] == "|")
        {
          hostnameStart = i + 1;
          canSafelyMatchAsLowercase = true;
          break;
        }
        break;
      case "/":
        if (!hostnameFinished &&
            characters[i - 2] == ":" && characters[i - 1] == "/")
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

    if (c == "%" || c == "|" || c == "^")
      urlFilter.push(c);
    else
      urlFilter.push(encodeURI(c));
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
  if (contentType & typeMap.OTHER)
    types.push("other");

  // FIXME - What about typeMap.WEBRTC and typeMap.OBJECT_SUBREQUEST? other?
  // FIXME - What about typeMap.POPUP? main_frame?
  return types;
}

function convertFilterAddRules(rules, filter, action, exceptionDomains)
{
  let parsed = parseFilterRegexpSource(filter.regexpSource);

  // For the special case of $document whitelisting filters with just a domain
  // we can generate an equivalent blocking rule exception using domains.
  if (filter instanceof filterClasses.WhitelistFilter &&
      filter.contentType & typeMap.DOCUMENT &&
      parsed.justHostname)
  {
    rules.push({
      condition: {
        "urlFilter": "*",
        "domains": ["*" + parsed.hostname]
      },
      action: {type: "allow"}
    });
    // If the filter contains other supported options we'll need to generate
    // further rules for it, but if not we can simply return now.
    if (!(filter.contentType & whitelistableRequestTypes))
      return;
  }

  let trigger = {"urlFilter": parsed.urlFilter};

  // For rules containing only a hostname we know that we're matching against
  // a lowercase string unless the matchCase option was passed.
  if (parsed.canSafelyMatchAsLowercase && !filter.matchCase)
    trigger["urlFilter"] = trigger["urlFilter"].toLowerCase();

  if (!parsed.canSafelyMatchAsLowercase && !filter.matchCase)
    trigger["isUrlFilterCaseSensitive"] = false;

  let included = [];
  let excluded = [];

  parseDomains(filter.domains, included, excluded);

  if (exceptionDomains)
    excluded = excluded.concat(exceptionDomains);

  let resourceTypes = getResourceTypes(filter.contentType);
  if (resourceTypes.length)
    trigger["resourceTypes"] = resourceTypes;

  if (filter.thirdParty != null)
    trigger["domainType"] = filter.thirdParty ? "thirdParty" : "firstParty";

  let addTopLevelException = false;

  if (included.length > 0)
  {
    trigger["domains"] = [];

    for (let name of included)
    {
      // If this is a blocking filter, add the subdomain wildcard only
      // if no subdomains have been excluded.
      let notSubdomains = null;
      if ((filter instanceof filterClasses.BlockingFilter) &&
          (notSubdomains = findSubdomainsInList(name, excluded)).length > 0)
      {
        trigger["domains"].push(name);

        // Add the "www" prefix but only if it hasn't been excluded.
        if (!notSubdomains.includes("www"))
          trigger["domains"].push("www." + name);
      }
      else
      {
        trigger["domains"].push("*" + name);
      }
    }
  }
  else if (excluded.length > 0)
  {
    trigger["excludedDomains"] = excluded.map(name => "*" + name);
  }

  rules.push({condition: trigger, action: {type: action}});
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
  if (filter.sitekeys)
    return;
  if (filter instanceof filterClasses.RegExpFilter &&
      filter.regexpSource == null)
    return;

  if (filter instanceof filterClasses.BlockingFilter)
    this.requestFilters.push(filter);

  if (filter instanceof filterClasses.WhitelistFilter)
  {
    if (filter.contentType & (typeMap.DOCUMENT | whitelistableRequestTypes))
      this.requestExceptions.push(filter);

    if (filter.contentType & typeMap.GENERICBLOCK)
      this.genericblockExceptions.push(filter);
  }
};

/**
 * Generate content blocker list for all filters that were added
 */
ContentBlockerList.prototype.generateRules = function()
{
  let blockingRules = [];
  let blockingExceptionRules = [];

  let requestFilterExceptionDomains = [];
  for (let filter of this.genericblockExceptions)
  {
    let parsed = parseFilterRegexpSource(filter.regexpSource);
    if (parsed.hostname)
      requestFilterExceptionDomains.push(parsed.hostname);
  }

  for (let filter of this.requestFilters)
  {
    convertFilterAddRules(blockingRules, filter, "block",
                          requestFilterExceptionDomains);
  }

  for (let filter of this.requestExceptions)
    convertFilterAddRules(blockingExceptionRules, filter, "allow");

  let rules = blockingRules.concat(blockingExceptionRules);
  let nextID = 1;
  for (let rule of rules)
    rule.id = nextID++;
  return rules;
};
