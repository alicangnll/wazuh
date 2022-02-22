/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "OpBuilderHelperMap.hpp"

#include <string>

namespace builder::internals::builders
{

types::Lifter opBuilderHelperRegexExtract(const types::DocumentValue & def)
{
    // Get fields
    std::string base_field = def.MemberBegin()->name.GetString();
    std::string value = def.MemberBegin()->value.GetString();
    std::vector<std::string> parameters = utils::string::split(value, '/');
    if (parameters.size() != 3)
    {
        throw std::invalid_argument("Wrong number of arguments passed");
    }
    std::string map_field = parameters[1];
    std::string regexp = parameters[2];
    auto regex_ptr = std::make_shared<RE2>(regexp);

    // Return Lifter
    return [=](types::Observable o)
    {
        // Append rxcpp operation
        return o.map(
            [=](types::Event e)
            {
                std::string match;
                if (RE2::PartialMatch(e.get("/" + base_field)->GetString(), *regex_ptr,
                                      &match))
                {
                    auto aux_string = "{ \"" + map_field + "\": \"" + match + "\"}";
                    types::Document doc{aux_string.c_str()};
                    e.set(doc);
                }
                return e;
            });
    };
}

} // namespace builder::internals::builders
