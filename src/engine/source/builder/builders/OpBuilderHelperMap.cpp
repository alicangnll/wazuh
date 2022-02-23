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
    if (regexp.empty())
    {
        throw std::invalid_argument("The regular expression can't be empty");
    }
    auto regex_ptr = std::make_shared<RE2>(regexp);

    // Return Lifter
    return [=](types::Observable o)
    {
        // Append rxcpp operation
        return o.map(
            [=](types::Event e)
            {
                const rapidjson::Value * field_str{};
                try
                {
                    field_str = e.get("/" + base_field);
                }
                catch (std::exception & ex)
                {
                    // TODO Check exception type
                    return e;
                }
                if (field_str)
                {
                    std::string match;
                    if (RE2::PartialMatch(field_str->GetString(), *regex_ptr, &match))
                    {
                        // TODO Implement add member of EventDocument
                        auto aux_string = "{ \"" + map_field + "\": \"" + match + "\"}";
                        types::Document doc{aux_string.c_str()};
                        e.set(doc);
                    }
                }
                return e;
            });
    };
}

} // namespace builder::internals::builders
