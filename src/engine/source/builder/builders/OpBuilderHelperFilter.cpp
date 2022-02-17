/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "OpBuilderHelperFilter.hpp"

#include <string>

using namespace std;

namespace builder::internals::builders
{

types::Lifter opBuilderHelperExists(const types::DocumentValue & def)
{
    // Get field
    std::string field = def.MemberBegin()->name.GetString();

    // Return Lifter
    return [=](types::Observable o)
    {
        // Append rxcpp operation
        return o.filter([=](types::Event e) { return e.exists("/" + field); });
    };
}

types::Lifter opBuilderHelperNotExists(const types::DocumentValue & def)
{
    // Get field
    std::string field = def.MemberBegin()->name.GetString();

    // Return Lifter
    return [=](types::Observable o)
    {
        // Append rxcpp operation
        return o.filter([=](types::Event e) { return !e.exists("/" + field); });
    };
}

types::Lifter opBuilderHelperRegexMatch(const types::DocumentValue & def)
{
    // Get field
    std::string field = def.MemberBegin()->name.GetString();
    std::string value = def.MemberBegin()->value.GetString();
    std::vector<std::string> parameters = utils::string::split(value, '/');
    if (parameters.size() != 2){
        throw std::invalid_argument("Wrong number of arguments passed");
    }
    std::string regexp = parameters[1];

    // Return Lifter
    return [=](types::Observable o)
    {
        // Append rxcpp operations
        return o.filter([=](types::Event e) { return (RE2::FullMatch(e.get("/" + field)->GetString(), regexp)); });
    };
}

} // namespace builder::internals::builders
