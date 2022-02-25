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
    if (parameters.size() != 2)
    {
        throw std::invalid_argument("Wrong number of arguments passed");
    }
    std::string regexp = parameters[1];
    if (regexp.empty())
    {
        throw std::invalid_argument("The regular expression can't be empty");
    }
    auto regex_ptr = std::make_shared<RE2>(regexp);

    // Return Lifter
    return [=](types::Observable o)
    {
        // Append rxcpp operations
        return o.filter(
            [=](types::Event e)
            {
                // TODO Remove try catch
                const rapidjson::Value * field_str{};
                try
                {
                    field_str = e.get("/" + field);
                }
                catch (std::exception & ex)
                {
                    // TODO Check exception type
                    return false;
                }
                if (field_str)
                {
                    return (RE2::PartialMatch(field_str->GetString(), *regex_ptr));
                }
                return false;
            });
    };
}

types::Lifter opBuilderHelperRegexNotMatch(const types::DocumentValue & def)
{
    // Get field
    std::string field = def.MemberBegin()->name.GetString();
    std::string value = def.MemberBegin()->value.GetString();
    std::vector<std::string> parameters = utils::string::split(value, '/');
    if (parameters.size() != 2)
    {
        throw std::invalid_argument("Wrong number of arguments passed");
    }
    std::string regexp = parameters[1];
    if (regexp.empty())
    {
        throw std::invalid_argument("The regular expression can't be empty");
    }
    auto regex_ptr = std::make_shared<RE2>(regexp);

    // Return Lifter
    return [=](types::Observable o)
    {
        // Append rxcpp operations
        return o.filter(
            [=](types::Event e)
            {
                // TODO Remove try catch
                const rapidjson::Value * field_str{};
                try
                {
                    field_str = e.get("/" + field);
                }
                catch (std::exception & ex)
                {
                    // TODO Check exception type
                    return false;
                }
                if (field_str)
                {
                    return (!RE2::PartialMatch(field_str->GetString(), *regex_ptr));
                }
                return false;
            });
    };
}

} // namespace builder::internals::builders
