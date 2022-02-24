/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <tuple>
#include <string>
#include <optional>
#include "OpBuilderHelperFilter.hpp"

using DocumentValue = builder::internals::types::DocumentValue;
namespace {

using opString = std::optional<std::string>;
std::tuple<std::string, opString, opString>  getCompOpParameter(const DocumentValue & def)
{
    // Get destination path
    std::string field = def.MemberBegin()->name.GetString();
    // Get function helper
    std::string rawValue = def.MemberBegin()->value.GetString();

    // Parse parameters
    std::vector<std::string> parameters = utils::string::split(rawValue, '/');
    if (parameters.size() != 2)
    {
        throw std::runtime_error("Invalid parameters");
    }

    std::optional<std::string> refValue;
    std::optional<std::string> value;

    if (parameters[1][0] == '$')
    {
        refValue = parameters[1].substr(1);
    }
    else
    {
        value = parameters[1];
    }

    return {field, refValue, value};
}
} // namespace

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

types::Lifter opBuilderHelperIntEqual(const types::DocumentValue & def)
{
    // Get field
    std::string field = def.MemberBegin()->name.GetString();
    std::string rawValue = def.MemberBegin()->value.GetString();

    std::vector<std::string> parameters = utils::string::split(rawValue, '/');

    if(parameters.size() != 2)
    {
        throw std::runtime_error("Invalid parameters");
    }

    std::optional<std::string> refValue;
    std::optional<int> value;

    if(parameters[1][0] == '$')
    {
        // Check case `+int/$`
        refValue = parameters[1].substr(1, std::string::npos);
    }
    else
    {
        value = std::stoi(parameters[1]);
    }

    // Return Lifter
    return [refValue, value, field](types::Observable o)
    {
        // Append rxcpp operation
        return o.filter([=](types::Event e) {
            if(e.exists("/" + field))
            {
                auto fieldToCheck = e.getObject().FindMember(field.c_str());
                if(fieldToCheck->value.IsInt())
                {
                    if(value.has_value())
                    {
                        return fieldToCheck->value.GetInt() == value.value();
                    }
                    auto refValueToCheck = e.getObject().FindMember(refValue.value().c_str());
                    if(refValueToCheck->value.IsInt())
                    {
                        return fieldToCheck->value.GetInt() == refValueToCheck->value.GetInt();
                    }
                }
            }
            return false;
        });
    };
}

} // namespace builder::internals::builders
