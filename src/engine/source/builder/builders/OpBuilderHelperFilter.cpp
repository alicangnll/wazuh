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

types::Lifter opBuilderHelperIntEqual(const types::DocumentValue & def) //{field: +int/10} $ref
{
    // Get field
    std::string field = def.MemberBegin()->name.GetString();
    std::string rawValue = def.MemberBegin()->value.GetString();

    int posDel = rawValue.find("/");

    if (posDel == std::string::npos || posDel == rawValue.size() - 1) {

        throw std::runtime_error("Value not found");
    }

    std::string strValue = rawValue.substr(posDel + 1, std::string::npos);

    std::optional<std::string> refValue;
    std::optional<int> value;

    if(strValue[0] == '$')
    {
        // Check case `+int/$`
        refValue = strValue.substr(1, std::string::npos);
    }
    else
    {
        // exception @TODO
        value = std::stoi(strValue);
    }

    // Return Lifter
    return [refValue, value, field](types::Observable o)
    {
        // Append rxcpp operation
        return o.filter([=](types::Event e) {

            auto fieldToCheck = e.getObject().FindMember(field.c_str());

            if(e.exists("/" + field))
            {
                if(fieldToCheck->value.IsInt())
                {
                    if(value.has_value())
                    {
                        return fieldToCheck->value.GetInt() == value.value();
                    }
                    else
                    {
                        auto refValueToCheck = e.getObject().FindMember(refValue.value().c_str());
                        if(refValueToCheck->value.IsInt())
                        {
                            return fieldToCheck->value.GetInt() == refValueToCheck->value.GetInt();
                        }
                        else
                        {
                            return false;
                        }
                    }
                }
                else
                {
                    return false;
                }
            }
            else
            {
                return false;
            }
             });
    };
}

} // namespace builder::internals::builders
