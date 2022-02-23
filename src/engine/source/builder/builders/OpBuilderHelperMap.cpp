/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "OpBuilderHelperMap.hpp"

#include <optional>
#include <string>

using namespace std;

namespace builder::internals::builders
{

types::Lifter opBuilderHelperIntCalc(const types::DocumentValue & def)
{
    // Get field
    std::string field = def.MemberBegin()->name.GetString();
    std::string rawValue = def.MemberBegin()->value.GetString();

    std::vector<std::string> parameters = utils::string::split(rawValue, '/');

    if (parameters.size() != 3)
    {
        throw std::runtime_error("Invalid parameters");
    }

    std::optional<std::string> refValue;
    std::optional<int> value;

    // Take operator parameter
    if (parameters[1].size() != 1)
    {
        throw std::runtime_error("Invalid operator");
    }

    char op = parameters[1][0];

    switch (op)
    {
        case '+':
        case '-':
        case '*':
            break;
        case '%':
            if (parameters[2] == "0")
            {
                throw std::runtime_error("Division by zero");
            }
            break;
        default:
            throw std::runtime_error("Invalid operator");
    }

    if (parameters[2][0] == '$')
    {
        // Check case `+i_calc/op/$`
        refValue = parameters[2].substr(1, std::string::npos);
    }
    else
    {
        value = std::stoi(parameters[2]);
    }

    // Return Lifter
    return [op, refValue, value, field](types::Observable o)
    {
        // Append rxcpp operation
        return o.map(
            [=](types::Event e)
            {
                if (e.exists("/" + field))
                {
                    auto fieldToCheck = e.getObject().FindMember(field.c_str());
                    if (fieldToCheck->value.IsInt())
                    {
                        if (value.has_value())
                        {
                            switch (op)
                            {
                                case '+':
                                    fieldToCheck->value.SetInt(
                                        fieldToCheck->value.GetInt() + value.value());
                                    return e;
                                case '-':
                                    fieldToCheck->value.SetInt(
                                        fieldToCheck->value.GetInt() - value.value());
                                    return e;
                                case '*':
                                    fieldToCheck->value.SetInt(
                                        fieldToCheck->value.GetInt() * value.value());
                                    return e;
                                case '%': // TODO: Check if this is correct
                                    if (value.value() != 0)
                                    {
                                        fieldToCheck->value.SetInt(
                                            fieldToCheck->value.GetInt() / value.value());
                                    }
                                    return e;
                                default:
                                    throw std::runtime_error("Invalid operator");
                            }
                            return e;
                        }
                        auto refValueToCheck =
                            e.getObject().FindMember(refValue.value().c_str());
                        if (refValueToCheck->value.IsInt())
                        {
                            switch (op)
                            {
                                case '+':
                                    fieldToCheck->value.SetInt(
                                        fieldToCheck->value.GetInt() +
                                        refValueToCheck->value.GetInt());
                                    return e;
                                case '-':
                                    fieldToCheck->value.SetInt(
                                        fieldToCheck->value.GetInt() -
                                        refValueToCheck->value.GetInt());
                                    return e;
                                case '*':
                                    fieldToCheck->value.SetInt(
                                        fieldToCheck->value.GetInt() *
                                        refValueToCheck->value.GetInt());
                                    return e;
                                case '%': // TODO: divide by zero
                                    if (refValueToCheck->value.GetInt() != 0)
                                    {
                                        fieldToCheck->value.SetInt(
                                            fieldToCheck->value.GetInt() /
                                            refValueToCheck->value.GetInt());
                                    }
                                    return e;
                                default:
                                    throw std::runtime_error("Invalid operator");
                            }
                        }
                    }
                }
                return e;
            });
    };
}

} // namespace builder::internals::builders
