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

types::Event opBuilderHelperIntTransformation(const std::string field, std::string op,
                                              types::Event & e,
                                              std::optional<std::string> refValue,
                                              std::optional<int> value)
{
    auto fieldToCheck = e.getObject().FindMember(field.c_str());
    if (fieldToCheck->value.IsInt())
    {
        if (refValue.has_value())
        {
            // Get reference to json event
            // TODO Remove try catch or if nullptr after fix get method of document class
            const rapidjson::Value * refValueToCheck{};
            try
            {
                refValueToCheck = e.get("/" + refValue.value());
            }
            catch (std::exception & ex)
            {
                // TODO Check exception type
                return e;
            }

            if (refValueToCheck == nullptr || !refValueToCheck->IsInt())
            {
                return e;
            }
            value = refValueToCheck->GetInt();
        }

        // Operation
        if (op == "sum")
        {
            value = fieldToCheck->value.GetInt() + value.value();
        }
        else if (op == "sub")
        {
            value = fieldToCheck->value.GetInt() - value.value();
        }
        else if (op == "mul")
        {
            value = fieldToCheck->value.GetInt() * value.value();
        }
        else if (op == "div")
        {
            if (value.value() == 0)
            {
                return e;
            }
            value = fieldToCheck->value.GetInt() / value.value();
        }
        else
        {
            return e;
        }

        // Create and add string to event
        try
        {
            e.set("/" + field, rapidjson::Value(value.value()));
        }
        catch (std::exception & ex)
        {
            // TODO Check exception type
            return e;
        }
    }
    return e;
}

    // field: +i_calc/[+|-|*|/]/val|$ref/
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
        std::string op = parameters[1];

        if (op != "sum" && op != "sub" && op != "mul" && op != "div")
        {
            throw std::runtime_error("Invalid operator");
        }

        if (op == "div")
        {
            if (parameters[2] == "0")
            {
                throw std::runtime_error("Division by zero");
            }
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
        return [field, op, refValue, value](types::Observable o)
        {
            // Append rxcpp operation
            return o.map(
                [=](types::Event e)
                {
                    return opBuilderHelperIntTransformation(field, op, e, refValue,
                                                            value);
                });
        };
    }

} // namespace builder::internals::builders
