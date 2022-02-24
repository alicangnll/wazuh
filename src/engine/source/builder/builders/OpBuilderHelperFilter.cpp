/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "OpBuilderHelperFilter.hpp"
#include <optional>
#include <string>
#include <tuple>

using DocumentValue = builder::internals::types::DocumentValue;
namespace
{

using opString = std::optional<std::string>;
std::tuple<std::string, opString, opString> getCompOpParameter(const DocumentValue & def)
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

bool opBuilderHelperIntComparison(const std::string field, char op, types::Event & e,
                                  std::optional<std::string> refValue,
                                  std::optional<int> value)
{

    // TODO Remove try catch or if nullptr after fix get method of document class
    // Get value to compare
    const rapidjson::Value * fieldValue{};
    try
    {
        fieldValue = e.get("/" + field);
    }
    catch (std::exception & e)
    {
        // TODO Check exception type
        return false;
    }

    if (fieldValue == nullptr || !fieldValue->IsInt())
    {
        return false;
    }

    // get str to compare
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
            return false;
        }

        if (refValueToCheck == nullptr || !refValueToCheck->IsInt())
        {
            return false;
        }
        value = refValueToCheck->GetInt();
    }

    // Int operation
    switch (op)
    {
        // case '==':
        case '=':
            return fieldValue->GetInt() == value.value();
        // case '!=':
        case '!':
            return fieldValue->GetInt() != value.value();
        case '>':
            return fieldValue->GetInt() > value.value();
        // case '>=':
        case 'g':
            return fieldValue->GetInt() >= value.value();
        case '<':
            return fieldValue->GetInt() < value.value();
        // case '<=':
        case 'l':
            return fieldValue->GetInt() <= value.value();

        default:
            // if raise here, then the source code is wrong
            throw std::invalid_argument("Invalid operator: '" + std::string{op} + "' ");
    }

    return false;
}

types::Lifter opBuilderHelperIntEqual(const types::DocumentValue & def)
{

    auto [field, refValue, valuestr] = getCompOpParameter(def);

    std::optional<int> value = valuestr.has_value()
                                   ? std::optional<int>{std::stoi(valuestr.value())}
                                   : std::nullopt;

    // Return Lifter
    return [field, refValue, value](types::Observable o)
    {
        // Append rxcpp operation
        return o.filter(
            [=](types::Event e)
            { return opBuilderHelperIntComparison(field, '=', e, refValue, value); });
    };
}

types::Lifter opBuilderHelperIntNotEqual(const types::DocumentValue & def)
{

    auto [field, refValue, valuestr] = getCompOpParameter(def);

    std::optional<int> value = valuestr.has_value()
                                   ? std::optional<int>{std::stoi(valuestr.value())}
                                   : std::nullopt;

    // Return Lifter
    return [field, refValue, value](types::Observable o)
    {
        // Append rxcpp operation
        return o.filter(
            [=](types::Event e)
            {
                // try and catche, return false
                return opBuilderHelperIntComparison(field, '!', e, refValue, value);
            });
    };
}

types::Lifter opBuilderHelperIntLessThan(const types::DocumentValue & def)
{

    auto [field, refValue, valuestr] = getCompOpParameter(def);

    std::optional<int> value = valuestr.has_value()
                                   ? std::optional<int>{std::stoi(valuestr.value())}
                                   : std::nullopt;

    // Return Lifter
    return [field, refValue, value](types::Observable o)
    {
        // Append rxcpp operation
        return o.filter(
            [=](types::Event e)
            {
                // try and catche, return false
                return opBuilderHelperIntComparison(field, '<', e, refValue, value);
            });
    };
}

types::Lifter opBuilderHelperIntLessThanEqual(const types::DocumentValue & def)
{

    auto [field, refValue, valuestr] = getCompOpParameter(def);

    std::optional<int> value = valuestr.has_value()
                                   ? std::optional<int>{std::stoi(valuestr.value())}
                                   : std::nullopt;

    // Return Lifter
    return [field, refValue, value](types::Observable o)
    {
        // Append rxcpp operation
        return o.filter(
            [=](types::Event e)
            {
                // try and catche, return false
                return opBuilderHelperIntComparison(field, 'l', e, refValue, value);
            });
    };
}

types::Lifter opBuilderHelperIntGreaterThan(const types::DocumentValue & def)
{

    auto [field, refValue, valuestr] = getCompOpParameter(def);

    std::optional<int> value = valuestr.has_value()
                                   ? std::optional<int>{std::stoi(valuestr.value())}
                                   : std::nullopt;

    // Return Lifter
    return [field, refValue, value](types::Observable o)
    {
        // Append rxcpp operation
        return o.filter(
            [=](types::Event e)
            {
                // try and catche, return false
                return opBuilderHelperIntComparison(field, '>', e, refValue, value);
            });
    };
}

types::Lifter opBuilderHelperIntGreaterThanEqual(const types::DocumentValue & def)
{

    auto [field, refValue, valuestr] = getCompOpParameter(def);

    std::optional<int> value = valuestr.has_value()
                                   ? std::optional<int>{std::stoi(valuestr.value())}
                                   : std::nullopt;

    // Return Lifter
    return [field, refValue, value](types::Observable o)
    {
        // Append rxcpp operation
        return o.filter(
            [=](types::Event e)
            {
                // try and catche, return false
                return opBuilderHelperIntComparison(field, 'g', e, refValue, value);
            });
    };
}

} // namespace builder::internals::builders
