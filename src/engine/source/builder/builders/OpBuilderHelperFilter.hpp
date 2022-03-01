/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _OP_BUILDER_HELPER_FILTER_H
#define _OP_BUILDER_HELPER_FILTER_H

#include "builderTypes.hpp"
#include "stringUtils.hpp"

namespace builder::internals::builders
{

/**
 * @brief Builds helper exists operation.
 * Checks that a field is present in the event.
 *
 * @param def Definition of the operation to be built
 * @return types::Lifter
 */
types::Lifter opBuilderHelperExists(const types::DocumentValue & def);

/**
 * @brief Builds helper not_exists operation.
 * Checks that a field is not present in the event.
 *
 * @param def Definition of the operation to be built
 * @return types::Lifter
 */
types::Lifter opBuilderHelperNotExists(const types::DocumentValue & def);

//*************************************************
//*           Integer filters                      *
//*************************************************

/**
 * @brief Compares a integer of the event against another integer that may or may not
 * belong to the event `e`
 *
 * @param field The key/path of the field to be compared
 * @param op The operator to be used for the comparison. Operators are:
 * - `=`: checks if the field is equal to the value
 * - `!`: checks if the field is not equal to the value
 * - `<`: checks if the field is less than the value
 * - `>`: checks if the field is greater than the value
 * - `m`: checks if the field is less than or equal to the value
 * - `n`: checks if the field is greater than or equal to the value
 * @param e The event containing the field to be compared
 * @param refValue The key/path of the field to be compared against (optional)
 * @param value The integer to be compared against (optional)
 * @return true if the comparison is true
 * @return false if the comparison is false
 * @note If `refValue` is not provided, the comparison will be against the value of
 * `value`
 */
inline bool opBuilderHelperIntComparison(const std::string field, char op,
                                         types::Event & e,
                                         std::optional<std::string> refValue,
                                         std::optional<int> value);

/**
 * @brief Builds helper integer equal operation.
 * Checks that the field is equal to an integer or another numeric field
 *
 * The filter checks if a field in the JSON event `wazuh` is equal to a value.
 * Only pass events if the fields are equal and the values are a integer.
 * @param def Definition of the operation to be built
 * @return types::Lifter The lifter with the `i_eq` filter.
 * @throw std::runtime_error if the parameter is not a integer.
 */
types::Lifter opBuilderHelperIntEqual(const types::DocumentValue & def);

/**
 * @brief Builds helper integer not equal operation.
 * Checks that the field is not equal to an integer or another numeric field
 *
 * The filter checks if a field in the JSON event `wazuh` is not equal to a value.
 * Only pass events if the fields are not equal and the values are a integer.
 * @param def Definition of the operation to be built
 * @return types::Lifter The lifter with the `i_ne` filter.
 * @throw std::runtime_error if the parameter is not a integer.
 */
types::Lifter opBuilderHelperIntNotEqual(const types::DocumentValue & def);

/**
 * @brief Builds helper integer less than operation.
 * Checks that the field is less than to an integer or another numeric field
 *
 * The filter checks if a field in the JSON event `wazuh` is less than a value.
 * Only pass events if the fields are less than and the values are a integer.
 * @param def Definition of the operation to be built
 * @return types::Lifter The lifter with the `i_lt` filter.
 * @throw std::runtime_error if the parameter is not a integer.
 */
types::Lifter opBuilderHelperIntLessThan(const types::DocumentValue & def);

/**
 * @brief Builds helper integer less than equal operation.
 * Checks that the field is less than equal to an integer or another numeric field
 *
 * The filter checks if a field in the JSON event `wazuh` is less than equal a value.
 * Only pass events if the fields are less than equal and the values are a integer.
 * @param def Definition of the operation to be built
 * @return types::Lifter The lifter with the `i_le` filter.
 * @throw std::runtime_error if the parameter is not a integer.
 */
types::Lifter opBuilderHelperIntLessThanEqual(const types::DocumentValue & def);

/**
 * @brief Builds helper integer greater than operation.
 * Checks that the field is greater than to an integer or another numeric field
 *
 * The filter checks if a field in the JSON event `wazuh` is greater than a value.
 * Only pass events if the fields are greater than and the values are a integer.
 * @param def Definition of the operation to be built
 * @return types::Lifter The lifter with the `i_gt` filter.
 * @throw std::runtime_error if the parameter is not a integer.
 */

types::Lifter opBuilderHelperIntGreaterThan(const types::DocumentValue & def);

/**
 * @brief Builds helper integer greater than equal operation.
 * Checks that the field is greater than equal to an integer or another numeric field
 *
 * The filter checks if a field in the JSON event `wazuh` is greater than equal a value.
 * Only pass events if the fields are greater than equal and the values are a integer.
 * @param def Definition of the operation to be built
 * @return types::Lifter The lifter with the `i_ge` filter.
 * @throw std::runtime_error if the parameter is not a integer.
 */
types::Lifter opBuilderHelperIntGreaterThanEqual(const types::DocumentValue & def);

} // namespace builder::internals::builders

#endif // _OP_BUILDER_HELPER_FILTER_H
