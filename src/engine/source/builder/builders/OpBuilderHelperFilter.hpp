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

#include "stringUtils.hpp"
#include "builderTypes.hpp"

#include <re2/re2.h>

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

/**
 * @brief Builds helper integer equal operation.
 * Checks that the field is equal to an integer or another numeric field
 *
 * @param def Definition of the operation to be built
 * @return types::Lifter
 */
types::Lifter opBuilderHelperIntEqual(const types::DocumentValue & def);

/**
 * @brief Builds helper regex match operation.
 * Checks that the field value matches a regular expression
 *
 * @param def Definition of the operation to be built
 * @return types::Lifter
 */
types::Lifter opBuilderHelperRegexMatch(const types::DocumentValue & def);

/**
 * @brief Builds helper regex not match operation.
 * Checks that the field value doesn't match a regular expression
 *
 * @param def Definition of the operation to be built
 * @return types::Lifter
 */
types::Lifter opBuilderHelperRegexNotMatch(const types::DocumentValue & def);

} // namespace builder::internals::builders

#endif // _OP_BUILDER_HELPER_FILTER_H
