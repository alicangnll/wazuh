/*
 * Copyright (C) 2015-2021, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdio.h>
#include <string.h>

#include "../wazuh_db/wdb.h"
#include "../headers/shared.h"
#include "../os_crypto/sha1/sha1_op.h"
#include "../external/sqlite/sqlite3.h"

#include "../wrappers/externals/openssl/digest_wrappers.h"
#include "../wrappers/externals/sqlite/sqlite3_wrappers.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../wrappers/wazuh/wazuh_db/wdb_wrappers.h"
#include "cJSON.h"
#include "os_err.h"

void wdbi_update_completion(wdb_t * wdb, wdb_component_t component, long timestamp, os_sha1 last_agent_checksum);
int wdb_calculate_stmt_checksum(wdb_t * wdb, sqlite3_stmt * stmt, wdb_component_t component, os_sha1 hexdigest);

/* setup/teardown */
static int setup_wdb_t(void **state) {
    wdb_t *data = calloc(1, sizeof(wdb_t));

    if(!data) {
        return -1;
    }

    //Initializing dummy statements pointers
    for (int i = 0; i < WDB_STMT_SIZE; ++i) {
        data->stmt[i] = (sqlite3_stmt *)1;
    }

    test_mode = 1;
    *state = data;
    return 0;
}

static int teardown_wdb_t(void **state) {
    wdb_t *data = *state;

    if(data) {
        os_free(data->id);
        os_free(data);
    }

    test_mode = 0;
    return 0;
}

/* tests */

// Tests wdb_calculate_stmt_checksum

static void test_wdb_calculate_stmt_checksum_wdb_null(void **state)
{
    expect_assert_failure(wdb_calculate_stmt_checksum(NULL, NULL, WDB_FIM, NULL));
}

static void test_wdb_calculate_stmt_checksum_stmt_null(void **state)
{
    wdb_t *data = *state;

    expect_assert_failure(wdb_calculate_stmt_checksum(data, NULL, WDB_FIM, NULL));
}

static void test_wdb_calculate_stmt_checksum_cks_null(void **state)
{
    wdb_t *data = *state;
    sqlite3_stmt *stmt = (sqlite3_stmt *)1;

    expect_assert_failure(wdb_calculate_stmt_checksum(data, stmt, WDB_FIM, NULL));
}

static void test_wdb_calculate_stmt_checksum_no_row(void **state)
{
    int ret;

    wdb_t *data = *state;
    sqlite3_stmt *stmt = (sqlite3_stmt *)1;
    os_sha1 test_hex = "";

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, 0);

    ret = wdb_calculate_stmt_checksum(data, stmt, WDB_FIM, test_hex);

    assert_int_equal(ret, 0);
}

static void test_wdb_calculate_stmt_checksum_success(void **state)
{
    int ret;

    wdb_t *data = *state;
    data->id = strdup("000");
    sqlite3_stmt *stmt = (sqlite3_stmt *)1;
    os_sha1 test_hex = {5,5,0,8,6,'c','e','f',9,'c',8,7,'d',6,'d',0,3,1,'c','d',5,'d','b',2,9,'c','d',0,3,'a',2,'e','d',0,2,5,2,'b',4,5};

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, 100);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, 0);
    expect_value(__wrap_sqlite3_column_text, iCol, 0);
    will_return(__wrap_sqlite3_column_text, NULL);

    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) has a NULL fim checksum.");

    ret = wdb_calculate_stmt_checksum(data, stmt, WDB_FIM, test_hex);

    assert_int_equal(ret, 1);
}

// Tests wdbi_checksum

static void test_wdbi_checksum_wbs_null(void **state)
{
    expect_assert_failure(wdbi_checksum(NULL, 0, ""));
}

static void test_wdbi_checksum_hexdigest_null(void **state)
{
    wdb_t * data = *state;
    data->id = strdup("000");

    expect_assert_failure(wdbi_checksum(data, 0, NULL));
}

static void test_wdbi_checksum_wdb_stmt_cache_fail(void **state)
{
    int ret;

    wdb_t * data = *state;
    data->id = strdup("000");
    os_sha1 test_hex = "";

    will_return(__wrap_wdb_stmt_cache, -1);

    ret = wdbi_checksum(data, 0, test_hex);

    assert_int_equal(ret, -1);
}

static void test_wdbi_checksum_success(void **state)
{
    int ret;

    wdb_t * data = *state;
    data->id = strdup("000");
    os_sha1 test_hex = {5,5,0,8,6,'c','e','f',9,'c',8,7,'d',6,'d',0,3,1,'c','d',5,'d','b',2,9,'c','d',0,3,'a',2,'e','d',0,2,5,2,'b',4,5};

    will_return(__wrap_wdb_stmt_cache, 1);

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, 100);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, 0);
    expect_value(__wrap_sqlite3_column_text, iCol, 0);
    will_return(__wrap_sqlite3_column_text, NULL);

    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) has a NULL fim checksum.");

    ret = wdbi_checksum(data, 0, test_hex);

    assert_int_equal(ret, 1);
}

// Tests wdbi_checksum_range

static void test_wdbi_checksum_range_wbs_null(void **state)
{
    expect_assert_failure(wdbi_checksum_range(NULL, 0, "test_begin", "test_end", ""));
}

static void test_wdbi_checksum_range_hexdigest_null(void **state)
{
    wdb_t * data = *state;
    data->id = strdup("000");

    expect_assert_failure(wdbi_checksum_range(data, 0, "test_begin", "test_end", NULL));
}

static void test_wdbi_checksum_range_wdb_stmt_cache_fail(void **state)
{
    int ret;

    wdb_t * data = *state;
    data->id = strdup("000");
    os_sha1 test_hex = "";

    will_return(__wrap_wdb_stmt_cache, -1);

    ret = wdbi_checksum_range(data, 0, "test_begin", "test_end", test_hex);

    assert_int_equal(ret, -1);
}

static void test_wdbi_checksum_range_begin_null(void **state)
{
    int ret;

    wdb_t * data = *state;
    data->id = strdup("000");

    const char* begin = NULL;
    const char* end = "test_end";
    os_sha1 test_hex = "";

    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, end);
    will_return(__wrap_sqlite3_bind_text, 0);

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, 0);

    ret = wdbi_checksum_range(data, 0, begin, end, test_hex);

    assert_int_equal(ret, 0);
}

static void test_wdbi_checksum_range_end_null(void **state)
{
    int ret;

    wdb_t * data = *state;
    data->id = strdup("000");

    const char* begin = "test_begin";
    const char* end = NULL;
    os_sha1 test_hex = "";

    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, begin);
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    will_return(__wrap_sqlite3_bind_text, 0);

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, 0);

    ret = wdbi_checksum_range(data, 0, begin, end, test_hex);

    assert_int_equal(ret, 0);
}

static void test_wdbi_checksum_range_success(void **state)
{
    int ret;

    wdb_t * data = *state;
    data->id = strdup("000");
    const char* begin = "test_begin";
    const char* end = "test_end";
    os_sha1 test_hex = {5,5,0,8,6,'c','e','f',9,'c',8,7,'d',6,'d',0,3,1,'c','d',5,'d','b',2,9,'c','d',0,3,'a',2,'e','d',0,2,5,2,'b',4,5};

    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, begin);
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, end);
    will_return(__wrap_sqlite3_bind_text, 0);

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, 100);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, 0);
    expect_value(__wrap_sqlite3_column_text, iCol, 0);
    will_return(__wrap_sqlite3_column_text, NULL);

    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) has a NULL fim checksum.");

    ret = wdbi_checksum_range(data, 0, begin, end, test_hex);

    assert_int_equal(ret, 1);
}

// Test wdbi_delete

static void test_wdbi_delete_wbs_null(void **state)
{
    expect_assert_failure(wdbi_delete(NULL, 0, "test_begin", "test_end","test_tail"));
}

static void test_wdbi_delete_begin_null(void **state)
{
    int ret;

    wdb_t * data = *state;
    data->id = strdup("000");
    const char* begin = NULL;
    const char* end = "test_end";
    const char* tail = NULL;

    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, end);
    will_return(__wrap_sqlite3_bind_text, 0);

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_errmsg, "test_begin_null");

    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) sqlite3_step(): test_begin_null");

    ret = wdbi_delete(data, 0, begin, end, tail);

    assert_int_equal(ret, -1);
}

static void test_wdbi_delete_end_null(void **state)
{
    int ret;

    wdb_t * data = *state;
    data->id = strdup("000");
    const char* begin = "test_begin";
    const char* end = NULL;
    const char* tail = "test_tail";

    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, tail);
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    will_return(__wrap_sqlite3_bind_text, 0);

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_errmsg, "test_end_null");

    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) sqlite3_step(): test_end_null");

    ret = wdbi_delete(data, 0, begin, end, tail);

    assert_int_equal(ret, -1);
}

static void test_wdbi_delete_tail_null(void **state)
{
    int ret;

    wdb_t * data = *state;
    data->id = strdup("000");
    const char* begin = "test_begin";
    const char* end = "test_end";
    const char* tail = NULL;

    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, begin);
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, end);
    will_return(__wrap_sqlite3_bind_text, 0);

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_errmsg, "test_tail_null");

    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) sqlite3_step(): test_tail_null");

    ret = wdbi_delete(data, 0, begin, end, tail);

    assert_int_equal(ret, -1);
}

static void test_wdbi_delete_wdb_stmt_cache_fail(void **state)
{
    int ret;

    wdb_t * data = *state;
    data->id = strdup("000");
    will_return(__wrap_wdb_stmt_cache, -1);

    ret = wdbi_delete(data, 0, "test_begin", "test_end","test_tail");

    assert_int_equal(ret, -1);
}

static void test_wdbi_delete_sql_no_done(void **state)
{
    int ret;

    wdb_t * data = *state;
    data->id = strdup("000");
    const char* begin = "test_begin";
    const char* end = "test_end";
    const char* tail = "test_fail";

    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, end);
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, tail);
    will_return(__wrap_sqlite3_bind_text, 0);

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_errmsg, "test_sql_no_done");

    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) sqlite3_step(): test_sql_no_done");

    ret = wdbi_delete(data, 0, begin, end, tail);

    assert_int_equal(ret, -1);
}

static void test_wdbi_delete_success(void **state)
{
    int ret;

    wdb_t * data = *state;
    data->id = strdup("000");
    const char* begin = "test_begin";
    const char* end = "test_end";
    const char* tail = "test_fail";

    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, end);
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, tail);
    will_return(__wrap_sqlite3_bind_text, 0);

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, 101);

    ret = wdbi_delete(data, 0, begin, end, tail);

    assert_int_equal(ret, 0);
}

// Test wdbi_update_attempt

static void test_wdbi_update_attempt_wbs_null(void **state)
{
    os_sha1 checksum = "ebccd0d055bfd85fecc7fe612f3ecfc14d679b1a";

    expect_assert_failure(wdbi_update_attempt(NULL, 0, 1, FALSE, checksum));
}

static void test_wdbi_update_attempt_stmt_cache_fail(void **state)
{
    wdb_t * data = *state;
    data->id = strdup("000");
    os_sha1 checksum = "ebccd0d055bfd85fecc7fe612f3ecfc14d679b1a";

    will_return(__wrap_wdb_stmt_cache, -1);

    wdbi_update_attempt(data, 0, 0, FALSE, checksum);
}

static void test_wdbi_update_attempt_no_sql_done(void **state)
{
    wdb_t * data = *state;
    data->id = strdup("000");
    const char *component = "fim";
    os_sha1 checksum = "ebccd0d055bfd85fecc7fe612f3ecfc14d679b1a";

    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_int64, index, 1);
    expect_value(__wrap_sqlite3_bind_int64, value, 0);
    will_return(__wrap_sqlite3_bind_int64, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, checksum);
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_string(__wrap_sqlite3_bind_text, buffer, component);
    will_return(__wrap_sqlite3_bind_text, 0);

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, 1);
    will_return(__wrap_sqlite3_errmsg, "test_no_sql_done");

    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) sqlite3_step(): test_no_sql_done");

    wdbi_update_attempt(data, WDB_FIM, 0, FALSE, checksum);
}

static void test_wdbi_update_attempt_success(void **state)
{
    wdb_t * data = *state;
    data->id = strdup("000");
    const char *component = "fim";
    os_sha1 checksum = "ebccd0d055bfd85fecc7fe612f3ecfc14d679b1a";

    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_int64, index, 1);
    expect_value(__wrap_sqlite3_bind_int64, value, 0);
    will_return(__wrap_sqlite3_bind_int64, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, checksum);
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_string(__wrap_sqlite3_bind_text, buffer, component);
    will_return(__wrap_sqlite3_bind_text, 0);

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, 101);

    wdbi_update_attempt(data, WDB_FIM, 0, FALSE, checksum);
}

// Test wdbi_update_completion

static void test_wdbi_update_completion_wbs_null(void **state)
{
    expect_assert_failure(wdbi_update_completion(NULL, 0, 0, ""));
}

static void test_wdbi_update_completion_stmt_cache_fail(void **state)
{
    wdb_t * data = *state;
    data->id = strdup("000");

    will_return(__wrap_wdb_stmt_cache, -1);

    wdbi_update_completion(data, 0, 0, "");
}

static void test_wdbi_update_completion_no_sql_done(void **state)
{
    wdb_t * data = *state;
    data->id = strdup("000");
    const char *component = "fim";

    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_int64, index, 1);
    expect_value(__wrap_sqlite3_bind_int64, value, 0);
    will_return(__wrap_sqlite3_bind_int64, 0);
    expect_value(__wrap_sqlite3_bind_int64, index, 2);
    expect_value(__wrap_sqlite3_bind_int64, value, 0);
    will_return(__wrap_sqlite3_bind_int64, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_string(__wrap_sqlite3_bind_text, buffer, "");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 4);
    expect_string(__wrap_sqlite3_bind_text, buffer, component);
    will_return(__wrap_sqlite3_bind_text, 0);

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, 1);
    will_return(__wrap_sqlite3_errmsg, "test_no_sql_done");

    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) sqlite3_step(): test_no_sql_done");

    wdbi_update_completion(data, WDB_FIM, 0, "");
}

static void test_wdbi_update_completion_success(void **state)
{
    wdb_t * data = *state;
    data->id = strdup("000");
    const char *component = "fim";

    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_int64, index, 1);
    expect_value(__wrap_sqlite3_bind_int64, value, 0);
    will_return(__wrap_sqlite3_bind_int64, 0);
    expect_value(__wrap_sqlite3_bind_int64, index, 2);
    expect_value(__wrap_sqlite3_bind_int64, value, 0);
    will_return(__wrap_sqlite3_bind_int64, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_string(__wrap_sqlite3_bind_text, buffer, "");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 4);
    expect_string(__wrap_sqlite3_bind_text, buffer, component);
    will_return(__wrap_sqlite3_bind_text, 0);

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, 101);

    wdbi_update_completion(data, WDB_FIM, 0, "");
}

// Test wdbi_query_clear

void test_wdbi_query_clear_null_payload(void **state)
{
    wdb_t *data = *state;
    int ret;
    os_strdup("000", data->id);
    char * payload = NULL;

    expect_string(__wrap__mdebug1, formatted_msg, "DB(000): cannot parse checksum range payload: '(null)'");

    ret = wdbi_query_clear(data, WDB_FIM, payload);

    assert_int_equal(ret, -1);
}

void test_wdbi_query_clear_invalid_payload(void **state)
{
    wdb_t *data = *state;
    int ret;
    os_strdup("000", data->id);
    char payload[] = "This is some test";

    expect_string(__wrap__mdebug1, formatted_msg, "DB(000): cannot parse checksum range payload: 'This is some test'");

    ret = wdbi_query_clear(data, WDB_FIM, payload);

    assert_int_equal(ret, -1);
}

void test_wdbi_query_clear_no_id(void **state)
{
    wdb_t *data = *state;
    int ret;
    os_strdup("000", data->id);
    char payload[] = "{\"Key\":\"Value\"}";

    expect_string(__wrap__mdebug1, formatted_msg, "No such string 'id' in JSON payload.");

    ret = wdbi_query_clear(data, WDB_FIM, payload);

    assert_int_equal(ret, -1);
}

void test_wdbi_query_clear_stmt_cache_error(void **state)
{
    wdb_t *data = *state;
    int ret;
    os_strdup("000", data->id);
    const char *payload = "{\"id\":5678}";

    will_return(__wrap_wdb_stmt_cache, -1);

    ret = wdbi_query_clear(data, WDB_FIM, payload);

    assert_int_equal(ret, -1);
}

void test_wdbi_query_clear_sql_step_error(void **state)
{
    wdb_t *data = *state;
    int ret;
    os_strdup("000", data->id);
    const char *payload = "{\"id\":5678}";

    will_return(__wrap_wdb_stmt_cache, 0);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_errmsg, "test_error");

    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) sqlite3_step(): test_error");

    ret = wdbi_query_clear(data, WDB_FIM, payload);

    assert_int_equal(ret, -1);
}

void test_wdbi_query_clear_ok(void **state)
{
    wdb_t *data = *state;
    int ret;
    os_strdup("000", data->id);
    const char *component = "fim";
    const char *payload = "{\"id\":5678}";

    will_return(__wrap_wdb_stmt_cache, 0);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, 101);

    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_int64, index, 1);
    expect_value(__wrap_sqlite3_bind_int64, value, 5678);
    will_return(__wrap_sqlite3_bind_int64, 0);
    expect_value(__wrap_sqlite3_bind_int64, index, 2);
    expect_value(__wrap_sqlite3_bind_int64, value, 5678);
    will_return(__wrap_sqlite3_bind_int64, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_string(__wrap_sqlite3_bind_text, buffer, "");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 4);
    expect_string(__wrap_sqlite3_bind_text, buffer, component);
    will_return(__wrap_sqlite3_bind_text, 0);

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, 101);

    ret = wdbi_query_clear(data, WDB_FIM, payload);

    assert_int_equal(ret, 0);
}

// Test wdbi_query_checksum

void test_wdbi_query_checksum_null_payload(void **state)
{
    wdb_t *data = *state;
    int ret;
    os_strdup("000", data->id);
    char * payload = NULL;

    expect_string(__wrap__mdebug1, formatted_msg, "DB(000): cannot parse checksum range payload: '(null)'");

    ret = wdbi_query_checksum(data, WDB_FIM, "integrity_check_global", payload);

    assert_int_equal(ret, -1);
}

void test_wdbi_query_checksum_no_begin(void **state)
{
    wdb_t *data = *state;
    int ret;
    os_strdup("000", data->id);
    const char * payload = "{\"Bad\":\"Payload\"}";

    expect_string(__wrap__mdebug1, formatted_msg, "No such string 'begin' in JSON payload.");

    ret = wdbi_query_checksum(data, WDB_FIM, "integrity_check_global", payload);

    assert_int_equal(ret, -1);
}

void test_wdbi_query_checksum_no_end(void **state)
{
    wdb_t *data = *state;
    int ret;
    os_strdup("000", data->id);
    const char * payload = "{\"begin\":\"something\"}";

    expect_string(__wrap__mdebug1, formatted_msg, "No such string 'end' in JSON payload.");

    ret = wdbi_query_checksum(data, WDB_FIM, "integrity_check_global", payload);

    assert_int_equal(ret, -1);
}

void test_wdbi_query_checksum_no_checksum(void **state)
{
    wdb_t *data = *state;
    int ret;
    os_strdup("000", data->id);
    const char * payload = "{\"begin\":\"something\",\"end\":\"something\"}";

    expect_string(__wrap__mdebug1, formatted_msg, "No such string 'checksum' in JSON payload.");

    ret = wdbi_query_checksum(data, WDB_FIM, "integrity_check_global", payload);

    assert_int_equal(ret, -1);
}

void test_wdbi_query_checksum_no_id(void **state)
{
    wdb_t *data = *state;
    int ret;
    os_strdup("000", data->id);
    const char * payload = "{\"begin\":\"something\",\"end\":\"something\",\"checksum\":\"something\"}";

    expect_string(__wrap__mdebug1, formatted_msg, "No such string 'id' in JSON payload.");

    ret = wdbi_query_checksum(data, WDB_FIM, "integrity_check_global", payload);

    assert_int_equal(ret, -1);
}

void test_wdbi_query_checksum_range_fail(void **state)
{
    wdb_t *data = *state;
    int ret;
    os_strdup("000", data->id);
    const char * payload = "{\"begin\":\"something\",\"end\":\"something\",\"checksum\":\"something\",\"id\":1234}";

    will_return(__wrap_wdb_stmt_cache, -1);

    ret = wdbi_query_checksum(data, WDB_FIM, "integrity_check_global", payload);

    assert_int_equal(ret, -1);
}

void test_wdbi_query_checksum_range_no_data(void **state)
{
    wdb_t *data = *state;
    int ret;
    os_strdup("000", data->id);
    const char *begin = "something";
    const char *end = "something";
    const char *component = "fim";
    const char * payload = "{\"begin\":\"something\",\"end\":\"something\",\"checksum\":\"something\",\"id\":1234}";

    will_return(__wrap_wdb_stmt_cache, 1);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, 101); //predelete
    will_return(__wrap_wdb_stmt_cache, 1);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, 101); //pre attemps
    will_return(__wrap_wdb_stmt_cache, 1);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, 101);

    // wdbi_checksum_range
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, begin);
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, end);
    will_return(__wrap_sqlite3_bind_text, 0);
    // wdbi_delete
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, begin);
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, end);
    will_return(__wrap_sqlite3_bind_text, 0);
    // wdbi_update_attempt
    expect_value(__wrap_sqlite3_bind_int64, index, 1);
    expect_value(__wrap_sqlite3_bind_int64, value, 1234);
    will_return(__wrap_sqlite3_bind_int64, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, begin);
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_string(__wrap_sqlite3_bind_text, buffer, component);
    will_return(__wrap_sqlite3_bind_text, 0);

    ret = wdbi_query_checksum(data, WDB_FIM, "integrity_check_global", payload);

    assert_int_equal(ret, 0);
}

void test_wdbi_query_checksum_diff_hexdigest(void **state)
{
    wdb_t *data = *state;
    int ret;
    os_strdup("000", data->id);
    const char *begin = "something";
    const char *end = "something";
    const char * payload = "{\"begin\":\"something\",\"end\":\"something\",\"checksum\":\"something\",\"id\":1234}";

    will_return(__wrap_wdb_stmt_cache, 0);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, 100);
    expect_value(__wrap_sqlite3_column_text, iCol, 0);
    will_return(__wrap_sqlite3_column_text, NULL);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, 101);
    will_return(__wrap_wdb_stmt_cache, -1);
    will_return(__wrap_wdb_stmt_cache, -1);

    // wdbi_checksum_range
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, begin);
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, end);
    will_return(__wrap_sqlite3_bind_text, 0);

    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) has a NULL fim checksum.");
    expect_any(__wrap__mdebug2, formatted_msg);

    ret = wdbi_query_checksum(data, WDB_FIM, "integrity_check_global", payload);

    assert_int_equal(ret, 1);
}

void test_wdbi_query_checksum_equal_hexdigest(void **state)
{
    wdb_t *data = *state;
    int ret;
    os_strdup("000", data->id);
    const char *begin = "something";
    const char *end = "something";
    const char * payload = "{\"begin\":\"something\",\"end\":\"something\",\"checksum\":\"da39a3ee5e6b4b0d3255bfef95601890afd80709\",\"id\":1234}";

    will_return(__wrap_wdb_stmt_cache, 0);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, 100);
    expect_value(__wrap_sqlite3_column_text, iCol, 0);
    will_return(__wrap_sqlite3_column_text, "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    expect_string(__wrap_EVP_DigestUpdate, data, "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    expect_value(__wrap_EVP_DigestUpdate, count, 40);
    will_return(__wrap_EVP_DigestUpdate, 0);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, 101);
    will_return(__wrap_wdb_stmt_cache, -1);
    will_return(__wrap_wdb_stmt_cache, -1);

    // wdbi_checksum_range
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, begin);
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, end);
    will_return(__wrap_sqlite3_bind_text, 0);

    expect_any(__wrap__mdebug2, formatted_msg);

    ret = wdbi_query_checksum(data, WDB_FIM, "integrity_check_global", payload);

    assert_int_equal(ret, 2);
}

void test_wdbi_query_checksum_bad_command(void **state)
{
    wdb_t *data = *state;
    int ret;
    os_strdup("000", data->id);
    const char *begin = "something";
    const char *end = "something";
    const char * payload = "{\"begin\":\"something\",\"end\":\"something\",\"checksum\":\"something\",\"id\":1234}";

    will_return(__wrap_wdb_stmt_cache, 0);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, 100);
    expect_value(__wrap_sqlite3_column_text, iCol, 0);
    will_return(__wrap_sqlite3_column_text, NULL);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, 101);

    // wdbi_checksum_range
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, begin);
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, end);
    will_return(__wrap_sqlite3_bind_text, 0);

    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) has a NULL fim checksum.");
    expect_any(__wrap__mdebug2, formatted_msg);

    ret = wdbi_query_checksum(data, WDB_FIM, "bad_command", payload);

    assert_int_equal(ret, 1);
}

void test_wdbi_query_checksum_check_left_no_tail(void **state)
{
    wdb_t *data = *state;
    int ret;
    os_strdup("000", data->id);
    const char *begin = "something";
    const char *end = "something";
    const char * payload = "{\"begin\":\"something\",\"end\":\"something\",\"checksum\":\"something\",\"id\":1234}";

    will_return(__wrap_wdb_stmt_cache, 0);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, 100);
    expect_value(__wrap_sqlite3_column_text, iCol, 0);
    will_return(__wrap_sqlite3_column_text, "something");
    expect_string(__wrap_EVP_DigestUpdate, data, "something");
    expect_value(__wrap_EVP_DigestUpdate, count, 9);
    will_return(__wrap_EVP_DigestUpdate, 0);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, 101);
    will_return(__wrap_wdb_stmt_cache, -1);

    // wdbi_checksum_range
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, begin);
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, end);
    will_return(__wrap_sqlite3_bind_text, 0);

    expect_any(__wrap__mdebug2, formatted_msg);

    ret = wdbi_query_checksum(data, WDB_FIM, "integrity_check_left", payload);

    assert_int_equal(ret, 1);
}

void test_wdbi_query_checksum_check_left_ok(void **state)
{
    wdb_t *data = *state;
    int ret;
    os_strdup("000", data->id);

    const char *begin = "something";
    const char *end = "something";
    const char * payload = "{\"begin\":\"something\",\"end\":\"something\",\"checksum\":\"something\",\"id\":1234,\"tail\":\"something\"}";

    will_return(__wrap_wdb_stmt_cache, 0);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, 100);
    expect_value(__wrap_sqlite3_column_text, iCol, 0);
    will_return(__wrap_sqlite3_column_text, "something");
    expect_string(__wrap_EVP_DigestUpdate, data, "something");
    expect_value(__wrap_EVP_DigestUpdate, count, 9);
    will_return(__wrap_EVP_DigestUpdate, 0);
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, 101);
    will_return(__wrap_wdb_stmt_cache, -1);

    // wdbi_checksum_range
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, begin);
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, end);
    will_return(__wrap_sqlite3_bind_text, 0);

    expect_any(__wrap__mdebug2, formatted_msg);

    ret = wdbi_query_checksum(data, WDB_FIM, "integrity_check_left", payload);

    assert_int_equal(ret, 1);
}

//Test wdbi_sha_calculate
void test_wdbi_sha_calculate_array_success(void **state)
{
    const char** test_words = NULL;
    int ret_val = -1;
    os_sha1 hexdigest;

    os_malloc(6 * sizeof(char*),test_words);

    test_words[0] = "FirstWord";
    test_words[1] = "SecondWord";
    test_words[2] = "Word number 3";
    test_words[3] = "";
    test_words[4] = " ";
    test_words[5]= NULL;

    // Using real EVP_DigestUpdate
    test_mode = 0;

    ret_val = wdbi_sha_calculation(test_words, hexdigest, 0);

    assert_int_equal (ret_val, 0);
    assert_string_equal(hexdigest, "159a9a6e19ff891a8560376df65a078e064bd0ce");

    os_free(test_words);
}

void test_wdbi_sha_calculate_parameters_success(void **state)
{
    int ret_val = -1;
    os_sha1 hexdigest;

    // Using real EVP_DigestUpdate
    test_mode = 0;

    ret_val = wdbi_sha_calculation(NULL, hexdigest, 5, "FirstWord", "SecondWord", "Word number 3", "", " ");

    assert_int_equal (ret_val, 0);
    assert_string_equal(hexdigest, "159a9a6e19ff891a8560376df65a078e064bd0ce");
}

int main(void) {
    const struct CMUnitTest tests[] = {
        //Test wdb_calculate_stmt_checksum
        cmocka_unit_test(test_wdb_calculate_stmt_checksum_wdb_null),
        cmocka_unit_test_setup_teardown(test_wdb_calculate_stmt_checksum_stmt_null, setup_wdb_t, teardown_wdb_t),
        cmocka_unit_test_setup_teardown(test_wdb_calculate_stmt_checksum_cks_null, setup_wdb_t, teardown_wdb_t),
        cmocka_unit_test_setup_teardown(test_wdb_calculate_stmt_checksum_no_row, setup_wdb_t, teardown_wdb_t),
        cmocka_unit_test_setup_teardown(test_wdb_calculate_stmt_checksum_success, setup_wdb_t, teardown_wdb_t),

        //Test wdbi_checksum_range
        cmocka_unit_test(test_wdbi_checksum_wbs_null),
        cmocka_unit_test_setup_teardown(test_wdbi_checksum_hexdigest_null, setup_wdb_t, teardown_wdb_t),
        cmocka_unit_test_setup_teardown(test_wdbi_checksum_wdb_stmt_cache_fail, setup_wdb_t, teardown_wdb_t),
        cmocka_unit_test_setup_teardown(test_wdbi_checksum_success, setup_wdb_t, teardown_wdb_t),

        //Test wdbi_checksum_range
        cmocka_unit_test(test_wdbi_checksum_range_wbs_null),
        cmocka_unit_test_setup_teardown(test_wdbi_checksum_range_hexdigest_null, setup_wdb_t, teardown_wdb_t),
        cmocka_unit_test_setup_teardown(test_wdbi_checksum_range_wdb_stmt_cache_fail, setup_wdb_t, teardown_wdb_t),
        cmocka_unit_test_setup_teardown(test_wdbi_checksum_range_begin_null, setup_wdb_t, teardown_wdb_t),
        cmocka_unit_test_setup_teardown(test_wdbi_checksum_range_end_null, setup_wdb_t, teardown_wdb_t),
        cmocka_unit_test_setup_teardown(test_wdbi_checksum_range_success, setup_wdb_t, teardown_wdb_t),

        //Test wdbi_delete
        cmocka_unit_test(test_wdbi_delete_wbs_null),
        cmocka_unit_test_setup_teardown(test_wdbi_delete_begin_null, setup_wdb_t, teardown_wdb_t),
        cmocka_unit_test_setup_teardown(test_wdbi_delete_end_null, setup_wdb_t, teardown_wdb_t),
        cmocka_unit_test_setup_teardown(test_wdbi_delete_tail_null, setup_wdb_t, teardown_wdb_t),
        cmocka_unit_test_setup_teardown(test_wdbi_delete_wdb_stmt_cache_fail, setup_wdb_t, teardown_wdb_t),
        cmocka_unit_test_setup_teardown(test_wdbi_delete_sql_no_done, setup_wdb_t, teardown_wdb_t),
        cmocka_unit_test_setup_teardown(test_wdbi_delete_success, setup_wdb_t, teardown_wdb_t),

        //Test wdbi_update_attempt
        cmocka_unit_test(test_wdbi_update_attempt_wbs_null),
        cmocka_unit_test_setup_teardown(test_wdbi_update_attempt_stmt_cache_fail, setup_wdb_t, teardown_wdb_t),
        cmocka_unit_test_setup_teardown(test_wdbi_update_attempt_no_sql_done, setup_wdb_t, teardown_wdb_t),
        cmocka_unit_test_setup_teardown(test_wdbi_update_attempt_success, setup_wdb_t, teardown_wdb_t),

        //Test wdbi_update_completion
        cmocka_unit_test(test_wdbi_update_completion_wbs_null),
        cmocka_unit_test_setup_teardown(test_wdbi_update_completion_stmt_cache_fail, setup_wdb_t, teardown_wdb_t),
        cmocka_unit_test_setup_teardown(test_wdbi_update_completion_no_sql_done, setup_wdb_t, teardown_wdb_t),
        cmocka_unit_test_setup_teardown(test_wdbi_update_completion_success, setup_wdb_t, teardown_wdb_t),

        //Test wdbi_query_clear
        cmocka_unit_test_setup_teardown(test_wdbi_query_clear_null_payload, setup_wdb_t, teardown_wdb_t),
        cmocka_unit_test_setup_teardown(test_wdbi_query_clear_invalid_payload, setup_wdb_t, teardown_wdb_t),
        cmocka_unit_test_setup_teardown(test_wdbi_query_clear_no_id, setup_wdb_t, teardown_wdb_t),
        cmocka_unit_test_setup_teardown(test_wdbi_query_clear_stmt_cache_error, setup_wdb_t, teardown_wdb_t),
        cmocka_unit_test_setup_teardown(test_wdbi_query_clear_sql_step_error, setup_wdb_t, teardown_wdb_t),
        cmocka_unit_test_setup_teardown(test_wdbi_query_clear_ok, setup_wdb_t, teardown_wdb_t),

        //Test wdbi_query_checksum
        cmocka_unit_test_setup_teardown(test_wdbi_query_checksum_null_payload, setup_wdb_t, teardown_wdb_t),
        cmocka_unit_test_setup_teardown(test_wdbi_query_checksum_no_begin, setup_wdb_t, teardown_wdb_t),
        cmocka_unit_test_setup_teardown(test_wdbi_query_checksum_no_end, setup_wdb_t, teardown_wdb_t),
        cmocka_unit_test_setup_teardown(test_wdbi_query_checksum_no_checksum, setup_wdb_t, teardown_wdb_t),
        cmocka_unit_test_setup_teardown(test_wdbi_query_checksum_no_id, setup_wdb_t, teardown_wdb_t),
        cmocka_unit_test_setup_teardown(test_wdbi_query_checksum_range_fail, setup_wdb_t, teardown_wdb_t),
        cmocka_unit_test_setup_teardown(test_wdbi_query_checksum_range_no_data, setup_wdb_t, teardown_wdb_t),
        cmocka_unit_test_setup_teardown(test_wdbi_query_checksum_diff_hexdigest, setup_wdb_t, teardown_wdb_t),
        cmocka_unit_test_setup_teardown(test_wdbi_query_checksum_equal_hexdigest, setup_wdb_t, teardown_wdb_t),
        cmocka_unit_test_setup_teardown(test_wdbi_query_checksum_bad_command, setup_wdb_t, teardown_wdb_t),
        cmocka_unit_test_setup_teardown(test_wdbi_query_checksum_check_left_no_tail, setup_wdb_t, teardown_wdb_t),
        cmocka_unit_test_setup_teardown(test_wdbi_query_checksum_check_left_ok, setup_wdb_t, teardown_wdb_t),

        //Test wdbi_sha_calculate
        cmocka_unit_test_setup_teardown(test_wdbi_sha_calculate_array_success, setup_wdb_t, teardown_wdb_t),
        cmocka_unit_test_setup_teardown(test_wdbi_sha_calculate_parameters_success, setup_wdb_t, teardown_wdb_t),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
