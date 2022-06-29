# File: duo_const.py
#
# Copyright (c) 2022 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.
DEFAULT_TIMEOUT = 30
ACTION_ID_TEST_CONNECTIVITY = "test_connectivity"
ACTION_ID_RETRIEVE_USERS = "retrieve_users"
ACTION_ID_GET_PHONE = "get_phone"
ACTION_ID_BYPASSCODE_FOR_USER = "bypasscode_for_user"
ACTION_ID_ASSOCIATE_PHONE_WITH_USER = "associate_phone_with_user"
ACTION_ID_CREATE_PHONE = "create_phone"
ACTION_ID_MODIFY_PHONE = "modify_phone"
ACTION_ID_DELETE_PHONE = "delete_phone"
ACTION_ID_ACTIVATION_CODE_VIA_SMS = "activation_code_via_sms"
ACTION_ID_SYNCHRONIZE_USER_FROM_DIRECTORY = "synchronize_user_from_directory"
DEFAULT_MAX_RESULTS = 300
DUO_VALID_INTEGER_MSG = "Please provide a valid integer value in the {param}"
DUO_NON_NEGATIVE_INTEGER_MSG = "Please provide a valid non-negative integer value in the {param}"
DUO_POSITIVE_INTEGER_MSG = "Please provide a valid non-zero positive integer value in the {param}"
PARAMS_CREATE_PHONE = ["number", "name", "extension", "type", "platform"]
PARAMS_RETRIEVE_USERS = ["username", "limit", "offset"]
PARAMS_BYPASSCODE_FOR_USER = ["count", "codes", "reuse_count", "valid_secs"]
PARAMS_MODIFY_PHONE = ["number", "name", "extension", "type", "platform"]
PARAMS_ACTIVATION_CODE_VIA_SMS = ["valid_secs", "install"]
PARAMS_SYNCHRONIZE_USER_FROM_DIRECTORY = ["username"]
ENDPOINT_TEST_CONNECTIVITY = '/admin/v1/users'
ENDPOINT_RETRIEVE_USERS = '/admin/v1/users'
ENDPOINT_GET_PHONE = '/admin/v1/phones/{}'
ENDPOINT_BYPASSCODE_FOR_USER = '/admin/v1/users/{}/bypass_codes'
ENDPOINT_ASSOCIATE_PHONE_WITH_USER = '/admin/v1/users/{}/phones'
ENDPOINT_CREATE_PHONE = '/admin/v1/phones'
ENDPOINT_MODIFY_PHONE = '/admin/v1/phones/{}'
ENDPOINT_DELETE_PHONE = '/admin/v1/phones/{}'
ENDPOINT_ACTIVATION_CODE_VIA_SMS = '/admin/v1/phones/{}/send_sms_activation'
ENDPOINT_SYNCHRONIZE_USER_FROM_DIRECTORY = '/admin/v1/users/directorysync/{}/syncuser'
ALLOW_ZERO_TRUE = ["offset", "reuse_count", "valid_secs"]
SUMMARY_TEST_CONNECTIVITY = '/admin/v1/users'
SUMMARY_GET_PHONE = "Phone found successfully"
SUMMARY_BYPASSCODE_FOR_USER = "Bypasscode generated successful"
SUMMARY_ASSOCIATE_PHONE_WITH_USER = "Phone associated to user"
SUMMARY_CREATE_PHONE = "Phone created successfully"
SUMMARY_MODIFY_PHONE = "Modify phone successful"
SUMMARY_ACTIVATION_CODE_VIA_SMS = "Send activation code via SMS successful"
SUMMARY_SYNCHRONIZE_USER_FROM_DIRECTORY = "API Call Successful"
SUMMARY_DELETE_PHONE = "Phone deleted successfully"
