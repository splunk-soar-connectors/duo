# File: duo_connector.py
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

import base64
import email.utils
import hashlib
import hmac
import json
import re
import urllib

import phantom.app as phantom
import requests
from bs4 import BeautifulSoup
from phantom.app import ActionResult, BaseConnector

from duo_const import *


class RetVal(tuple):
    def __new__(cls, val1, val2):
        return tuple.__new__(RetVal, (val1, val2))


class DuoConnector(BaseConnector):

    def __init__(self):
        super(DuoConnector, self).__init__()
        self.duo = requests.Session()
        self.api_host = None
        self.skey = None
        self.ikey = None

    def auth(self, host, skey, ikey, method="GET", path="/admin/v1/users", params={}):
        """
        Return HTTP Basic Authentication ("Authorization" and "Date") headers.
        method, host, path: strings from request
        params: dict of request parameters
        skey: secret key
        ikey: integration key
        """

        # create canonical string
        now = email.utils.formatdate()
        canon = [now, method.upper(), host.lower(), path]
        args = []
        for key in sorted(params.keys()):
            val = params[key].encode("utf-8")
            args.append(
                '%s=%s' % (urllib.parse.
                        quote(key, '~'), urllib.parse.quote(val, '~')))
        canon.append('&'.join(args))
        canon = '\n'.join(canon)

        # sign canonical string
        sig = hmac.new(bytes(skey, encoding='utf-8'),
                    bytes(canon, encoding='utf-8'),
                    hashlib.sha1)
        auth = '%s:%s' % (ikey, sig.hexdigest())

        # return headers
        return {'Date': now, 'Authorization': 'Basic %s' % base64.b64encode(bytes(auth, encoding="utf-8")).decode()}

    def _process_empty_response(self, response, action_result):
        if response.status_code == 200:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(
            action_result.set_status(
                phantom.APP_ERROR, "Empty response and no information in the header"
            ), None
        )

    def _process_html_response(self, response, action_result):
        # An html response, treat it like an error
        status_code = response.status_code
        if status_code == 200:
            return RetVal(phantom.APP_SUCCESS, response.text)
        try:
            soup = BeautifulSoup(response.text, "html.parser")
            error_text = soup.text
            split_lines = error_text.split('\n')
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = '\n'.join(split_lines)
        except:
            error_text = "Cannot parse error details"

        message = "Status Code: {0}. Data from server:\n{1}\n".format(status_code, error_text)

        message = message.replace(u'{', '{{').replace(u'}', '}}')
        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, r, action_result):
        # Try a json parse
        try:
            resp_json = r.json()
        except Exception as e:
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR, "Unable to parse JSON response. Error: {0}".format(str(e))
                ), None
            )

        # Please specify the status codes here
        if 200 <= r.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        # You should process the error returned in the json
        message = "Error from server. Status Code: {0} Data from server: {1}".format(
            r.status_code,
            r.text.replace(u'{', '{{').replace(u'}', '}}')
        )

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_response(self, r, action_result):
        # store the r_text in debug data, it will get dumped in the logs if the action fails
        if hasattr(action_result, 'add_debug_data'):
            action_result.add_debug_data({'r_status_code': r.status_code})
            action_result.add_debug_data({'r_text': r.text})
            action_result.add_debug_data({'r_headers': r.headers})

        # Process each 'Content-Type' of response separately

        # Process a json response
        if 'json' in r.headers.get('Content-Type', ''):
            return self._process_json_response(r, action_result)

        # Process an HTML response, Do this no matter what the api talks.
        # There is a high chance of a PROXY in between phantom and the rest of
        # world, in case of errors, PROXY's return HTML, this function parses
        # the error and adds it to the action_result.
        if 'html' in r.headers.get('Content-Type', ''):
            return self._process_html_response(r, action_result)

        # it's not content-type that is to be parsed, handle an empty response
        if not r.text:
            return self._process_empty_response(r, action_result)

        # everything else is actually an error at this point
        message = "Can't process response from server. Status Code: {0} Data from server: {1}".format(
            r.status_code,
            r.text.replace('{', '{{').replace('}', '}}')
        )

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _validate_integer(self, action_result, parameter, key, allow_zero=False):
        """
        Validate an integer.

        :param action_result: Action result or BaseConnector object
        :param parameter: input parameter
        :param key: input parameter message key
        :allow_zero: whether zero should be considered as valid value or not
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS, integer value of the parameter or None in case of failure
        """
        if parameter is not None:
            try:
                if not float(parameter).is_integer():
                    return action_result.set_status(phantom.APP_ERROR, DUO_VALID_INTEGER_MSG.format(param=key)), None

                parameter = int(parameter)
            except Exception:
                return action_result.set_status(phantom.APP_ERROR, DUO_VALID_INTEGER_MSG.format(param=key)), None

            if parameter < 0:
                return action_result.set_status(phantom.APP_ERROR, DUO_NON_NEGATIVE_INTEGER_MSG.format(param=key)), None
            if not allow_zero and parameter == 0:
                return action_result.set_status(phantom.APP_ERROR, DUO_POSITIVE_INTEGER_MSG.format(param=key)), None

        return phantom.APP_SUCCESS, parameter

    def _make_rest_call(self, endpoint, action_result, method="get", params={}, **kwargs):
        # **kwargs can be any additional parameters that requests.request accepts

        auth_params = {}
        for key in params.keys():
            auth_params[key] = str(params[key])
        headers = self.auth(host=self.api_host, skey=self.skey, ikey=self.ikey, path=endpoint, method=method, params=auth_params)
        resp_json = None

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(
                action_result.set_status(phantom.APP_ERROR, "Invalid method: {0}".format(method)),
                resp_json
            )

        # Create a URL to connect to
        url = "https://{}{}".format(self.api_host, endpoint)

        try:
            r = request_func(
                url,
                # auth=(username, password),  # basic authentication
                headers=headers,
                params=params,
                timeout=DEFAULT_TIMEOUT,
                **kwargs
            )
        except Exception as e:
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR, "Error Connecting to server. Details: {0}".format(str(e))
                ), resp_json
            )

        return self._process_response(r, action_result)

    def _paginator(self, endpoint, action_result, method="get", params={}, **kwargs):
        action_id = self.get_action_identifier()
        max_limit = DEFAULT_MAX_RESULTS

        response = {}
        limit_count = params.get("limit")

        while True:
            ret_val, interim_response = self._make_rest_call(endpoint, action_result,
                method=method, params=params, **kwargs)
            if phantom.is_fail(ret_val):
                return ret_val, interim_response

            if response:
                if not interim_response['metadata'].get("next_offset"):
                    response['metadata'].pop("next_offset")
                response['metadata'].update(interim_response['metadata'])

                if action_id == 'retrieve_users':
                    response['response'].extend(interim_response['response'])
            else:
                response = interim_response
            if not response.get("metadata") or not response["metadata"].get("next_offset"):
                break

            if isinstance(limit_count, int):
                limit_count = limit_count - max_limit
                params['offset'] = response["metadata"].get("next_offset")
                limit = min(max_limit, limit_count)
                params["limit"] = limit

                if params.get("limit") <= 0:
                    break

            if params.get("limit") is None:
                break

        return ret_val, response

    def initialize(self):
        config = self.get_config()
        self.api_host = config['api_host']
        self.skey = config['skey']
        self.ikey = config['ikey']
        return phantom.APP_SUCCESS

    def get_params(self, param, parameters, action_result, action_name=""):
        available_keys = param.keys()
        params = {}
        for key in parameters:
            if key in available_keys:
                params[key] = param[key]
                if isinstance(params[key], bool) or isinstance(params[key], str):
                    continue
                params[key] = int(params[key])
                if isinstance(params[key], int):
                    allow_zero = False
                    if key in ALLOW_ZERO_TRUE and action_name != ACTION_ID_ACTIVATION_CODE_VIA_SMS:
                        allow_zero = True
                    ret_val, _ = self._validate_integer(action_result, params.get(key), key, allow_zero=allow_zero)
                    if phantom.is_fail(ret_val):
                        return ret_val

        return params

    def process_with_regex(self, params, action_result):

        if params.get("number"):
            regex = r"^\+(?:[0-9] ?-?){6,14}[0-9]$"
            processed_number = ""

            if re.search(regex, params["number"]):

                for i in range(len(params["number"])):
                    if not re.search(r"[\s|-]", params["number"][i]):
                        processed_number = processed_number + params["number"][i]

                params["number"] = processed_number
            else:
                return action_result.set_status(phantom.APP_ERROR, "Phone number is not valid")

        if params.get("extension"):
            regex = r"[0-9|\#|\*]+"
            if not re.search(regex, params.get("extension")):
                return action_result.set_status(phantom.APP_ERROR, "Extension not valid")

        return params

    def _handle_test_connectivity(self, param):
        self.save_progress("Connecting to endpoint")
        try:
            action_result = self.add_action_result(ActionResult(dict(param)))
            ret_val, response = self._make_rest_call(
                ENDPOINT_TEST_CONNECTIVITY, action_result, params={"limit": 1}
            )
            if phantom.is_fail(ret_val):
                self.save_progress("Test Connectivity Failed.")
                return action_result.get_status()
        except requests.HTTPError as e:
            return self.set_status_save_progress(phantom.APP_ERROR, 'Unable to connect to API server', e)
        self.save_progress("Test Connectivity Passed")
        return RetVal(action_result.set_status(phantom.APP_SUCCESS), None)

    def _handle_retrieve_users(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))
        endpoint = ENDPOINT_RETRIEVE_USERS

        params = self.get_params(param, PARAMS_RETRIEVE_USERS, action_result)
        if isinstance(params, bool):
            ret_val = params
            if phantom.is_fail(ret_val):
                return RetVal(action_result.get_status(), None)

        ret_val, response = self._paginator(endpoint, action_result, method="get", params=params)

        if phantom.is_fail(ret_val):
            return RetVal(ret_val, None)

        try:
            action_result.add_data(response['response'])
        except Exception:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Action Failed"), None)

        summary = action_result.update_summary({})
        summary['users_found'] = len(response["response"])
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_phone(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))
        endpoint = ENDPOINT_GET_PHONE.format(param["phone_id"])

        ret_val, response = self._make_rest_call(endpoint, action_result, method="get",)

        if phantom.is_fail(ret_val):
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR, "Parameter phone_id is not valid."
                ), None
            )

        try:
            action_result.add_data(response['response'])
        except Exception:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Action Failed"), None)

        summary = action_result.update_summary({})
        summary['status'] = SUMMARY_GET_PHONE
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_bypasscode_for_user(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))
        endpoint = ENDPOINT_BYPASSCODE_FOR_USER.format(param["user_id"],)
        method = "post"

        params = self.get_params(param, PARAMS_BYPASSCODE_FOR_USER, action_result)

        if isinstance(params, bool):
            ret_val = params
            if phantom.is_fail(ret_val):
                return RetVal(action_result.get_status(), None)

        if params.get("codes"):
            try:
                all_codes = params.get("codes")
                codes_without_space = all_codes.replace(" ", "")
                all_codes = codes_without_space.split(",")
                final_codes = []
                for code in all_codes:
                    if len(code) == 0:
                        continue
                    elif len(code) == 9:
                        if not code.isdigit():
                            return RetVal(
                                action_result.set_status(
                                    phantom.APP_ERROR, "Parameter codes need to be in numeric form not in string {} is not valid".format(code)
                                ), None
                            )
                        final_codes.append(code)
                    elif len(code) != 9:
                        return RetVal(
                            action_result.set_status(
                                phantom.APP_ERROR, "Parameter codes is not valid need exact nine digits"
                            ), None
                        )

                unique_codes = set(final_codes)

                if len(final_codes) != len(unique_codes):
                    return RetVal(
                        action_result.set_status(
                            phantom.APP_ERROR, "Need unique codes. Duplicate codes are not valid"
                        ), None
                    )
                if len(final_codes) > 10:
                    return RetVal(
                        action_result.set_status(
                            phantom.APP_ERROR, "More than ten bypass codes are not allowed"
                        ), None
                    )
                params["codes"] = ",".join(final_codes)
            except Exception as e:
                return RetVal(
                        action_result.set_status(
                            phantom.APP_ERROR, "Parameter is Not Valid. Error : {}".format(e)
                        ), None
                    )

        ret_val, response = self._make_rest_call(endpoint, action_result, method=method, params=params)
        if phantom.is_fail(ret_val):
            if params.get("count") and params["count"] > 0 and params.get("codes"):
                return RetVal(
                    action_result.set_status(
                        phantom.APP_ERROR, "parameter count and codes are mutually exclusive please provide one of the parameter"
                    ), None
                 )

            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR, "Parameters are not valid."
                ), None
            )

        try:
            action_result.add_data(response['response'])
        except Exception:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Action Failed"), None)

        summary = action_result.update_summary({})
        summary['status'] = SUMMARY_BYPASSCODE_FOR_USER
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_associate_phone_with_user(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))
        endpoint = ENDPOINT_ASSOCIATE_PHONE_WITH_USER.format(param["user_id"])
        method = "post"

        params = {
            "phone_id": param.get("phone_id")
        }

        ret_val, response = self._make_rest_call(endpoint, action_result, method=method, params=params)
        if phantom.is_fail(ret_val):
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR, "Parameters are not valid."
                ), None
            )

        try:
            action_result.add_data(response['response'])
        except Exception:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Action Failed"), None)

        summary = action_result.update_summary({})
        summary['status'] = SUMMARY_ASSOCIATE_PHONE_WITH_USER
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_create_phone(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))
        endpoint = ENDPOINT_CREATE_PHONE
        method = "post"
        params = self.get_params(param, PARAMS_CREATE_PHONE, action_result)

        if isinstance(params, bool):
            ret_val = params
            if phantom.is_fail(ret_val):
                return RetVal(action_result.get_status(), None)

        params = self.process_with_regex(params, action_result)

        if isinstance(params, bool):
            ret_val = params
            if phantom.is_fail(ret_val):
                return RetVal(action_result.get_status(), None)

        ret_val, response = self._make_rest_call(endpoint, action_result, method=method, params=params)

        if phantom.is_fail(ret_val):
            if "40003" in action_result.get_message():
               return RetVal(
                    action_result.set_status(
                        phantom.APP_ERROR, "Phone number already exist"
                    ), None
                )
            elif "number" in action_result.get_message():
                return RetVal(
                    action_result.set_status(
                        phantom.APP_ERROR, "Phone number is not valid"
                    ), None
                )

            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR, "Please provide valid parameter"
                ), None
            )

        try:
            action_result.add_data(response['response'])
        except Exception:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Action Failed"), None)

        summary = action_result.update_summary({})
        summary['status'] = SUMMARY_CREATE_PHONE
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_modify_phone(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))
        endpoint = ENDPOINT_MODIFY_PHONE.format(param["phone_id"])
        method = "post"
        params = self.get_params(param, PARAMS_MODIFY_PHONE, action_result)

        if isinstance(params, bool):
            ret_val = params
            if phantom.is_fail(ret_val):
                return RetVal(action_result.get_status(), None)

        params = self.process_with_regex(params, action_result)
        if isinstance(params, bool):
            ret_val = params
            if phantom.is_fail(ret_val):
                return RetVal(action_result.get_status(), None)

        ret_val, response = self._make_rest_call(endpoint, action_result, method=method, params=params)

        if phantom.is_fail(ret_val):

            if "number" in action_result.get_message():
                return RetVal(
                    action_result.set_status(
                        phantom.APP_ERROR, "Phone number is not valid"
                    ), None
                )

            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR, "Invalid parameter"
                ), None
            )

        try:
            action_result.add_data(response['response'])
        except Exception:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Action Failed"), None)

        summary = action_result.update_summary({})
        summary['status'] = SUMMARY_MODIFY_PHONE
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_delete_phone(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))
        endpoint = ENDPOINT_DELETE_PHONE.format(param["phone_id"])
        method = "delete"
        params = {}

        ret_val, response = self._make_rest_call(endpoint, action_result, method=method, params=params)

        if phantom.is_fail(ret_val):

            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR, "Please provide valid parameter"
                ), None
            )

        try:
            action_result.add_data(response['response'])
        except Exception:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Action Failed"), None)

        summary = action_result.update_summary({})
        summary['status'] = SUMMARY_DELETE_PHONE
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_activation_code_via_sms(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))
        endpoint = ENDPOINT_GET_PHONE.format(param["phone_id"])

        params = self.get_params(param, PARAMS_ACTIVATION_CODE_VIA_SMS, action_result, action_name=ACTION_ID_ACTIVATION_CODE_VIA_SMS)

        if params.get("valid_secs") and params.get("valid_secs") > 2592000:
            return RetVal(
                    action_result.set_status(
                        phantom.APP_ERROR, "valid_sec can not be more than 2592000(30days)"
                    ), None
                 )
        if isinstance(params, bool):
            ret_val = params
            if phantom.is_fail(ret_val):
                return RetVal(action_result.get_status(), None)

        ret_val, response = self._make_rest_call(endpoint, action_result,)

        if phantom.is_fail(ret_val):
            return RetVal(
                    action_result.set_status(
                        phantom.APP_ERROR, "Please provide valid phone_id"
                    ), None
                 )
        try:
            if len(response["response"].get("number")) == 0:
                return RetVal(
                        action_result.set_status(
                            phantom.APP_ERROR, "Please provide phone number in given phone_id"
                        ), None
                    )

            if response["response"].get("type") == "Unknown" or response["response"].get("platform") == "Unknown":
                return RetVal(
                        action_result.set_status(
                            phantom.APP_ERROR, "Action will not work if type or platform is Unknown"
                        ), None
                    )

        except Exception as e:
            return RetVal(
                    action_result.set_status(
                        phantom.APP_ERROR, "Action Failed. Error : {}".format(e)
                    ), None
               )
        endpoint = ENDPOINT_ACTIVATION_CODE_VIA_SMS.format(param["phone_id"])
        method = "post"
        ret_val, response = self._make_rest_call(endpoint, action_result, method=method, params=params)
        if phantom.is_fail(ret_val):
            if "40006" in action_result.get_message():
                return RetVal(action_result.get_status(), None)

            return RetVal(
                    action_result.set_status(
                        phantom.APP_ERROR, "Parameters are not valid"
                    ), None
                 )
        try:
            action_result.add_data(response['response'])
        except Exception:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Action Failed"), None)

        summary = action_result.update_summary({})
        summary['status'] = SUMMARY_ACTIVATION_CODE_VIA_SMS
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_synchronize_user_from_directory(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))
        endpoint = ENDPOINT_SYNCHRONIZE_USER_FROM_DIRECTORY.format(param["directory_key"])
        method = "post"

        params = self.get_params(param, PARAMS_SYNCHRONIZE_USER_FROM_DIRECTORY, action_result)

        if isinstance(params, bool):
            ret_val = params
            if phantom.is_fail(ret_val):
                return RetVal(action_result.get_status(), None)

        ret_val, response = self._make_rest_call(endpoint, action_result, method=method, params=params)

        if phantom.is_fail(ret_val):
            return ret_val

        try:
            action_result.add_data(response['response'])
        except Exception:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Action Failed"), None)

        summary = action_result.update_summary({})
        summary['status'] = SUMMARY_SYNCHRONIZE_USER_FROM_DIRECTORY
        return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):
        ret_val = phantom.APP_SUCCESS
        action_id = self.get_action_identifier()
        if action_id == ACTION_ID_TEST_CONNECTIVITY:
            ret_val = self._handle_test_connectivity(param)
        if action_id == ACTION_ID_RETRIEVE_USERS:
            ret_val = self._handle_retrieve_users(param)
        if action_id == ACTION_ID_GET_PHONE:
            ret_val = self._handle_get_phone(param)
        if action_id == ACTION_ID_BYPASSCODE_FOR_USER:
            ret_val = self._handle_bypasscode_for_user(param)
        if action_id == ACTION_ID_ASSOCIATE_PHONE_WITH_USER:
            ret_val = self._handle_associate_phone_with_user(param)
        if action_id == ACTION_ID_CREATE_PHONE:
            ret_val = self._handle_create_phone(param)
        if action_id == ACTION_ID_MODIFY_PHONE:
            ret_val = self._handle_modify_phone(param)
        if action_id == ACTION_ID_DELETE_PHONE:
            ret_val = self._handle_delete_phone(param)
        if action_id == ACTION_ID_ACTIVATION_CODE_VIA_SMS:
            ret_val = self._handle_activation_code_via_sms(param)
        if action_id == ACTION_ID_SYNCHRONIZE_USER_FROM_DIRECTORY:
            ret_val = self._handle_synchronize_user_from_directory(param)
        return ret_val


def main():
    import argparse
    import sys

    import pudb

    pudb.set_trace()
    argparser = argparse.ArgumentParser()

    argparser.add_argument('input_test_json', help='Input Test JSON file')
    argparser.add_argument('-u', '--username', help='username', required=False)
    argparser.add_argument('-p', '--password', help='password', required=False)

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password

    if username is not None and password is None:

        # User specified a username but not a password, so ask
        import getpass
        password = getpass.getpass("Password: ")

    if username and password:
        try:
            login_url = DuoConnector._get_phantom_base_url() + '/login'

            print("Accessing the Login page")
            r = requests.get(login_url, verify=False, timeout=DEFAULT_TIMEOUT)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken=' + csrftoken
            headers['Referer'] = login_url

            print("Logging into Platform to get the session id")
            r2 = requests.post(login_url, verify=False, data=data, headers=headers)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print("Unable to get session id from the platform. Error: " + str(e))
            sys.exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = DuoConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    sys.exit(0)


if __name__ == '__main__':
    main()
