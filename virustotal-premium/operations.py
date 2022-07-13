""" Copyright start
  Copyright (C) 2008 - 2022 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

import requests, datetime, time, json
from connectors.core.connector import ConnectorError, get_logger

logger = get_logger('virustotal-premium')

errors = {
    '401': 'Unauthorized, API key invalid',
    '405': 'Method Not Allowed, Method other than POST used',
    '413': 'Request Entity Too Large, Sample file size over max limit',
    '415': 'Unsupported Media Type',
    '418': 'Unsupported File Type Sample, file type is not supported',
    '419': 'Request quota exceeded',
    '420': 'Insufficient arguments',
    '421': 'Invalid arguments',
    '500': 'Internal error',
    '502': 'Bad Gateway',
    '513': 'File upload failed'
}


class VirusTotalPremium(object):
    def __init__(self, config, *args, **kwargs):
        self.api_key = config.get('api_key')
        url = config.get('server_url').strip('/')
        if not url.startswith('https://') and not url.startswith('http://'):
            self.url = 'https://{0}/api/v3/'.format(url)
        else:
            self.url = url + '/api/v3/'
        self.verify_ssl = config.get('verify_ssl')

    def make_rest_call(self, url, method, data=None, params=None, json=None):
        try:
            url = self.url + url
            headers = {
                'x-apikey': self.api_key
            }
            logger.debug("Endpoint {0}".format(url))
            response = requests.request(method, url, data=data, params=params, json=json, headers=headers,
                                        verify=self.verify_ssl)
            logger.debug("response_content {0}:{1}".format(response.status_code, response.content))
            if response.ok or response.status_code == 204:
                logger.info('Successfully got response for url {0}'.format(url))
                if 'json' in str(response.headers):
                    return response.json()
                else:
                    return response
            elif response.status_code == 404:
                return {"message": "Not Found"}
            else:
                logger.error("{0}".format(errors.get(response.status_code, '')))
                raise ConnectorError("{0}".format(errors.get(response.status_code, response.text)))
        except requests.exceptions.SSLError:
            raise ConnectorError('SSL certificate validation failed')
        except requests.exceptions.ConnectTimeout:
            raise ConnectorError('The request timed out while trying to connect to the server')
        except requests.exceptions.ReadTimeout:
            raise ConnectorError(
                'The server did not send any data in the allotted amount of time')
        except requests.exceptions.ConnectionError:
            raise ConnectorError('Invalid endpoint or credentials')
        except Exception as err:
            raise ConnectorError(str(err))


def check_payload(payload):
    updated_payload = {}
    for key, value in payload.items():
        if isinstance(value, dict):
            nested = check_payload(value)
            if len(nested.keys()) > 0:
                updated_payload[key] = nested
        elif value:
            updated_payload[key] = value
    return updated_payload


def download_file(config, params):
    vtp = VirusTotalPremium(config)
    endpoint = 'files/{0}/download'.format(params.get('id'))
    try:
        response = vtp.make_rest_call(endpoint, 'GET')
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def create_zip_file(config, params):
    vtp = VirusTotalPremium(config)
    endpoint = 'intelligence/zip_files'
    hashes = params.get('hashes')
    if not isinstance(hashes, list):
        hashes = hashes.split(",")
    try:
        payload = {
            "data": {
                "password": params.get('password'),
                "hashes": hashes
            }
        }
        payload = check_payload(payload)
        response = vtp.make_rest_call(endpoint, 'POST', data=json.dumps(payload))
        return response.get('data')
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def get_zip_file_status(config, params):
    vtp = VirusTotalPremium(config)
    endpoint = 'intelligence/zip_files/{0}'.format(params.get('id'))
    try:
        response = vtp.make_rest_call(endpoint, 'GET')
        return response.get('data')
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def get_zip_file_url(config, params):
    vtp = VirusTotalPremium(config)
    endpoint = 'intelligence/zip_files/{0}/download_url'.format(params.get('id'))
    try:
        response = vtp.make_rest_call(endpoint, 'GET')
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def download_zip_file(config, params):
    vtp = VirusTotalPremium(config)
    endpoint = 'intelligence/zip_files/{0}/download'.format(params.get('id'))
    try:
        response = vtp.make_rest_call(endpoint, 'GET')
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def get_pcap_file_behaviour(config, params):
    vtp = VirusTotalPremium(config)
    endpoint = 'file_behaviours/{0}/pcap'.format(params.get('sandbox_id'))
    try:
        response = vtp.make_rest_call(endpoint, 'GET')
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def search_intelligence(config, params):
    vtp = VirusTotalPremium(config)
    endpoint = 'intelligence/search'
    try:
        payload = {
            "query": params.get('query'),
            "order": params.get('order'),
            "limit": params.get('limit'),
            "descriptors_only": params.get('descriptors_only'),
            "cursor": params.get('cursor')
        }
        payload = check_payload(payload)
        response = vtp.make_rest_call(endpoint, 'GET', params=payload)
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def create_livehunt_ruleset(config, params):
    vtp = VirusTotalPremium(config)
    endpoint = 'intelligence/hunting_rulesets'
    notifications = params.get('notification_emails')
    if not isinstance(notifications, list):
        notifications = notifications.split(",")
    try:
        payload = {
            "data": {
                "type": "hunting_ruleset",
                "attributes": {
                    "name": params.get('name'),
                    "enabled": params.get('enabled'),
                    "limit": params.get('limit'),
                    "rules": params.get('rules'),
                    "notification_emails": notifications
                }
            }
        }
        payload = check_payload(payload)
        response = vtp.make_rest_call(endpoint, 'POST', data=json.dumps(payload))
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def get_livehunt_rulesets_list(config, params):
    vtp = VirusTotalPremium(config)
    endpoint = 'intelligence/hunting_rulesets'
    try:
        payload = {
            "limit": params.get('limit'),
            "filter": params.get('filter'),
            "order": params.get('order'),
            "cursor": params.get('cursor')
        }
        payload = check_payload(payload)
        response = vtp.make_rest_call(endpoint, 'GET', params=payload)
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def get_livehunt_ruleset_details(config, params):
    vtp = VirusTotalPremium(config)
    endpoint = 'intelligence/hunting_rulesets/{0}'.format(params.get('id'))
    try:
        response = vtp.make_rest_call(endpoint, 'GET')
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def update_livehunt_ruleset(config, params):
    vtp = VirusTotalPremium(config)
    endpoint = 'intelligence/hunting_rulesets/{0}'.format(params.get('id'))
    notifications = params.get('notification_emails')
    if not isinstance(notifications, list):
        notifications = notifications.split(",")
    try:
        payload = {
            "data": {
                "type": "hunting_ruleset",
                "attributes": {
                    "name": params.get('name'),
                    "enabled": params.get('enabled'),
                    "limit": params.get('limit'),
                    "rules": params.get('rules'),
                    "notification_emails": notifications
                }
            }
        }
        payload = check_payload(payload)
        response = vtp.make_rest_call(endpoint, 'PATCH', data=json.dumps(payload))
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def delete_livehunt_ruleset(config, params):
    vtp = VirusTotalPremium(config)
    endpoint = 'intelligence/hunting_rulesets/{0}'.format(params.get('id'))
    try:
        response = vtp.make_rest_call(endpoint, 'DELETE')
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def get_livehunt_notifications_list(config, params):
    vtp = VirusTotalPremium(config)
    endpoint = 'intelligence/hunting_notifications'
    try:
        payload = {
            "limit": params.get('limit'),
            "filter": params.get('filter'),
            "order": params.get('order'),
            "cursor": params.get('cursor'),
            "count_limit": params.get('count_limit')
        }
        payload = check_payload(payload)
        response = vtp.make_rest_call(endpoint, 'GET', params=payload)
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def get_livehunt_notifications_files_list(config, params):
    vtp = VirusTotalPremium(config)
    endpoint = 'intelligence/hunting_notification_files'
    try:
        payload = {
            "limit": params.get('limit'),
            "filter": params.get('filter'),
            "cursor": params.get('cursor'),
            "count_limit": params.get('count_limit')
        }
        payload = check_payload(payload)
        response = vtp.make_rest_call(endpoint, 'GET', params=payload)
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def get_livehunt_notifications_details(config, params):
    vtp = VirusTotalPremium(config)
    endpoint = 'intelligence/hunting_notifications/{0}'.format(params.get('id'))
    try:
        response = vtp.make_rest_call(endpoint, 'GET')
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def get_livehunt_rule_files_list(config, params):
    vtp = VirusTotalPremium(config)
    endpoint = 'intelligence/hunting_rulesets/{0}/relationships/hunting_notification_files'.format(params.get('id'))
    try:
        payload = {
            "limit": params.get('limit'),
            "cursor": params.get('cursor')
        }
        payload = check_payload(payload)
        response = vtp.make_rest_call(endpoint, 'GET', params=payload)
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def convert_datetime_to_epoch(self, date_time):
    d1 = time.strptime(date_time, "%Y-%m-%dT%H:%M:%S.%fZ")
    epoch = datetime.datetime.fromtimestamp(time.mktime(d1)).strftime('%s')
    return epoch


def create_retrohunt_job(config, params):
    vtp = VirusTotalPremium(config)
    endpoint = 'intelligence/retrohunt_jobs'
    start_time = params.get('start_time')
    if 'T' in start_time:
        start_time = convert_datetime_to_epoch(start_time)
    end_time = params.get('end_time')
    if 'T' in end_time:
        end_time = convert_datetime_to_epoch(end_time)
    corpus = params.get('corpus')
    notifications = params.get('notification_emails')
    if not isinstance(notifications, list):
        notifications = notifications.split(",")
    try:
        payload = {
            "data": {
                "type": "retrohunt_job",
                "attributes": {
                    "rules": params.get('rules'),
                    "notification_emails": notifications,
                    "corpus": corpus.lower() if corpus else '',
                    "time_range": {
                        "start": start_time,
                        "end": end_time
                    }
                }
            }
        }
        payload = check_payload(payload)
        response = vtp.make_rest_call(endpoint, 'POST', data=json.dumps(payload))
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def abort_retrohunt_job(config, params):
    vtp = VirusTotalPremium(config)
    endpoint = 'intelligence/retrohunt_jobs/{0}/abort'.format(params.get('id'))
    try:
        response = vtp.make_rest_call(endpoint, 'POST')
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def get_retrohunt_jobs_list(config, params):
    vtp = VirusTotalPremium(config)
    endpoint = 'intelligence/retrohunt_jobs'
    try:
        payload = {
            "limit": params.get('limit'),
            "filter": params.get('filter'),
            "cursor": params.get('cursor')
        }
        payload = check_payload(payload)
        response = vtp.make_rest_call(endpoint, 'GET', params=payload)
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def get_retrohunt_job_details(config, params):
    vtp = VirusTotalPremium(config)
    endpoint = 'intelligence/retrohunt_jobs/{0}'.format(params.get('id'))
    try:
        response = vtp.make_rest_call(endpoint, 'GET')
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def delete_retrohunt_job(config, params):
    vtp = VirusTotalPremium(config)
    endpoint = 'intelligence/retrohunt_jobs/{0}'.format(params.get('id'))
    try:
        response = vtp.make_rest_call(endpoint, 'DELETE')
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def get_retrohunt_job_matching_files(config, params):
    vtp = VirusTotalPremium(config)
    endpoint = 'intelligence/retrohunt_jobs/{0}/matching_files'.format(params.get('id'))
    try:
        payload = {
            "limit": params.get('limit'),
            "cursor": params.get('cursor')
        }
        payload = check_payload(payload)
        response = vtp.make_rest_call(endpoint, 'GET', params=payload)
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def _check_health(config):
    try:
        vtp = VirusTotalPremium(config)
        endpoint = "users/{0}".format(config.get('api_key'))
        response = vtp.make_rest_call(endpoint, 'GET')
        if response:
            return True
    except Exception as err:
        raise ConnectorError("{0}".format(str(err)))


operations = {
    'download_file': download_file,
    'create_zip_file': create_zip_file,
    'get_zip_file_status': get_zip_file_status,
    'get_zip_file_url': get_zip_file_url,
    'download_zip_file': download_zip_file,
    'get_pcap_file_behaviour': get_pcap_file_behaviour,
    'search_intelligence': search_intelligence,
    'get_livehunt_rulesets_list': get_livehunt_rulesets_list,
    'get_livehunt_ruleset_details': get_livehunt_ruleset_details,
    'create_livehunt_ruleset': create_livehunt_ruleset,
    'update_livehunt_ruleset': update_livehunt_ruleset,
    'delete_livehunt_ruleset': delete_livehunt_ruleset,
    'get_livehunt_notifications_list': get_livehunt_notifications_list,
    'get_livehunt_notifications_files_list': get_livehunt_notifications_files_list,
    'get_livehunt_notifications_details': get_livehunt_notifications_details,
    'get_livehunt_rule_files_list': get_livehunt_rule_files_list,
    'create_retrohunt_job': create_retrohunt_job,
    'get_retrohunt_jobs_list': get_retrohunt_jobs_list,
    'get_retrohunt_job_details': get_retrohunt_job_details,
    'abort_retrohunt_job': abort_retrohunt_job,
    'delete_retrohunt_job': delete_retrohunt_job,
    'get_retrohunt_job_matching_files': get_retrohunt_job_matching_files
}
