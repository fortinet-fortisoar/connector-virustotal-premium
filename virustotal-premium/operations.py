""" Copyright start
  Copyright (C) 2008 - 2023 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

import requests, datetime, time, json, os, base64, re
from os.path import join
from django.conf import settings
from connectors.core.connector import ConnectorError, get_logger
from integrations.crudhub import make_request
from connectors.cyops_utilities.builtins import upload_file_to_cyops
from connectors.cyops_utilities.builtins import download_file_from_cyops
from .constants import *

logger = get_logger('virustotal-premium')


class VirusTotalPremium(object):
    def __init__(self, config, *args, **kwargs):
        self.api_key = config.get('api_key')
        url = config.get('server_url').strip('/')
        if not url.startswith('https://') and not url.startswith('http://'):
            self.url = 'https://{0}/api/v3/'.format(url)
        else:
            self.url = url + '/api/v3/'
        self.verify_ssl = config.get('verify_ssl')

    def make_rest_call(self, url, method, data=None, params=None, json=None, files=None):
        try:
            if 'www.virustotal.com' in url:
                url = url
            else:
                url = self.url + url
            headers = {
                'x-apikey': self.api_key,
                'Content-Type': 'application/json'
            }
            if files:
                del headers['Content-Type']
            logger.debug("Endpoint {0}".format(url))
            response = requests.request(method, url, data=data, params=params, json=json, headers=headers, files=files,
                                        verify=self.verify_ssl)
            logger.debug("response_content {0}:{1}".format(response.status_code, response.content))
            if response.ok or response.status_code == 204:
                logger.info('Successfully got response for url {0}'.format(url))
                if 'json' in str(response.headers):
                    return response.json()
                else:
                    return response.text
            elif response.status_code == 404:
                return response.json()
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


def isValidHash(_len, file_hash):
    if _len in [32, 40, 64]:  # md5/sha1/sha256
        pattern = re.compile(r'[0-9a-fA-F]{%s}' % _len)
        match = re.match(pattern, file_hash)
        if match is not None:
            return True
    return False


def download_file(config, params):
    vtp = VirusTotalPremium(config)
    endpoint = 'files/{0}/download'.format(params.get('id'))
    try:
        file_name = params.get('id')
        response = vtp.make_rest_call(endpoint, 'GET')
        logger.debug("API response: {0}".format(response))
        if response:
            path = os.path.join(settings.TMP_FILE_ROOT, file_name)
            logger.debug("Path: {0}".format(path))
            with open(path, 'wb') as fp:
                fp.write(response.content)
            attach_response = upload_file_to_cyops(file_path=file_name, filename=file_name,
                                                   name=file_name, create_attachment=True)
            return attach_response
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
        if response.get('data'):
            return response.get('data')
        else:
            return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def get_zip_file_url(config, params):
    vtp = VirusTotalPremium(config)
    endpoint = 'intelligence/zip_files/{0}/download_url'.format(params.get('id'))
    try:
        response = vtp.make_rest_call(endpoint, 'GET')
        if response.get('data'):
            return {"url": response.get('data')}
        else:
            return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def download_zip_file(config, params):
    vtp = VirusTotalPremium(config)
    endpoint = 'intelligence/zip_files/{0}/download'.format(params.get('id'))
    try:
        file_name = str(params.get('id')) + '.zip'
        response = vtp.make_rest_call(endpoint, 'GET')
        logger.debug("API response: {0}".format(response))
        if response:
            if response.get('error'):
                return response
            path = os.path.join(settings.TMP_FILE_ROOT, file_name)
            logger.debug("Path: {0}".format(path))
            with open(path, 'wb') as fp:
                fp.write(response.content)
            attach_response = upload_file_to_cyops(file_path=file_name, filename=file_name,
                                                   name=file_name, create_attachment=True)
            return attach_response
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
    if notifications:
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
                    "notification_email": notifications
                }
            }
        }
        payload = check_payload(payload)
        response = vtp.make_rest_call(endpoint, 'POST', data=json.dumps(payload))
        return response.get('data')
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
        if response.get('data'):
            return response.get('data')
        else:
            return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def update_livehunt_ruleset(config, params):
    vtp = VirusTotalPremium(config)
    endpoint = 'intelligence/hunting_rulesets/{0}'.format(params.get('id'))
    notifications = params.get('notification_emails')
    if notifications:
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
                    "notification_email": notifications
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
    response = vtp.make_rest_call(endpoint, 'DELETE')
    if response:
        return response
    else:
        return {"message": "Successfully deleted livehunt ruleset {0}".format(params.get('id'))}


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
        if response.get('data'):
            return response.get('data')
        else:
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


def convert_datetime_to_epoch(date_time):
    d1 = time.strptime(date_time, "%Y-%m-%dT%H:%M:%S.%fZ")
    epoch = datetime.datetime.fromtimestamp(time.mktime(d1)).strftime('%s')
    return epoch


def create_retrohunt_job(config, params):
    vtp = VirusTotalPremium(config)
    endpoint = 'intelligence/retrohunt_jobs'
    start_time = params.get('start_time')
    if 'T' in start_time:
        start_time = int(convert_datetime_to_epoch(start_time))
    end_time = params.get('end_time')
    if 'T' in end_time:
        end_time = int(convert_datetime_to_epoch(end_time))
    corpus = params.get('corpus')
    try:
        payload = {
            "data": {
                "type": "retrohunt_job",
                "attributes": {
                    "rules": params.get('rules'),
                    "notification_email": params.get('notification_emails'),
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
        return response.get('data')
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
        if response:
            return response
        else:
            return {"message": "Successfully deleted retrohunt job {0}".format(params.get('id'))}
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


def create_relationship(params, relationship_type):
    relationships_list = []
    relationships = params.get('relationships')
    if relationship_type == 'IP':
        relationships_list = [IP_RELATIONSHIP_VALUE.get(r) for r in relationships]
    elif relationship_type == 'DOMAIN':
        relationships_list = [DOMAIN_RELATIONSHIP_VALUE.get(r) for r in relationships]
    elif relationship_type == 'URL':
        relationships_list = [URL_RELATIONSHIP_VALUE.get(r) for r in relationships]
    elif relationship_type == 'FILE':
        relationships_list = [FILE_RELATIONSHIP_VALUE.get(r) for r in relationships]
    return relationships_list


def create_output_schema(params, relationship_type):
    relationships_list = create_relationship(params, relationship_type)
    relationship = relationships_list if relationships_list else []
    output_object = {'relationships': {}}
    for relation_name in relationship:
        output_object['relationships'].update({relation_name: TEMPLATE})
    return output_object


def build_output_schema_ip(config, params):
    output_object = create_output_schema(params, 'IP')
    output_object.update(IP_TEMPLATE)
    return output_object


def build_output_schema_domain(config, params):
    output_object = create_output_schema(params, 'DOMAIN')
    output_object.update(DOMAIN_TEMPLATE)
    return output_object


def build_output_schema_url(config, params):
    output_object = create_output_schema(params, 'URL')
    output_object.update(URL_TEMPLATE)
    return output_object


def build_output_schema_file(config, params):
    output_object = create_output_schema(params, 'FILE')
    output_object.update(FILE_TEMPLATE)
    return output_object


def get_output_schema_ip(config, params):
    return build_output_schema_ip(config, params)


def get_output_schema_domain(config, params):
    return build_output_schema_domain(config, params)


def get_output_schema_url(config, params):
    return build_output_schema_url(config, params)


def get_output_schema_file(config, params):
    return build_output_schema_file(config, params)


def get_ip_reputation(config, params):
    try:
        vtp = VirusTotalPremium(config)
        relationships_list = []
        relationships = params.get('relationships')
        ip = params.get('ip')
        if relationships:
            for r in relationships:
                relationships_list.append(IP_RELATIONSHIP_VALUE.get(r))
            relationships_string = ",".join(relationships_list)
            endpoint = 'ip_addresses/{0}?relationships={1}'.format(ip, relationships_string)
        else:
            endpoint = 'ip_addresses/{0}'.format(ip)
        response = vtp.make_rest_call(endpoint, 'GET')
        if response.get('error'):
            return response.get('error')
        try:
            whois = response['data']['attributes']['whois']
            response['data']['attributes']['whois'] = {'raw': [], 'data': whois}
        except:
            response['data']['attributes']['whois'] = {'raw': [], 'data': 'No match found for {0}'.format(ip)}
        response['data']['links']['self'] = 'https://www.virustotal.com/gui/ip-address/{0}'.format(ip)
        return response.get('data')
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def get_domain_reputation(config, params):
    try:
        vtp = VirusTotalPremium(config)
        relationships_list = []
        domain = params.get('domain')
        relationships = params.get('relationships')
        if relationships:
            for r in relationships:
                relationships_list.append(DOMAIN_RELATIONSHIP_VALUE.get(r))
            relationships_string = ",".join(relationships_list)
            endpoint = 'domains/{0}?relationships={1}'.format(domain, relationships_string)
        else:
            endpoint = 'domains/{0}'.format(domain)
        response = vtp.make_rest_call(endpoint, 'GET')
        if response.get('error'):
            return response.get('error')
        try:
            whois = response['data']['attributes']['whois']
            response['data']['attributes']['whois'] = {'raw': [], 'data': whois}
        except:
            response['data']['attributes']['whois'] = {'raw': [], 'data': 'No match found for {0}'.format(domain)}
        response['data']['links']['self'] = 'https://www.virustotal.com/gui/domain/{0}'.format(domain)
        return response.get('data')
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def get_url_reputation(config, params):
    try:
        vtp = VirusTotalPremium(config)
        relationships_list = []
        url = params.get('url')
        relationships = params.get('relationships')
        if relationships:
            for r in relationships:
                relationships_list.append(URL_RELATIONSHIP_VALUE.get(r))
            relationships_string = ",".join(relationships_list)
            endpoint = 'urls/{0}?relationships={1}'.format(
                base64.urlsafe_b64encode(url.encode()).decode().strip("="),
                relationships_string)
        else:
            endpoint = 'urls/{0}'.format(base64.urlsafe_b64encode(url.encode()).decode().strip("="))
        response = vtp.make_rest_call(endpoint, 'GET')
        if response.get('error'):
            response['error']['message'] = "URL '{0}' not found".format(url)
            return response.get('error')
        if response:
            id = response['data']['id']
            response['data']['links']['self'] = 'https://www.virustotal.com/gui/url/{0}/detection'.format(id)
            return response.get('data')
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def get_file_reputation(config, params):
    try:
        vtp = VirusTotalPremium(config)
        relationships_list = []
        relationships = params.get('relationships')
        file_hash = params.get('file_hash')
        if not isValidHash(len(file_hash), file_hash):
            msg = 'Invalid hash provided'
            return {'error': msg}
        if relationships:
            for r in relationships:
                relationships_list.append(FILE_RELATIONSHIP_VALUE.get(r))
            relationships_string = ",".join(relationships_list)
            endpoint = 'files/{0}?relationships={1}'.format(file_hash, relationships_string)
        else:
            endpoint = 'files/{0}'.format(file_hash)
        response = vtp.make_rest_call(endpoint, 'GET')
        if response.get('error'):
            return response.get('error')
        if response:
            id = response['data']['id']
            response['data']['links']['self'] = 'https://www.virustotal.com/gui/file/{0}/detection'.format(id)
            return response.get('data')
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def analysis_file(config, params):
    try:
        vtp = VirusTotalPremium(config)
        analysis_id = params.get('analysis_id')
        endpoint = 'analyses/{0}'.format(analysis_id)
        response = vtp.make_rest_call(endpoint, 'GET')
        if response.get('error'):
            return response.get('error')
        if response:
            try:
                id = response['meta']['url_info']['id']
                response['data']['links']['self'] = 'https://www.virustotal.com/gui/url/{0}/detection'.format(id)
                return response
            except:
                sha256 = response['meta']['file_info']['sha256']
                response['data']['links']['self'] = 'https://www.virustotal.com/gui/file/{0}/detection'.format(
                    sha256)
                return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def handle_params(params):
    value = str(params.get('value'))
    input_type = params.get('input')
    try:
        if isinstance(value, bytes):
            value = value.decode('utf-8')
        if input_type == 'Attachment ID':
            if not value.startswith('/api/3/attachments/'):
                value = '/api/3/attachments/{0}'.format(value)
            attachment_data = make_request(value, 'GET')
            file_iri = attachment_data['file']['@id']
            file_name = attachment_data['file']['filename']
            logger.info('file id = {0}, file_name = {1}'.format(file_iri, file_name))
            return file_iri
        elif input_type == 'File IRI':
            if value.startswith('/api/3/files/'):
                return value
            else:
                raise ConnectorError('Invalid File IRI {0}'.format(value))
    except Exception as err:
        logger.info('handle_params(): Exception occurred {0}'.format(err))
        raise ConnectorError('Requested resource could not be found with input type "{0}" and value "{1}"'.format
                             (input_type, value.replace('/api/3/attachments/', '')))


def submit_file(config, params):
    try:
        vtp = VirusTotalPremium(config)
        file_iri = handle_params(params)
        endpoint = 'files'
        file_path = join('/tmp', download_file_from_cyops(file_iri)['cyops_file_path'])
        logger.info(file_path)
        with open(file_path, 'rb') as attachment:
            file_data = attachment.read()
        if file_data:
            files = {'file': file_data}
            res = vtp.make_rest_call(endpoint, 'POST', files=files)
            if res.get('error'):
                return res.get('error')
            return res.get('data')
        raise ConnectorError('File size too large, submit file up to 32 MB')
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def get_widget_rendering_url(config, params):
    try:
        vtp = VirusTotalPremium(config)
        endpoint = 'widget/url'
        response = vtp.make_rest_call(endpoint, 'GET', params=params)
        if response.get('error'):
            return response.get('error')
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def get_widget_html_content(config, params):
    try:
        vtp = VirusTotalPremium(config)
        token = params.get('token')
        if '/' in token:
            token = token.split("/")[-1]
        endpoint = 'https://www.virustotal.com/ui/widget/html/{0}'.format(token)
        response = vtp.make_rest_call(endpoint, 'GET')
        if response.get('error'):
            return response.get('error')
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
    'get_ip_reputation': get_ip_reputation,
    'get_domain_reputation': get_domain_reputation,
    'get_url_reputation': get_url_reputation,
    'get_file_reputation': get_file_reputation,
    'submit_sample': submit_file,
    'analysis_file': analysis_file,
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
    'get_retrohunt_job_matching_files': get_retrohunt_job_matching_files,
    'get_output_schema_ip': get_output_schema_ip,
    'get_output_schema_domain': get_output_schema_domain,
    'get_output_schema_url': get_output_schema_url,
    'get_output_schema_file': get_output_schema_file,
    'get_widget_rendering_url': get_widget_rendering_url,
    'get_widget_html_content': get_widget_html_content
}
