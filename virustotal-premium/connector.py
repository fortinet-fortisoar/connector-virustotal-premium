""" Copyright start
  Copyright (C) 2008 - 2023 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

from connectors.core.connector import Connector, get_logger, ConnectorError
from integrations.crudhub import make_request
from django.conf import settings
from .operations import operations, _check_health
from .constants import MACRO_LIST

logger = get_logger("virustotal-premium")


class VirusTotalPremium(Connector):
    def execute(self, config, operation, params, **kwargs):
        logger.debug("Invoking {0} Operation".format(operation))
        try:
            action = operations.get(operation)
            logger.info('Executing action {0}'.format)
            return action(config, params)
        except Exception as Err:
            logger.exception("Exception in execute function: {0} ".format(str(Err)))
            raise ConnectorError(str(Err))

    def check_health(self, config):
        _check_health(config)

    def del_micro(self, config):
        if not settings.LW_AGENT:
            for macro in MACRO_LIST:
                try:
                    resp = make_request(f'/api/wf/api/dynamic-variable/?name={macro}', 'GET')
                    if resp['hydra:member']:
                        logger.info("resetting global variable '%s'" % macro)
                        macro_id = resp['hydra:member'][0]['id']
                        resp = make_request(f'/api/wf/api/dynamic-variable/{macro_id}/?format=json', 'DELETE')
                except Exception as e:
                    logger.error(e)

    def on_deactivate(self, config):
        self.del_micro(config)

    def on_activate(self, config):
        self.del_micro(config)

    def on_add_config(self, config, active):
        self.del_micro(config)

    def on_delete_config(self, config):
        self.del_micro(config)
