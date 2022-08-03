""" Copyright start
  Copyright (C) 2008 - 2022 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

from connectors.core.connector import Connector, get_logger, ConnectorError
from connectors.cyops_utilities.builtins import make_cyops_request
from .operations import operations, _check_health, MACRO_LIST

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
        for macro in MACRO_LIST:
            try:
                resp = make_cyops_request(f'/api/wf/api/dynamic-variable/?name={macro}', 'GET')
                if resp['hydra:member']:
                    macro_id = resp['hydra:member'][0]['id']
                    resp = make_cyops_request(f'/api/wf/api/dynamic-variable/{macro_id}/?format=json', 'DELETE')
            except Exception as e:
                logger.error(e)

    def on_deactivate(self, config):
        self.del_micro(config)

    def on_activate(self, config):
        self.del_micro(config)

    def on_add_config(self, config):
        self.del_micro(config)
