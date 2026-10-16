from connectors.core.connector import Connector, ConnectorError, get_logger

from .operations import API_ERRORS, _check_health, _client, operations

logger = get_logger('fortinet-fortiaigate')


class FortiAIGate(Connector):
    def execute(self, config, operation, params, **kwargs):
        action = operations.get(operation)
        if action is None:
            raise ValueError('Unknown operation: {0}'.format(operation))
        logger.info('Executing action {0}'.format(operation))
        config = dict(config, _faig_client=_client(config))
        try:
            return action(config, params or {})
        except API_ERRORS as err:
            # A FortiAIGate answer (pyfortiaigate's FaigError is a LookupError or OSError
            # subclass) or a failed connection: show the library's message.
            raise ConnectorError(str(err))

    def check_health(self, config):
        return _check_health(config)
