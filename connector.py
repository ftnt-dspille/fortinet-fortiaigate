from connectors.core.connector import Connector, get_logger

from .operations import operations, _check_health, resolve_names, _client

logger = get_logger('fortinet-fortiaigate')


class FortiAIGate(Connector):
    def execute(self, config, operation, params, **kwargs):
        action = operations.get(operation)
        if action is None:
            raise ValueError('Unknown operation: {0}'.format(operation))
        logger.info('Executing action {0}'.format(action))
        return action(config, resolve_names(_client(config), params))

    def check_health(self, config):
        return _check_health(config)
