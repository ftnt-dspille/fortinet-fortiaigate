from connectors.core.connector import Connector, ConnectorError, get_logger

from .operations import API_ERRORS, _check_health, _client, friendly_error, operations

logger = get_logger('fortinet-fortiaigate')


class FortiAIGate(Connector):
    def execute(self, config, operation, params, **kwargs):
        action = operations.get(operation)
        if action is None:
            raise ConnectorError('Unknown operation: {0}'.format(operation))
        logger.info('Executing action {0}'.format(operation))
        config = dict(config, _faig_client=_client(config))
        try:
            return action(config, params or {})
        except ConnectorError:
            raise
        except (ValueError, *API_ERRORS) as err:
            # A FortiAIGate answer, a failed connection, or input the library refused
            # (a ValueError, e.g. a login in several workspaces with none chosen).
            raise ConnectorError(friendly_error(err, config.get('username')))

    def check_health(self, config):
        return _check_health(config)
