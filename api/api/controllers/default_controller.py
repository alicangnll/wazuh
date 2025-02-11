# # Copyright (C) 2015, Wazuh Inc.
# # Created by Wazuh, Inc. <info@wazuh.com>.
# # This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import logging
import socket
from datetime import datetime

from aiohttp import web

from api.encoder import dumps, prettify
from api.models.basic_info_model import BasicInfo
from wazuh.core.common import DATE_FORMAT
from wazuh.core.results import WazuhResult
from wazuh.core.security import load_spec

logger = logging.getLogger('wazuh-api')


async def default_info(pretty=False):
    """Get basicinfo

    :param pretty: Show results in human-readable format

    Returns various basic information about the API
    """
    info_data = load_spec()
    data = {
        'title': info_data['info']['title'],
        'api_version': info_data['info']['version'],
        'revision': info_data['info']['x-revision'],
        'license_name': info_data['info']['license']['name'],
        'license_url': info_data['info']['license']['url'],
        'hostname': socket.gethostname(),
        'timestamp': datetime.utcnow().strftime(DATE_FORMAT)
    }
    response = WazuhResult({'data': BasicInfo.from_dict(data)})

    return web.json_response(data=response, status=200, dumps=prettify if pretty else dumps)
