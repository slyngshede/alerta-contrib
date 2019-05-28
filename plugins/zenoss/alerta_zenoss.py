import os
import re
import json
import logging
import time
import requests

from alerta.plugins import PluginBase

try:
    from alerta.plugins import app  # alerta >= 5.0
except ImportError:
    from alerta.app import app  # alerta < 5.0
from alerta.plugins import PluginBase


log = logging.getLogger('alerta.plugins')


requests.packages.urllib3.disable_warnings()

ZEN_HOST = os.environ.get('ZENOSS_HOST') or app.config.get('ZENOSS_HOST', None)
ZEN_USER = os.environ.get('ZENOSS_USER') or app.config['ZENOSS_USER']
ZEN_PASSWORD = os.environ.get('ZENOSS_PASSWORD') or app.config['ZENOSS_PASSWORD']
ZEN_EVENT_CLASS_KEY = os.environ.get('ZENOSS_EVENT_CLASS') or app.config['ZENOSS_EVENT_CLASS'] 


# Remap alerta severity levels to Zenoss naming
ZEN_SEVERITY = {'security': 'Info',
                'critical': 'Critical',
                'major': 'Error',
                'minor': 'Warning',
                'warning': 'Warning',
                'indeterminate': 'Info',
                'informational': 'Info',
                'normal': 'Clear',
                'ok': 'Clear',
                'cleared': 'Clear',
                'debug': 'Debug',
                'trace': 'Debug',
                'unknown': 'Info'}

ZEN_INTERNAL_SEVERITY_MAP = {'Clear': 0,
                             'Debug': 1,
                             'Info': 2,
                             'Warning': 3,
                             'Error': 4,
                             'Critical': 5
                            }

ROUTERS = {'MessagingRouter': 'messaging',
           'EventsRouter': 'evconsole',
           'EventClassesRouter': 'Events/evclasses',
           'ProcessRouter': 'process',
           'ServiceRouter': 'service',
           'DeviceRouter': 'device',
           'ManufacturersRouter': 'manufacturers',
           'NetworkRouter': 'network',
           'PropertiesRouter': 'properties',
           'TemplateRouter': 'template',
           'DetailNavRouter': 'detailnav',
           'ReportRouter': 'report',
           'MibRouter': 'mib',
           'TriggersRouter': 'triggers',
           'ZenPackRouter': 'zenpack'}


class Zenoss(object):
    '''A class that represents a connection to a Zenoss server
    '''
    def __init__(self, host, username, password, ssl_verify=True):
        self.__host = host
        self.__session = requests.Session()
        self.__session.auth = (username, password)
        self.__session.verify = ssl_verify
        self.__req_count = 0

    def __router_request(self, router, method, data=None, uri=None):
        '''Internal method to make calls to the Zenoss request router
        '''
        if router not in ROUTERS:
            raise LookupError('Router "' + router + '" not available.')

        req_data = json.dumps([dict(
            action=router,
            method=method,
            data=data,
            type='rpc',
            tid=self.__req_count)])
        log.debug('Making request to router %s with method %s', router, method)
        if not uri:
            uri = '%s/zport/dmd/%s_router' % (self.__host, ROUTERS[router])
        headers = {'Content-type': 'application/json; charset=utf-8'}
        response = self.__session.post(uri, data=req_data, headers=headers)
        self.__req_count += 1

        # The API returns a 200 response code even whe auth is bad.
        # With bad auth, the login page is displayed. Here I search for
        # an element on the login form to determine if auth failed.
        if re.search('name="__ac_name"', response.content.decode("utf-8")):
            log.error('Request failed. Bad username/password.')
            raise PermissionError('Request failed. Bad username/password.')
        if response.status_code == 200:
            return json.loads(response.content.decode("utf-8"))['result']
        else:
            raise Exception("Unable to complete request:\n%s\nHTTP Status: %s" % (
                req_data,
                response.status_code,
            ))

    def find_device(self, device_name):
        '''Find a device by name.

        '''
        log.info('Finding device %s', device_name)
        all_devices = self.get_devices()

        try:
            device = [d for d in all_devices['devices'] if d['name'] == device_name][0]
            # We need to save the has for later operations
            device['hash'] = all_devices['hash']
            log.info('%s found', device_name)
            return device
        except IndexError:
            log.error('Cannot locate device %s', device_name)
            raise Exception('Cannot locate device %s' % device_name)

    def device_uid(self, device):
        '''Helper method to retrieve the device UID for a given device name
        '''
        return self.find_device(device)['uid']

    def get_events(self, device=None, limit=100, component=None,
                   severity=None, event_class=None, start=0,
                   event_state=None, sort='severity', direction='DESC'):
        '''Find current events.
             Returns a list of dicts containing event details. By default
             they are sorted in descending order of severity.  By default,
             severity {5, 4, 3, 2} and state {0, 1} are the only events that
             will appear.

        '''
        if severity is None:
            severity = [5, 4, 3, 2]
        if event_state is None:
            event_state = [0, 1]
        data = dict(start=start, limit=limit, dir=direction, sort=sort)
        data['params'] = dict(severity=severity, eventState=event_state)
        if device is not None:
            data['params']['device'] = device
        if component is not None:
            data['params']['component'] = component
        if event_class is not None:
            data['params']['eventClass'] = event_class
        log.info('Getting events for %s', data)
        return self.__router_request(
            'EventsRouter', 'query', [data])['events']

    def get_event_detail(self, event_id):
        '''Find specific event details

        '''
        data = dict(evid=event_id)
        return self.__router_request('EventsRouter', 'detail', [data])

    def write_log(self, event_id, message):
        '''Write a message to the event's log

        '''
        data = dict(evid=event_id, message=message)
        return self.__router_request('EventsRouter', 'write_log', [data])

    def change_event_state(self, event_id, state):
        '''Change the state of an event.

        '''
        log.info('Changing eventState on %s to %s', event_id, state)
        return self.__router_request('EventsRouter', state, [{'evids': [event_id]}])

    def ack_event(self, event_id):
        '''Helper method to set the event state to acknowledged.

        '''
        return self.change_event_state(event_id, 'acknowledge')

    def close_event(self, event_id):
        '''Helper method to set the event state to closed.

        '''
        return self.change_event_state(event_id, 'close')

    def create_event_on_device(self, device_name, severity, summary,
                               component='', evclasskey='', evclass=''):
        '''Manually create a new event for the device specified.

        '''
        log.info('Creating new event for %s with severity %s', device_name, severity)
        if severity not in ('Critical', 'Error', 'Warning', 'Info', 'Debug', 'Clear'):
            raise Exception('Severity %s is not valid.' % severity)
        data = dict(device=device_name, summary=summary, severity=severity,
                    component=component, evclasskey=evclasskey, evclass=evclass)
        return self.__router_request('EventsRouter', 'add_event', [data])


class ZenossHandler(PluginBase):

    def pre_receive(self, alert, **kwargs):
        return alert
        
    def post_receive(self, alert, **kwargs):
        z = Zenoss(ZEN_HOST, ZEN_USER, ZEN_PASSWORD, False)
        
        # Map Alerta severity to Zenoss terms.
        severity = ZEN_SEVERITY[alert.severity]

        # Device, Severity, Summary, Component, evclasskey, evclass
        status = z.create_event_on_device(alert.resource,
                                         severity, 
                                         alert.text,
                                         alert.service[0],
                                         ZEN_EVENT_CLASS_KEY)

        # If the even was created successfully lookup the Zenoss event
        # and update or insert the correct event id in Alerta.
        if status['success']:
            log.info('Created Zenoss event for alert: %s', alert.id)
            self.update_zenoss_event(z, alert, severity)
        else:
            log.warning('Failed to create Zenoss event for alert: %s',
                        alert.id)
        return alert

    def status_change(self, alert, status, text, **kwargs):
        if 'zenoss_evid' not in alert.attributes:
            return
    
        evid = alert.attributes['zenoss_evid']

        z = Zenoss(ZEN_HOST, ZEN_USER, ZEN_PASSWORD, False)
        if status == 'ack':
            result = z.ack_event(evid)
        elif status == 'closed':
            result = z.close_event(evid)
        return

    def update_zenoss_event(self, z, alert, severity):
        updated = False
        count = 0
        severity_code = ZEN_INTERNAL_SEVERITY_MAP[severity]

        # Zenoss accepts events into an internal queue, meaning
        # that our newly created event may not be available
        # right away. 
        while not updated and count < 3:
            count += 1
            events = z.get_events(alert.resource,
                                 limit=10,
                                 severity=severity_code,
                                 sort='firstTime')

            if not events:
                time.sleep(2)
            
            for event in events:
                if event['eventState'] == 'New' \
                   and event['summary'] == alert.text \
                   and event['component']['text'] == alert.service[0]:
                    alert.attributes.update(zenoss_evid=event['id'])
                    log.info('Zenoss event id: %s mapped to alert: %s',
                             event['id'], alert.id)
                    updated = True

        if not updated:
            log.warning('Failed to create Zenoss mapping for alert: %s',
                        alert.id)


    def take_action(self, alert, action, text, **kwargs):
        raise NotImplementedError
