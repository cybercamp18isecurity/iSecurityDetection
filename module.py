from elasticsearch_sdk.elasticsearcher import ElasticSearcher
from pusher_push_notifications import PushNotifications
from configparser import ConfigParser
import os
import logging



class Module:

    def __init__(self):
        self.elk_controler = self.init_elastic()
        self.init_pusher()
        self.logger = logging.getLogger(__name__)

    def push_notification(self, alert):
        description = alert.get('description')
        type_alert = alert.get("type")
        hostname = alert.get("id_external")
        body = "El dispositivo {} ha tenido el siguiente incidente: {}".format(
            hostname, description
        )
        self.logger.info("- Enviado push")
        response = self.pusher.publish(
            interests=['hello'],
            publish_body={
                'fcm': {
                    'notification': {
                        'title': description,
                        'body': body,
                    },
                },
            },
        )
        self.logger.info("- Push enviado")

        return response


    def query_apache_logs(self, source, time_gte, time_lt):
        query = {
            "query": {
                "bool": {
                    "must": [
                        {
                            "term": {
                                "source": source
                            }
                        },
                        {
                            "range": {
                                "@timestamp": {
                                    "gte": time_gte,
                                    "lt": time_lt
                                }
                            }
                        }
                    ]
                }
            }
        }

        return self.elk_controler.make_query(query)

    def query_windows_events(self, time_gte, time_lt):
        query = {
            "query": {
                "bool": {
                    "must": [
                        {
                            "term": {
                                "osquery.result.name": "pack_windows-attacks-isecurity_windows_events"
                            }
                        },
                        {
                            "range": {
                                "@timestamp": {
                                    "gte": time_gte,
                                    "lt": time_lt
                                }
                            }
                        }
                    ]
                }
            }
        }

        return self.elk_controler.make_query(query)

    def create_alert(self, data):
        self.elk_controler.create_document(
            "", data, index="isecurity_datamodel-alerts")
        self.push_notification(data)

    def init_elastic(self):
        dir_path = os.path.dirname(os.path.abspath(__file__))
        config_path = os.path.join(dir_path, "elasticsearch.ini")

        parser = ConfigParser()
        parser.read(config_path)

        host = parser.get('elasticsearch', 'host')
        port = parser.get('elasticsearch', 'port')
        index = parser.get('elasticsearch', 'index')

        return ElasticSearcher(host, port, index)

    def init_pusher(self):
        dir_path = os.path.dirname(os.path.abspath(__file__))
        config_path = os.path.join(dir_path, "pusher.ini")

        parser = ConfigParser()
        parser.read(config_path)

        instance_id = parser.get('pusher', 'instance_id')
        secret_key = parser.get('pusher', 'secret_key')

        self.pusher = PushNotifications(
            instance_id=instance_id,
            secret_key=secret_key,
        )
