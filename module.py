from elasticsearch_sdk.elasticsearcher import ElasticSearcher
from configparser import ConfigParser
import os


class Module:

    def __init__(self):
        self.elk_controler = self.init_elastic()

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

    def create_alert(self, data):
        self.elk_controler.create_document(
            "", data, index="isecurity_datamodel-alerts")

    def init_elastic(self):
        dir_path = os.path.dirname(os.path.abspath(__file__))
        config_path = os.path.join(dir_path, "elasticsearch.ini")

        parser = ConfigParser()
        parser.read(config_path)

        host = parser.get('elasticsearch', 'host')
        port = parser.get('elasticsearch', 'port')
        index = parser.get('elasticsearch', 'index')

        return ElasticSearcher(host, port, index)
