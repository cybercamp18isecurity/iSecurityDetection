
from module import Module, ElasticSearcher
from datetime import datetime


class CustomModule(Module):

    EVENTS = [40962, 53504, 40961, 4672, 4624, 400, 600]

    def run(self):
        """Esta funcion localiza logs cada 2 minutos y comprueba si esta caido."""

        print("[+] Comprobando los logs del servidor...")

        results = self.query_windows_events("now-15m", "now")
        if results:
            eventids = [result['_source']['osquery']['result']['columns']['eventid']
                        for result in results['hits']]
            print(eventids)

            for event in self.EVENTS:
                if event not in eventids:
                    return

            print("[+] Posible UAC BYPASS detectado")
            print("[+] Generando una alerta")
            self.create_alert(self.alertgen())

    def alertgen(self):
        alert = {
            "@datetime": ElasticSearcher.parseDatetimeToEpoch(str(datetime.now())),
            "id_external": "keywork",
            "id_user": "keyword",
            "type": "keyword",
            "status": 0,
            "criticity": 0,
            "description": "UAC Bypass detected",
            "events": [],
        }
        return alert
