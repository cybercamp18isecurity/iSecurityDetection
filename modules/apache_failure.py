
from module import Module, ElasticSearcher
from datetime import datetime


class CustomModule(Module):

    def run(self):
        """Esta funcion localiza logs cada 2 minutos y comprueba si esta caido
        el servidor de aplicacion apache2"""

        print("[+] Comprobando los logs del servidor...")

        results = self.query_apache_logs(
            "/var/log/apache2/error.log", "now-2m", "now")
        if results:
            print("[+] Generando una alerta")
            alert = self.alertgen(results)
            self.create_alert(alert)

    def alertgen(self, data=None):
        hostname = data['hits'][0]['_source']['beat'].get('hostname', '')
        alert = {
            "@datetime": ElasticSearcher.parseDatetimeToEpoch(str(datetime.now())),
            "id_external": hostname,
            "type": "disponibility",
            "status": 0,
            "criticity": 0,
            "description": "Apache is down.",
            "events": [],
        }
        return alert
