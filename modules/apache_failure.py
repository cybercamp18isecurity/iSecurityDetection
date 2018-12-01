
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
            self.create_alert(self.alertgen())

    def alertgen(self):
        alert = {
            "@datetime": ElasticSearcher.parseDatetimeToEpoch(str(datetime.now())),
            "id_external": "keywork",
            "id_user": "keyword",
            "type": "keyword",
            "status": 0,
            "criticity": 0,
            "description": "apache is down",
            "events": [],
        }
        return alert
