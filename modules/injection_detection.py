from module import Module, ElasticSearcher
from datetime import datetime
from urllib.parse import urlparse
from difflib import SequenceMatcher
import pandas as pd
from urllib.parse import quote_plus


class CustomModule(Module):
    """ Esta clase detecta inyecciones de codigo en parametros de urls
    de manera generica basandose en el conjunto de datos que se le proporciona.
    Para ello, realiza un url encode sobre el conjunto de datos que debe estar
    formado por una lista de payloads de la amenza que se desea detectar, despues
    realiza una comparacion utilizando la metrica ratio de la diferencia entre cada
    uno de los elementos del conjunto de datos y los parametros. Si la similitud es
    mayor del 50% para la media del conjunto de elementos, se considera un ataque.
    Actualmente testeado con:
    - XSS
    - SQLi
    - Path Traversal
    """

    DATASET = "datasets/xssdataset.csv"

    def run(self):
        """Esta funcion localiza logs cada 2 minutos y comprueba las urls."""

        print("[+] Comprobando los logs del servidor...")

        results = self.query_apache_logs(
            "/var/log/apache2/access.log", "now-1m", "now")
        if results:
            for result in results['hits']:
                url = result['_source']['apache2']['access']['referrer']
                print("[+] Parsing url:", url)
                params = self.get_params(url)
                print(params)
                if self.is_injection(params):
                    print("[+] Generando una alerta")
                    self.create_alert(self.alertgen(result['_source']))

    def is_injection(self, params):
        df = pd.read_csv(self.DATASET)
        df['payload'] = df['payload'].apply(quote_plus)
        # Verify similarity
        for p in params:
            similars = [self.similarity(p, pay)
                        for pay in df['payload']]

            try:
                average = sum(similars)/len(similars)
            except:
                average = 0

            print(p, ":", average)

            if average > 0.5:
                return True
        return False

    def get_params(self, url):
        parameters = []
        url = urlparse(url)
        params = url.query.split("&")
        return [p.split("=")[1] for p in params]

    def similarity(self, a, b):
        return SequenceMatcher(None, a, b).ratio()

    def alertgen(self, data=None):
        hostname = data["beat"].get('hostname','')
        alert = {
            "@datetime": ElasticSearcher.parseDatetimeToEpoch(str(datetime.now())),
            "id_external": hostname,
            "type": "intrussion",
            "status": 0,
            "criticity": 0,
            "description": "Possible injection detected",
            "events": [],
        }
        return alert
