# iSecurityDetection

Este repositorio contiene el conjunto de modulos que se encargan de realizar diferentes tipos de deteccion.

Los modulos son invocados por un driver que importa y elimina modulos en tiempo de ejecucion leyendolos de un fichero de configuracion.

Para mantener un alcance manejable, se propone la deteccion de un conjunto limitado de tecnicas. Para la seleccion de la tecnicas de deteccion nos hemos basado en el framework ATT&CK de MITRE, que describe las fases de ejecucion de un ataque. Hemos intentado ajustar las detecciones para que se cubra el ciclo completo de ejecucion de un ataque mediante la deteccion de, por lo menos, un TTP.

![Alt text](doc/images/ATTCK.png?raw=true "Mitre ATT&CK")

### Instalación
## Configurar Elasticsearch
Para configurar las credenciales de Elasticsearch, es necesario crear un archivo `elasticsearch.ini`, siguiendo en ejemplo de `elasticsearch.ini.example`, con el Host, puerto e índice de la instancia.


## Configurar PUSHER
Para configurar el pusher, hacer falta crear un archivo en el root de la carpeta, llamado `pusher.ini`, que contenga las claves del pusher, siguiente el ejemplo de `pusher.ini.example`.
