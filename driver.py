# File from isecurity project
# Copyright (C) 2018 Santiago Hernandez Ramos <shramos@protonmail.com>
# For more information about the project: https://github.com/cybercamp18isecurity
import logging
from lxml import etree
import time
import importlib

logging.basicConfig(filename='driver.log', level=logging.DEBUG)


def modules_management(modules, xml_modules):
    """Adds and deletes modules to the driver."""

    xml_module_names = []

    for xml_module in xml_modules:
        module = xml_module.getchildren()
        mod_file = module[0].text
        mod_time = int(module[1].text)
        xml_module_names.append(mod_file)

        # Importing the new module to the driver
        if mod_file not in modules.keys():
            logging.info("Importing module %s" % mod_file)
            modules[mod_file] = {"exec_time": mod_time,
                                 "rest_time": mod_time}

    # Deleting modules removed from xml file
    for mod_name in list(modules):
        if mod_name not in xml_module_names:
            logging.info("Deleting module %s" % mod_name)
            modules.pop(mod_name)

    return modules


def get_import_path(path):
    path = path.split('/')
    path = path[path.index('modules'):]
    return ".".join(path)[:-3]


def instantiate_module(module_path):
    module_path = get_import_path(module_path)
    try:
        logging.info('Loading module...')
        m = importlib.import_module(module_path)
        return m.CustomModule()
    except ImportError as error:
        logging.exception('Error importing the module %s' % module_path)
        return None


def main():
    """Function responsible for running the modules based on configuration time"""

    modules = {}

    while True:
        time.sleep(1)
        logging.info("Reading new modules")
        try:
            tree = etree.parse("modules.conf")
        except:
            print("ERROR: malformed xml")
            logging.error("Malformed xml")
            continue

        root = tree.getroot()
        modules = modules_management(modules, root.getchildren())
        print(modules)

        # Execute the modules based on time
        for key in list(modules):
            modules[key]["rest_time"] -= 1
            if modules[key]["rest_time"] == 0:
                modules[key]["rest_time"] = modules[key]["exec_time"]
                custom_module = instantiate_module(key)
                try:
                    if custom_module:
                        custom_module.run()
                except:
                    logging.exception("failed running %s module" % key)


if __name__ == "__main__":
    logging.info("Attack modules driver started!")
    logging.info("Logging activated!")
    main()
