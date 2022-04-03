import os
from configparser import ConfigParser
from pathlib import Path


class Configurator(object):

    _cfg = None

    DEFAULT_DATA_DIRECTORY_NAME = '.wpc'
    DEFAULT_CONFIG_FILE_NAME = 'config.ini'

    SEC_USER = 'session'
    OPT_CUSTOMER_ID = 'customer.id'
    OPT_KM_LITRE = 'km_litre'
    OPT_OIL_COST_LITRE = 'oil_cost_litre'
    OPT_PRICE = 'price'

    SEC_APP = 'app'
    OPT_DATEFORMAT = 'dateformat'
    OPT_DEBUG = 'debug'
    OPT_DATA_PATH = 'data_path'
    OPT_CONFIG_FILE_PATH = 'config_file_path'
    OPT_DB_CONNECTION_STRING = 'db_connection_string'

    SEC_DOC = 'doc'
    OPT_CLEAR_SOURCES = 'clear_src'

    def __init__(self):
        super().__init__()
        self._cfg = ConfigParser()
        self._cfg.read(self.config_file_path)

        self._setup_defaults()
        self._make_defaults()

    def get(self, section, option, type=None):
        """
        Get an option from configuration store.

        :param type: The type of config option, if None retrieves the default.
        :param section: A config section.
        :param option: A config option.
        :return: The value of option if any, None otherwise.
        """
        self._read()

        if type is not None:
            if type == bool:
                return self._cfg.getboolean(section, option)
            if type == float:
                return self._cfg.getfloat(section, option)
            if type == int:
                return self._cfg.getint(section, option)

        return self._cfg.get(section, option)

    def set(self, section, option, value):
        """
        Set a value for an option to the configuration store.

        Note: if section is not set, it will be created.

        :param section: A config section.
        :param option: A config option.
        :param value: A value for config option key.
        """
        self._read()
        self._do_section(section)
        self._cfg.set(section, option, value)
        self._save()

    def _save(self):
        with open(str(os.path.join(self.data_path, self.config_file_path)), 'w') as configfile:
            self._cfg.write(configfile)

    def _read(self):
        self._cfg.read(str(os.path.join(self.data_path, self.config_file_path)))

    def _do_section(self, value):
        """
        Creates a section if it does not exist.
        :param value: A section name.
        """
        if not self._cfg.has_section(value):
            self._cfg.add_section(value)
            self._save()

    def _setup_defaults(self, force=False):
        """
        Do some util setup for the application (e.g. create data directory, ...).
        :param force: If true, run again default setup.
        """
        if force or not os.path.exists(self.data_path):
            os.mkdir(self.data_path)

    def _make_defaults(self, force=False):
        """
        Creates default values if does not exist or if ``force`` is true.
        :param force: If true, restores the default values.
        """
        if force or not self._cfg.has_option(self.SEC_APP, self.OPT_DATEFORMAT):
            self.dateformat = str("%%d/%%m/%%Y")
        if force or not self._cfg.has_option(self.SEC_APP, self.OPT_DEBUG):
            self.debug = str(False)
        if force or not self._cfg.has_option(self.SEC_DOC, self.OPT_CLEAR_SOURCES):
            self.clear_sources = str(True)
        if force or not self._cfg.has_option(self.SEC_USER, self.OPT_KM_LITRE):
            self.km_litre = str(15)
        if force or not self._cfg.has_option(self.SEC_USER, self.OPT_OIL_COST_LITRE):
            self.oil_cost_litre = str(1.5)
        if force or not self._cfg.has_option(self.SEC_USER, self.OPT_PRICE):
            self.price = str(12.0)
        if force or not self._cfg.has_option(self.SEC_APP, self.OPT_DB_CONNECTION_STRING):
            self.db_connection_string = 'sqlite:///' + str(os.path.join(self.data_path, 'wpc.db'))
        # OPT_CUSTOMER_ID is intentionally not initialized by default.

    # user properties

    @property
    def customer(self):
        return self.get(self.SEC_USER, self.OPT_CUSTOMER_ID)

    @customer.setter
    def customer(self, value):
        self.set(self.SEC_USER, self.OPT_CUSTOMER_ID, value)

    @property
    def km_litre(self):
        return self.get(self.SEC_USER, self.OPT_KM_LITRE, type=int)

    @km_litre.setter
    def km_litre(self, value):
        self.set(self.SEC_USER, self.OPT_KM_LITRE, str(value))

    @property
    def oil_cost_litre(self):
        return self.get(self.SEC_USER, self.OPT_OIL_COST_LITRE, type=float)

    @oil_cost_litre.setter
    def oil_cost_litre(self, value):
        self.set(self.SEC_USER, self.OPT_OIL_COST_LITRE, str(value))

    @property
    def price(self):
        return self.get(self.SEC_USER, self.OPT_PRICE, type=float)

    @price.setter
    def price(self, value):
        self.set(self.SEC_USER, self.OPT_PRICE, str(value))

    # app properties

    @property
    def dateformat(self):
        return self.get(self.SEC_APP, self.OPT_DATEFORMAT)

    @dateformat.setter
    def dateformat(self, value):
        self.set(self.SEC_APP, self.OPT_DATEFORMAT, value)

    @property
    def debug(self):
        return self.get(self.SEC_APP, self.OPT_DEBUG, type=bool)

    @debug.setter
    def debug(self, value):
        self.set(self.SEC_APP, self.OPT_DEBUG, str(value))

    @property
    def data_path(self):
        return str(os.path.join(str(Path.home()), self.DEFAULT_DATA_DIRECTORY_NAME))

    @property
    def config_file_path(self):
        return str(os.path.join(str(Path.home()), self.DEFAULT_DATA_DIRECTORY_NAME, self.DEFAULT_CONFIG_FILE_NAME))

    @config_file_path.setter
    def config_file_path(self, value):
        self.set(self.SEC_APP, self.OPT_CONFIG_FILE_PATH, value)

    @property
    def db_connection_string(self):
        return self.get(self.SEC_APP, self.OPT_DB_CONNECTION_STRING)

    @db_connection_string.setter
    def db_connection_string(self, value):
        self.set(self.SEC_APP, self.OPT_DB_CONNECTION_STRING, str(value))

    # doc properties

    @property
    def clear_sources(self):
        return self.get(self.SEC_DOC, self.OPT_CLEAR_SOURCES, type=bool)

    @clear_sources.setter
    def clear_sources(self, value):
        self.set(self.SEC_DOC, self.OPT_CLEAR_SOURCES, str(value))


configurator = Configurator()
