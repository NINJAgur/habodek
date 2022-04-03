from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from wpc.model import Base
from wpc.config.config import configurator


class Database:
    _session = None

    def __init__(self):
        self._autocommit = False

        engine = create_engine(configurator.db_connection_string)
        # Bind the engine to the metadata of the Base class so that the
        # declaratives can be accessed through a DBSession instance
        Base.metadata.bind = engine

        db_session = sessionmaker(bind=engine)
        # A DBSession() instance establishes all conversations with the database
        # and represents a "staging zone" for all the objects loaded into the
        # database session object. Any change made against the objects in the
        # session won't be persisted into the database until you call
        # session.commit(). If you're not happy about the changes, you can
        # revert all of them back to the last commit by calling
        # session.rollback()
        self._session = db_session()

    @property
    def autocommit(self):
        return self._autocommit

    @autocommit.setter
    def autocommit(self, val):
        self._autocommit = val

    @property
    def session(self):
        return self._session
