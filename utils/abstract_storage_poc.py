#!/usr/bin/env python3
__project__ = "Abstract Storage POC"
__version__ = "0.2.0"
__author__ = "Giuseppe De Marco (giuseppe.demarco@unical.it)"
__copyright__ = "(C) 2018 Giuseppe De Marco. GNU GPL 2."
__description__ = """
This is a POC of an AbstractStorage

# Setup section show us how to get the database being created and working

# JWK things show us how to use the Database in a traditional way with the ORM 

# Storage Abstraction Layer

This is the most important section, it show how configure a database (data storage) 
and maps a Custom StorageObject in ABSTRACT_STORAGE_DRIVERS dictionary.

The Interface to get, set and generally interacts with data is called AbstractStorage.
Followings example on the bottom page run the games.
"""

# Setup

import datetime
import json
import sqlalchemy as alchemy_db

engine = alchemy_db.create_engine('sqlite:///things.sqlite')
connection = engine.connect()

# that's for inspection, if a alchemy_db has been already created
# metadata = alchemy_db.MetaData()
# thing = alchemy_db.Table('Thing', metadata, autoload=True, autoload_with=engine)

# otherwise be "declarative"
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()


class Thing(Base):
    __tablename__ = 'thing'
    
    id = alchemy_db.Column(alchemy_db.Integer, alchemy_db.Sequence('thing_id_seq'),
                   primary_key=True)
    owner = alchemy_db.Column(alchemy_db.String(80), unique=False, nullable=False)
    data = alchemy_db.Column(alchemy_db.String(2048), unique=True, nullable=False)
    created = alchemy_db.Column(alchemy_db.DateTime, default=datetime.datetime.utcnow)

    def __repr__(self):
        return '<Thing owned by %r>' % self.owner

Base.metadata.create_all(engine)


# ======================================================================

# JWK things

from cryptojwt.jwk.rsa import new_rsa_key
from cryptojwt.jwk.jwk import key_from_jwk_dict
rsa_key = new_rsa_key()
rsa_key.serialize(private=True)

# get and set things in the alchemy_db

from sqlalchemy.orm import sessionmaker
Session = sessionmaker(bind=engine)
session = Session()

thing = Thing(owner='peppe', data=json.dumps(rsa_key.serialize(private=True)))

# store in the alchemy_db, commit means we have in a transation
session.add(thing)
session.commit()

# get an entry
session.query(Thing).filter_by(owner='peppe').all()  

# get a key
_key = key_from_jwk_dict(json.loads(session.query(Thing).filter_by(owner='peppe').all()[0].data))


# ======================================================================

# Storage Abstraction Layer

class AbstractStorageSQLAlchemy:
    def __init__(self, conf_dict):
        self.engine = alchemy_db.create_engine('sqlite:///things.sqlite')
        self.connection = engine.connect()

        self.metadata = alchemy_db.MetaData()
        self.table = alchemy_db.Table(conf_dict['params']['table'],
                                      self.metadata, autoload=True,
                                      autoload_with=self.engine)
        Session = sessionmaker(bind=self.engine)
        self.session = Session()

    def get(self, k):
        entries = self.session.query(self.table).filter_by(owner=k).all()  
        result = []
        for entry in entries:
            try:
                result.append(json.loads(entry.data))
            except:
                result.append(entry.data)
        return result
        
    def set(self, k, v):
        if isinstance(v, dict) or isinstance(v, list):
            value = json.dumps(v)
        else:
            value = v

        ins = self.table.insert().values(owner=k,
                                        data=value)
        self.session.execute(ins)
        self.session.commit()
        return 1

    def delete(self, v, k='owner'):
        table_column = getattr(self.table.c, k)
        self.session.execute(self.table.delete().where(table_column == v))
        return 1

    def __contains__(self, k):
        for entry in self():
            if k in entry:
                return 1
    
    def __call__(self):
        return self.session.query(self.table).all() 

    def __iter__(self):
        return self.session.query(self.table)

        
configuration_dict = dict(
                            driver = 'sqlalchemy',
                            url = 'sqlite:///things.sqlite',
                            params = dict(table='Thing')
                         )

ABSTRACT_STORAGE_DRIVERS = {
                             'sqlalchemy' : AbstractStorageSQLAlchemy,    
                            }

class AbstractStorage:
    def __init__(self, configuration_dict):
        self.storage = ABSTRACT_STORAGE_DRIVERS[configuration_dict['driver']](configuration_dict)

    def get(self, k):
        return self.storage.get(k)

    def set(self, k, v):
        return self.storage.set(k, v)

    def delete(self, k, v):
        return self.storage.delete(v, k=k)

    def __getitem__(self, k):
        return self.storage.get(k)

    def __setitem__(self, k, v):
        return self.storage.set(k, v)

    def __delitem__(self, v):
        return self.storage.delete(v)

    def __call__(self):
        return self.storage() 
    
    def __len__(self):
        return len(self.storage())

    def __contains__(self, k):
        return self.storage.__contains__(k)

    def __str__(self):
        entries = []
        for entry in self.storage():
            l = []
            for element in entry:
                if isinstance(element, datetime.datetime):
                    l.append(element.isoformat())
                else:
                    l.append(element)
            entries.append(l)
        return json.dumps(entries, indent=2)

    def __iter__(self):
        return iter(self.storage.__iter__())

    def flush(self):
        """
        make a decision here ...
        """
        try:
            self.storage.session.commit()
        except:
            self.storage.session.flush()
            self.storage.session.rollback()

    
# proof
absdb = AbstractStorage(configuration_dict)

print(absdb)

# set
rsa_key = new_rsa_key()
absdb.set('peppe', rsa_key.serialize(private=True))
absdb['emy'] = 'dfsdfdsf'

# get
absdb.get('peppe')
absdb['emy']  

# delete
absdb.delete('owner', 'peppe') 

# get all
absdb()

# set again and see all
rsa_key = new_rsa_key()
absdb.set('peppe', rsa_key.serialize(private=True))
absdb()

# len
len(absdb)

# contains
'ciao' in absdb  
1 in absdb
'peppe' in absdb

# __iter__
for i in absdb:
    print(i)
