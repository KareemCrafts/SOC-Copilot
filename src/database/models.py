# src/database/models.py
from sqlalchemy import create_engine, Column, String, Float, DateTime, Text, Integer
from sqlalchemy.orm import declarative_base
from datetime import datetime
import uuid

Base = declarative_base()

class Alert(Base):
    __tablename__ = "alerts"
    id                   = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    timestamp            = Column(DateTime, default=datetime.utcnow)
    host                 = Column(String, nullable=False)
    user                 = Column(String, nullable=True)
    source_ip            = Column(String, nullable=True)
    event_id             = Column(String, nullable=True)
    rule_name            = Column(String, nullable=False)
    mitre_technique_id   = Column(String, nullable=False)
    mitre_technique_name = Column(String, nullable=False)
    mitre_tactic         = Column(String, nullable=False)
    severity             = Column(String, nullable=False)
    confidence           = Column(Float, nullable=False)
    raw_event            = Column(Text, nullable=True)
    incident_id          = Column(String, nullable=True)

class Incident(Base):
    __tablename__ = "incidents"
    id               = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    host             = Column(String, nullable=False)
    source_ip        = Column(String, nullable=True)
    user             = Column(String, nullable=True)
    start_time       = Column(DateTime, nullable=False)
    end_time         = Column(DateTime, nullable=False)
    alert_count      = Column(Integer, nullable=False)
    max_severity     = Column(String, nullable=False)
    mitre_tactics    = Column(Text, nullable=True)
    mitre_techniques = Column(Text, nullable=True)
    rule_names       = Column(Text, nullable=True)
    ai_summary       = Column(Text, nullable=True)

def init_db(db_path: str = "soc_copilot.db"):
    engine = create_engine(f"sqlite:///{db_path}")
    Base.metadata.create_all(engine)
    return engine