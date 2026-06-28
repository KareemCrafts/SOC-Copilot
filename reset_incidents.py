from src.database.models import init_db, Alert, Incident
from sqlalchemy.orm import Session

engine = init_db()
with Session(engine) as session:
    session.query(Incident).delete()
    session.query(Alert).update({Alert.incident_id: None})
    session.commit()
print("[+] Reset complete")