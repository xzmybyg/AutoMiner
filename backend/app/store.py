import os
from datetime import UTC, datetime

from sqlalchemy import Integer, String, Text, create_engine, text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker


def now():
    return datetime.now(UTC).timestamp()


class Base(DeclarativeBase):
    pass


class Record(Base):
    __tablename__ = "records"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    kind: Mapped[str] = mapped_column(String(32), index=True)
    payload: Mapped[str] = mapped_column(Text)


class Mutex(Base):
    __tablename__ = "mutex"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    revision: Mapped[int] = mapped_column(Integer, default=0)


engine = create_engine(
    os.getenv("DATABASE_URL", "sqlite:///./autominer.db"),
    **(
        {"connect_args": {"check_same_thread": False, "timeout": 30}}
        if os.getenv("DATABASE_URL", "sqlite:").startswith("sqlite:")
        else {}
    ),
)
Session = sessionmaker(engine, expire_on_commit=False)


def init_db():
    if engine.dialect.name == "postgresql":
        with engine.begin() as connection:
            connection.execute(text("SELECT pg_advisory_xact_lock(802104)"))
            Base.metadata.create_all(connection)
            connection.execute(
                text(
                    "INSERT INTO mutex (id, revision) VALUES (1, 0) ON CONFLICT (id) DO NOTHING"
                )
            )
        return
    Base.metadata.create_all(engine)
    with Session.begin() as s:
        if not s.get(Mutex, 1):
            s.add(Mutex(id=1, revision=0))
