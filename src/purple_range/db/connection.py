"""SQLite database connection manager with WAL mode optimization."""

import sqlite3
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path


class DatabaseManager:
    """Manages SQLite connections configured with Write-Ahead Logging (WAL) and foreign keys."""

    def __init__(self, db_path: Path | str, timeout_seconds: float = 30.0) -> None:
        self.db_path = Path(db_path)
        self.timeout_seconds = timeout_seconds
        self._ensure_dir()

    def _ensure_dir(self) -> None:
        """Ensure parent directory for database file exists."""
        if str(self.db_path) != ":memory:":
            self.db_path.parent.mkdir(parents=True, exist_ok=True)

    def get_connection(self) -> sqlite3.Connection:
        """Create and configure a new SQLite connection with WAL mode."""
        conn = sqlite3.connect(
            str(self.db_path),
            timeout=self.timeout_seconds,
            check_same_thread=False,
        )
        conn.row_factory = sqlite3.Row

        # Configure WAL mode and foreign key enforcement
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA synchronous = NORMAL;")
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute(f"PRAGMA busy_timeout = {int(self.timeout_seconds * 1000)};")
        return conn

    @contextmanager
    def connection(self) -> Generator[sqlite3.Connection, None, None]:
        """Context manager providing a transactional connection with automatic commit/rollback."""
        conn = self.get_connection()
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()
