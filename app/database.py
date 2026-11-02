import json
import hashlib
import hmac
import secrets
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Generator


class InvestigationStore:
    def __init__(self, path: str) -> None:
        self.path = path
        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    @contextmanager
    def _connection(self) -> Generator[sqlite3.Connection, None, None]:
        connection = self._connect()
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def _initialize(self) -> None:
        with self._connection() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS investigations (
                    id TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    investigation_type TEXT NOT NULL,
                    target TEXT NOT NULL,
                    risk_score INTEGER NOT NULL,
                    risk_category TEXT NOT NULL,
                    summary TEXT NOT NULL,
                    evidence_json TEXT NOT NULL,
                    report_json TEXT NOT NULL
                )
                """
            )
            columns = {
                row["name"]
                for row in connection.execute("PRAGMA table_info(investigations)")
            }
            if "user_id" not in columns:
                connection.execute(
                    "ALTER TABLE investigations ADD COLUMN user_id TEXT"
                )
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY,
                    email TEXT NOT NULL UNIQUE,
                    display_name TEXT NOT NULL,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL DEFAULT 'user',
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS auth_sessions (
                    token_hash TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    expires_at TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS password_resets (
                    token_hash TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    expires_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS saved_investigations (
                    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    investigation_id TEXT NOT NULL,
                    note TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL,
                    PRIMARY KEY (user_id, investigation_id)
                );
                CREATE TABLE IF NOT EXISTS watchlist (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    value TEXT NOT NULL,
                    item_type TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE (user_id, value, item_type)
                );
                CREATE TABLE IF NOT EXISTS watchlist_monitoring (
                    watchlist_id TEXT PRIMARY KEY
                        REFERENCES watchlist(id) ON DELETE CASCADE,
                    enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
                    interval_hours INTEGER NOT NULL CHECK (interval_hours >= 6),
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS watchlist_monitor_checks (
                    id TEXT PRIMARY KEY,
                    watchlist_id TEXT NOT NULL
                        REFERENCES watchlist(id) ON DELETE CASCADE,
                    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    checked_at TEXT NOT NULL,
                    status TEXT NOT NULL,
                    report_json TEXT NOT NULL,
                    delta_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS watchlist_alerts (
                    id TEXT PRIMARY KEY,
                    watchlist_id TEXT NOT NULL
                        REFERENCES watchlist(id) ON DELETE CASCADE,
                    check_id TEXT NOT NULL
                        REFERENCES watchlist_monitor_checks(id) ON DELETE CASCADE,
                    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    created_at TEXT NOT NULL,
                    message TEXT NOT NULL,
                    read_at TEXT
                );
                CREATE TABLE IF NOT EXISTS user_preferences (
                    user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
                    language TEXT NOT NULL DEFAULT 'en',
                    notifications_enabled INTEGER NOT NULL DEFAULT 1
                );
                CREATE TABLE IF NOT EXISTS login_attempts (
                    email TEXT NOT NULL,
                    attempted_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS registration_attempts (
                    source_hash TEXT NOT NULL,
                    attempted_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS rate_limit_events (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_investigations_user_created
                    ON investigations(user_id, created_at DESC);
                CREATE INDEX IF NOT EXISTS idx_sessions_user
                    ON auth_sessions(user_id);
                CREATE INDEX IF NOT EXISTS idx_login_attempts
                    ON login_attempts(email, attempted_at);
                CREATE INDEX IF NOT EXISTS idx_registration_attempts
                    ON registration_attempts(source_hash, attempted_at);
                CREATE INDEX IF NOT EXISTS idx_monitor_checks_owner
                    ON watchlist_monitor_checks(user_id, checked_at DESC);
                CREATE INDEX IF NOT EXISTS idx_monitor_alerts_owner
                    ON watchlist_alerts(user_id, created_at DESC);
                CREATE INDEX IF NOT EXISTS idx_rate_limits_owner_action_time
                    ON rate_limit_events(user_id, action, created_at DESC);
                """
            )

    def save(self, report: dict[str, Any], *, user_id: str | None = None) -> None:
        summary = report.get("scoring_explanation", "")
        with self._connection() as connection:
            connection.execute(
                """
                INSERT INTO investigations
                (id, created_at, investigation_type, target, risk_score,
                 risk_category, summary, evidence_json, report_json, user_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    created_at = excluded.created_at,
                    investigation_type = excluded.investigation_type,
                    target = excluded.target,
                    risk_score = excluded.risk_score,
                    risk_category = excluded.risk_category,
                    summary = excluded.summary,
                    evidence_json = excluded.evidence_json,
                    report_json = excluded.report_json,
                    user_id = excluded.user_id
                """,
                (
                    report["id"],
                    report["created_at"],
                    report["investigation_type"],
                    report["target"],
                    report["risk_score"],
                    report["risk_category"],
                    summary,
                    json.dumps(report.get("evidence", [])),
                    json.dumps(report),
                    user_id,
                ),
            )

    def list_recent(
        self,
        limit: int = 50,
        *,
        investigation_type: str | None = None,
        risk_category: str | None = None,
        search_text: str | None = None,
        user_id: str | None = None,
    ) -> list[dict[str, Any]]:
        filters: list[str] = []
        values: list[Any] = []
        if investigation_type:
            filters.append("investigation_type = ?")
            values.append(investigation_type)
        if risk_category:
            filters.append("risk_category = ?")
            values.append(risk_category)
        if search_text:
            filters.append("(target LIKE ? OR summary LIKE ?)")
            values.extend((f"%{search_text}%", f"%{search_text}%"))
        if user_id is not None:
            filters.append("user_id = ?")
            values.append(user_id)
        where = f"WHERE {' AND '.join(filters)}" if filters else ""
        with self._connection() as connection:
            rows = connection.execute(
                f"""
                SELECT id, created_at, investigation_type, target, risk_score,
                       risk_category, summary
                FROM investigations {where} ORDER BY created_at DESC LIMIT ?
                """,
                (*values, limit),
            ).fetchall()
        return [dict(row) for row in rows]

    def analytics(self, *, user_id: str | None = None) -> dict[str, Any]:
        owner_filter = "WHERE user_id = ?" if user_id is not None else ""
        owner_values: tuple[Any, ...] = (user_id,) if user_id is not None else ()
        activity_filter = "WHERE user_id = ? AND created_at >= datetime('now', '-29 days')" if user_id is not None else "WHERE created_at >= datetime('now', '-29 days')"
        with self._connection() as connection:
            total = connection.execute(
                f"SELECT COUNT(*) AS count FROM investigations {owner_filter}",
                owner_values,
            ).fetchone()["count"]
            categories = connection.execute(
                f"""
                SELECT risk_category AS category, COUNT(*) AS count
                FROM investigations {owner_filter} GROUP BY risk_category
                """,
                owner_values,
            ).fetchall()
            types = connection.execute(
                f"""
                SELECT investigation_type AS type, COUNT(*) AS count
                FROM investigations {owner_filter} GROUP BY investigation_type
                """,
                owner_values,
            ).fetchall()
            activity = connection.execute(
                f"""
                SELECT substr(created_at, 1, 10) AS date, COUNT(*) AS count,
                       AVG(risk_score) AS average_risk
                FROM investigations
                {activity_filter}
                GROUP BY substr(created_at, 1, 10)
                ORDER BY date
                """,
                owner_values,
            ).fetchall()
        return {
            "total_investigations": total,
            "risk_categories": [dict(row) for row in categories],
            "investigation_types": [dict(row) for row in types],
            "activity": [dict(row) for row in activity],
            "latest": self.list_recent(8, user_id=user_id),
        }

    def get(
        self,
        investigation_id: str,
        *,
        user_id: str | None = None,
    ) -> dict[str, Any] | None:
        owner_filter = " AND user_id = ?" if user_id is not None else ""
        parameters: tuple[Any, ...] = (
            (investigation_id, user_id)
            if user_id is not None
            else (investigation_id,)
        )
        with self._connection() as connection:
            row = connection.execute(
                f"SELECT report_json FROM investigations WHERE id = ?{owner_filter}",
                parameters,
            ).fetchone()
        return json.loads(row["report_json"]) if row else None

    def delete_investigation(self, user_id: str, investigation_id: str) -> bool:
        with self._connection() as connection:
            row = connection.execute(
                "SELECT 1 FROM investigations WHERE id = ? AND user_id = ?",
                (investigation_id, user_id),
            ).fetchone()
            if row is None:
                return False
            connection.execute(
                "DELETE FROM saved_investigations WHERE user_id = ? AND investigation_id = ?",
                (user_id, investigation_id),
            )
            connection.execute(
                "DELETE FROM investigations WHERE id = ? AND user_id = ?",
                (investigation_id, user_id),
            )
        return True

    @staticmethod
    def _token_hash(token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    @staticmethod
    def _password_hash(password: str, salt: bytes | None = None) -> str:
        actual_salt = salt or secrets.token_bytes(16)
        digest = hashlib.scrypt(
            password.encode("utf-8"),
            salt=actual_salt,
            n=2**14,
            r=8,
            p=1,
            dklen=64,
        )
        return f"scrypt${actual_salt.hex()}${digest.hex()}"

    @classmethod
    def _verify_password(cls, password: str, encoded_hash: str) -> bool:
        try:
            scheme, salt_hex, expected_hex = encoded_hash.split("$", 2)
            if scheme != "scrypt":
                return False
            actual_hash = cls._password_hash(password, bytes.fromhex(salt_hex))
            actual = actual_hash.rsplit("$", 1)[1]
            return hmac.compare_digest(actual, expected_hex)
        except (ValueError, TypeError):
            return False

    @staticmethod
    def _public_user(row: sqlite3.Row) -> dict[str, str]:
        return {
            "id": row["id"],
            "email": row["email"],
            "display_name": row["display_name"],
            "role": row["role"],
            "created_at": row["created_at"],
        }

    def register_user(
        self,
        email: str,
        display_name: str,
        password: str,
    ) -> dict[str, str]:
        normalized_email = email.strip().lower()
        user_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        with self._connection() as connection:
            connection.execute(
                """
                INSERT INTO users (id, email, display_name, password_hash, role, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    user_id,
                    normalized_email,
                    display_name.strip(),
                    self._password_hash(password),
                    "user",
                    now,
                ),
            )
            connection.execute(
                "INSERT INTO user_preferences (user_id) VALUES (?)",
                (user_id,),
            )
            row = connection.execute(
                "SELECT * FROM users WHERE id = ?", (user_id,)
            ).fetchone()
        return self._public_user(row)

    def user_by_email(self, email: str) -> sqlite3.Row | None:
        with self._connection() as connection:
            return connection.execute(
                "SELECT * FROM users WHERE email = ?",
                (email.strip().lower(),),
            ).fetchone()

    def user_by_id(self, user_id: str) -> dict[str, str] | None:
        with self._connection() as connection:
            row = connection.execute(
                "SELECT * FROM users WHERE id = ?", (user_id,)
            ).fetchone()
        return self._public_user(row) if row else None

    def authenticate_user(self, email: str, password: str) -> dict[str, str] | None:
        normalized_email = email.strip().lower()
        now = datetime.now(timezone.utc)
        cutoff = (now - timedelta(minutes=15)).isoformat()
        with self._connection() as connection:
            connection.execute(
                "DELETE FROM login_attempts WHERE attempted_at < ?",
                (cutoff,),
            )
            count = connection.execute(
                "SELECT COUNT(*) FROM login_attempts WHERE email = ? AND attempted_at >= ?",
                (normalized_email, cutoff),
            ).fetchone()[0]
            if count >= 10:
                return None
            row = connection.execute(
                "SELECT * FROM users WHERE email = ?", (normalized_email,)
            ).fetchone()
            if row is None or not self._verify_password(password, row["password_hash"]):
                if row is None:
                    self._password_hash(password, bytes(16))
                connection.execute(
                    "INSERT INTO login_attempts (email, attempted_at) VALUES (?, ?)",
                    (normalized_email, now.isoformat()),
                )
                return None
            connection.execute("DELETE FROM login_attempts WHERE email = ?", (normalized_email,))
            return self._public_user(row)

    def allow_registration_attempt(
        self,
        source_address: str,
        *,
        limit: int = 5,
        window_minutes: int = 60,
    ) -> bool:
        source_hash = hashlib.sha256(source_address.encode("utf-8")).hexdigest()
        now = datetime.now(timezone.utc)
        cutoff = (now - timedelta(minutes=window_minutes)).isoformat()
        with self._connection() as connection:
            connection.execute(
                "DELETE FROM registration_attempts WHERE attempted_at < ?",
                (cutoff,),
            )
            attempts = connection.execute(
                "SELECT COUNT(*) FROM registration_attempts WHERE source_hash = ? AND attempted_at >= ?",
                (source_hash, cutoff),
            ).fetchone()[0]
            if attempts >= limit:
                return False
            connection.execute(
                "INSERT INTO registration_attempts (source_hash, attempted_at) VALUES (?, ?)",
                (source_hash, now.isoformat()),
            )
        return True

    def create_session(self, user_id: str, *, hours: int = 12) -> str:
        token = secrets.token_urlsafe(32)
        now = datetime.now(timezone.utc)
        with self._connection() as connection:
            connection.execute(
                """
                INSERT INTO auth_sessions (token_hash, user_id, expires_at, created_at)
                VALUES (?, ?, ?, ?)
                """,
                (
                    self._token_hash(token),
                    user_id,
                    (now + timedelta(hours=hours)).isoformat(),
                    now.isoformat(),
                ),
            )
        return token

    def session_user(self, token: str) -> dict[str, str] | None:
        with self._connection() as connection:
            row = connection.execute(
                """
                SELECT users.* FROM auth_sessions
                JOIN users ON users.id = auth_sessions.user_id
                WHERE auth_sessions.token_hash = ? AND auth_sessions.expires_at > ?
                """,
                (self._token_hash(token), datetime.now(timezone.utc).isoformat()),
            ).fetchone()
        return self._public_user(row) if row else None

    def revoke_session(self, token: str) -> None:
        with self._connection() as connection:
            connection.execute(
                "DELETE FROM auth_sessions WHERE token_hash = ?",
                (self._token_hash(token),),
            )

    def update_profile(self, user_id: str, display_name: str) -> dict[str, str] | None:
        with self._connection() as connection:
            connection.execute(
                "UPDATE users SET display_name = ? WHERE id = ?",
                (display_name.strip(), user_id),
            )
            row = connection.execute(
                "SELECT * FROM users WHERE id = ?", (user_id,)
            ).fetchone()
        return self._public_user(row) if row else None

    def change_password(
        self,
        user_id: str,
        current_password: str,
        new_password: str,
    ) -> bool:
        with self._connection() as connection:
            row = connection.execute(
                "SELECT password_hash FROM users WHERE id = ?", (user_id,)
            ).fetchone()
            if row is None or not self._verify_password(
                current_password, row["password_hash"]
            ):
                return False
            connection.execute(
                "UPDATE users SET password_hash = ? WHERE id = ?",
                (self._password_hash(new_password), user_id),
            )
            connection.execute("DELETE FROM auth_sessions WHERE user_id = ?", (user_id,))
        return True

    def begin_password_reset(self, email: str) -> str | None:
        row = self.user_by_email(email)
        if row is None:
            return None
        token = secrets.token_urlsafe(32)
        expires_at = (datetime.now(timezone.utc) + timedelta(minutes=20)).isoformat()
        with self._connection() as connection:
            connection.execute(
                "DELETE FROM password_resets WHERE user_id = ?",
                (row["id"],),
            )
            connection.execute(
                "INSERT INTO password_resets (token_hash, user_id, expires_at) VALUES (?, ?, ?)",
                (self._token_hash(token), row["id"], expires_at),
            )
        return token

    def finish_password_reset(self, token: str, new_password: str) -> bool:
        now = datetime.now(timezone.utc).isoformat()
        with self._connection() as connection:
            row = connection.execute(
                "SELECT user_id FROM password_resets WHERE token_hash = ? AND expires_at > ?",
                (self._token_hash(token), now),
            ).fetchone()
            if row is None:
                return False
            connection.execute(
                "UPDATE users SET password_hash = ? WHERE id = ?",
                (self._password_hash(new_password), row["user_id"]),
            )
            connection.execute(
                "DELETE FROM auth_sessions WHERE user_id = ?", (row["user_id"],)
            )
            connection.execute(
                "DELETE FROM password_resets WHERE user_id = ?", (row["user_id"],)
            )
        return True

    def delete_user(self, user_id: str) -> None:
        with self._connection() as connection:
            row = connection.execute(
                "SELECT email FROM users WHERE id = ?", (user_id,)
            ).fetchone()
            if row is None:
                return
            connection.execute("DELETE FROM investigations WHERE user_id = ?", (user_id,))
            connection.execute("DELETE FROM rate_limit_events WHERE user_id = ?", (user_id,))
            connection.execute("DELETE FROM login_attempts WHERE email = ?", (row["email"],))
            connection.execute("DELETE FROM users WHERE id = ?", (user_id,))

    def save_investigation(
        self,
        user_id: str,
        investigation_id: str,
        note: str = "",
    ) -> None:
        with self._connection() as connection:
            owns_report = connection.execute(
                "SELECT 1 FROM investigations WHERE id = ? AND user_id = ?",
                (investigation_id, user_id),
            ).fetchone()
            if owns_report is None:
                raise ValueError("Investigation does not belong to this user.")
            connection.execute(
                """
                INSERT INTO saved_investigations (user_id, investigation_id, note, created_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(user_id, investigation_id) DO UPDATE SET note = excluded.note
                """,
                (
                    user_id,
                    investigation_id,
                    note.strip(),
                    datetime.now(timezone.utc).isoformat(),
                ),
            )

    def saved_investigations(self, user_id: str) -> list[dict[str, Any]]:
        with self._connection() as connection:
            rows = connection.execute(
                """
                SELECT saved.investigation_id AS id, saved.note, saved.created_at AS saved_at,
                       investigations.created_at, investigations.investigation_type,
                       investigations.target, investigations.risk_score,
                       investigations.risk_category
                FROM saved_investigations AS saved
                JOIN investigations ON investigations.id = saved.investigation_id
                WHERE saved.user_id = ? ORDER BY saved.created_at DESC
                """,
                (user_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def unsave_investigation(self, user_id: str, investigation_id: str) -> None:
        with self._connection() as connection:
            connection.execute(
                "DELETE FROM saved_investigations WHERE user_id = ? AND investigation_id = ?",
                (user_id, investigation_id),
            )

    def add_watchlist_item(self, user_id: str, value: str, item_type: str) -> dict[str, str]:
        item_id = str(uuid.uuid4())
        created_at = datetime.now(timezone.utc).isoformat()
        with self._connection() as connection:
            connection.execute(
                """
                INSERT INTO watchlist (id, user_id, value, item_type, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (item_id, user_id, value.strip(), item_type, created_at),
            )
        return {
            "id": item_id,
            "value": value.strip(),
            "item_type": item_type,
            "created_at": created_at,
            "monitoring": "manual_only",
        }

    def list_watchlist(self, user_id: str) -> list[dict[str, Any]]:
        with self._connection() as connection:
            rows = connection.execute(
                """
                SELECT watchlist.id, value, item_type, watchlist.created_at,
                       CASE WHEN monitoring.enabled = 1 THEN 'scheduled' ELSE 'manual_only' END
                           AS monitoring,
                       monitoring.interval_hours
                FROM watchlist
                LEFT JOIN watchlist_monitoring AS monitoring
                    ON monitoring.watchlist_id = watchlist.id
                WHERE user_id = ? ORDER BY watchlist.created_at DESC
                """,
                (user_id,),
            ).fetchall()
        return [
            dict(row)
            for row in rows
        ]

    def remove_watchlist_item(self, user_id: str, item_id: str) -> None:
        with self._connection() as connection:
            connection.execute(
                "DELETE FROM watchlist WHERE id = ? AND user_id = ?",
                (item_id, user_id),
            )

    def allow_rate_limited_action(
        self,
        user_id: str,
        action: str,
        *,
        limit: int,
        window_seconds: int,
    ) -> bool:
        now = datetime.now(timezone.utc)
        cutoff = (now - timedelta(seconds=window_seconds)).isoformat()
        with self._connection() as connection:
            connection.execute(
                "DELETE FROM rate_limit_events WHERE created_at < ?",
                ((now - timedelta(days=1)).isoformat(),),
            )
            count = connection.execute(
                """
                SELECT COUNT(*) FROM rate_limit_events
                WHERE user_id = ? AND action = ? AND created_at >= ?
                """,
                (user_id, action, cutoff),
            ).fetchone()[0]
            if count >= limit:
                return False
            connection.execute(
                """
                INSERT INTO rate_limit_events (id, user_id, action, created_at)
                VALUES (?, ?, ?, ?)
                """,
                (str(uuid.uuid4()), user_id, action, now.isoformat()),
            )
        return True

    def admin_analytics(self) -> dict[str, int]:
        with self._connection() as connection:
            users = connection.execute("SELECT COUNT(*) FROM users").fetchone()[0]
            investigations = connection.execute(
                "SELECT COUNT(*) FROM investigations"
            ).fetchone()[0]
            sessions = connection.execute(
                "SELECT COUNT(*) FROM auth_sessions WHERE expires_at > ?",
                (datetime.now(timezone.utc).isoformat(),),
            ).fetchone()[0]
        return {
            "registered_users": users,
            "investigations": investigations,
            "active_sessions": sessions,
        }
