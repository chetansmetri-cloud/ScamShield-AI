import asyncio
import json
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Any, Awaitable, Callable, Generator

from apscheduler.schedulers.background import BackgroundScheduler
from fastapi import HTTPException

from app.database import InvestigationStore
from app.evidence import canonicalize_url, company_evidence_is_relevant
from app.investigations import investigate_website

Search = Callable[[str], Awaitable[dict[str, Any]]]
Fetch = Callable[[list[str]], Awaitable[dict[str, Any]]]
ValidateURL = Callable[[str], str]
ALLOWED_INTERVAL_HOURS = {6, 12, 24, 168}


class WatchlistMonitoring:
    def __init__(
        self,
        database_path: str,
        *,
        search: Search,
        fetch: Fetch,
        validate_url: ValidateURL,
    ) -> None:
        self.database_path = database_path
        self.search = search
        self.fetch = fetch
        self.validate_url = validate_url
        self.reports = InvestigationStore(database_path)
        self.scheduler = BackgroundScheduler(timezone="UTC", daemon=True)

    @property
    def running(self) -> bool:
        return bool(self.scheduler.running)

    @contextmanager
    def _connect(self) -> Generator[sqlite3.Connection, None, None]:
        connection = sqlite3.connect(self.database_path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def start(self) -> None:
        if self.running:
            return
        self.scheduler.start()
        with self._connect() as connection:
            settings = connection.execute(
                """
                SELECT watchlist.id, monitoring.interval_hours
                FROM watchlist_monitoring AS monitoring
                JOIN watchlist ON watchlist.id = monitoring.watchlist_id
                WHERE monitoring.enabled = 1
                """
            ).fetchall()
        for setting in settings:
            self._schedule(setting["id"], setting["interval_hours"])

    def shutdown(self) -> None:
        if self.running:
            self.scheduler.shutdown(wait=True)

    def _schedule(self, item_id: str, interval_hours: int) -> None:
        if not self.running:
            raise RuntimeError("The watchlist monitoring scheduler is not running.")
        self.scheduler.add_job(
            self._scheduled_check,
            trigger="interval",
            hours=interval_hours,
            args=[item_id],
            id=f"watchlist:{item_id}",
            replace_existing=True,
            max_instances=1,
            coalesce=True,
            next_run_time=datetime.now(timezone.utc) + timedelta(hours=interval_hours),
        )

    def configure(
        self,
        user_id: str,
        item_id: str,
        *,
        enabled: bool,
        interval_hours: int,
    ) -> dict[str, Any]:
        if interval_hours not in ALLOWED_INTERVAL_HOURS:
            raise ValueError("Choose a monitoring interval of 6, 12, 24, or 168 hours.")
        if enabled and not self.running:
            raise RuntimeError("The background scheduler is not running.")
        now = datetime.now(timezone.utc).isoformat()
        with self._connect() as connection:
            item = connection.execute(
                "SELECT id FROM watchlist WHERE id = ? AND user_id = ?",
                (item_id, user_id),
            ).fetchone()
            if item is None:
                raise LookupError("Watchlist item not found.")
            connection.execute(
                """
                INSERT INTO watchlist_monitoring
                    (watchlist_id, enabled, interval_hours, updated_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(watchlist_id) DO UPDATE SET
                    enabled = excluded.enabled,
                    interval_hours = excluded.interval_hours,
                    updated_at = excluded.updated_at
                """,
                (item_id, int(enabled), interval_hours, now),
            )
        job_id = f"watchlist:{item_id}"
        if enabled:
            self._schedule(item_id, interval_hours)
        elif self.running and self.scheduler.get_job(job_id):
            self.scheduler.remove_job(job_id)
        return self.settings(user_id, item_id)

    def settings(self, user_id: str, item_id: str) -> dict[str, Any]:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT watchlist.id, watchlist.value, watchlist.item_type,
                       monitoring.enabled, monitoring.interval_hours,
                       monitoring.updated_at
                FROM watchlist
                LEFT JOIN watchlist_monitoring AS monitoring
                    ON monitoring.watchlist_id = watchlist.id
                WHERE watchlist.id = ? AND watchlist.user_id = ?
                """,
                (item_id, user_id),
            ).fetchone()
        if row is None:
            raise LookupError("Watchlist item not found.")
        job = self.scheduler.get_job(f"watchlist:{item_id}") if self.running else None
        return {
            "id": row["id"],
            "value": row["value"],
            "item_type": row["item_type"],
            "enabled": bool(row["enabled"]),
            "interval_hours": row["interval_hours"] or 24,
            "updated_at": row["updated_at"],
            "scheduler_running": self.running,
            "job_scheduled": job is not None,
            "next_run_time": job.next_run_time.isoformat() if job and job.next_run_time else None,
        }

    def history(self, user_id: str, item_id: str, limit: int = 20) -> list[dict[str, Any]]:
        self.settings(user_id, item_id)
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT id, checked_at, status, report_json, delta_json
                FROM watchlist_monitor_checks
                WHERE watchlist_id = ? AND user_id = ?
                ORDER BY checked_at DESC LIMIT ?
                """,
                (item_id, user_id, limit),
            ).fetchall()
        return [
            {
                "id": row["id"],
                "checked_at": row["checked_at"],
                "status": row["status"],
                "report": json.loads(row["report_json"]),
                "changes": json.loads(row["delta_json"]),
            }
            for row in rows
        ]

    def alerts(self, user_id: str, limit: int = 100) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT alerts.id, alerts.watchlist_id, watchlist.value,
                       alerts.check_id, alerts.created_at, alerts.message,
                       alerts.read_at
                FROM watchlist_alerts AS alerts
                JOIN watchlist ON watchlist.id = alerts.watchlist_id
                WHERE alerts.user_id = ?
                ORDER BY alerts.created_at DESC LIMIT ?
                """,
                (user_id, limit),
            ).fetchall()
        return [dict(row) for row in rows]

    def mark_alert_read(self, user_id: str, alert_id: str) -> bool:
        with self._connect() as connection:
            cursor = connection.execute(
                """
                UPDATE watchlist_alerts SET read_at = ?
                WHERE id = ? AND user_id = ? AND read_at IS NULL
                """,
                (datetime.now(timezone.utc).isoformat(), alert_id, user_id),
            )
        return cursor.rowcount > 0

    def remove_schedule(self, item_id: str) -> None:
        if not self.running:
            return
        job_id = f"watchlist:{item_id}"
        if self.scheduler.get_job(job_id):
            self.scheduler.remove_job(job_id)

    def _scheduled_check(self, item_id: str) -> None:
        asyncio.run(self.perform_check(item_id))

    async def perform_check(
        self,
        item_id: str,
        *,
        owner_id: str | None = None,
    ) -> dict[str, Any]:
        with self._connect() as connection:
            query = """
                SELECT watchlist.id, watchlist.user_id, watchlist.value,
                       watchlist.item_type, monitoring.enabled
                FROM watchlist
                LEFT JOIN watchlist_monitoring AS monitoring
                    ON monitoring.watchlist_id = watchlist.id
                WHERE watchlist.id = ?
            """
            parameters: tuple[Any, ...] = (item_id,)
            if owner_id is not None:
                query += " AND watchlist.user_id = ?"
                parameters = (item_id, owner_id)
            item = connection.execute(query, parameters).fetchone()
        if item is None:
            raise LookupError("Watchlist item not found.")
        if owner_id is None and not item["enabled"]:
            return {"status": "skipped", "reason": "Monitoring is disabled."}

        user_id = item["user_id"]
        checked_at = datetime.now(timezone.utc).isoformat()
        try:
            if item["item_type"] == "domain":
                target_url = self.validate_url(f"https://{item['value']}")
                report = await investigate_website(target_url, self.search, self.fetch)
            elif item["item_type"] == "organization":
                report = await self._company_report(item["value"])
            else:
                raise LookupError("Only domains and organizations can be monitored.")
        except HTTPException as exc:
            return self._record_failure(
                item_id,
                user_id,
                checked_at,
                item["value"],
                f"HTTP {exc.status_code}: {exc.detail}",
            )

        report["id"] = str(uuid.uuid4())
        report["created_at"] = checked_at
        report["monitoring_item_id"] = item_id
        report["investigation_type"] = (
            "website" if item["item_type"] == "domain" else "company"
        )
        delta = self._changes(item_id, user_id, report)
        self.reports.save(report, user_id=user_id)
        check_id = str(uuid.uuid4())
        self._record_check(
            check_id,
            item_id,
            user_id,
            checked_at,
            "completed",
            report,
            delta,
        )
        if delta["new_indicators"] or delta["risk_score_delta"] >= 10:
            message = (
                f"New warning indicators detected for {item['value']}."
                if delta["new_indicators"]
                else f"Risk indicators increased for {item['value']}."
            )
            with self._connect() as connection:
                connection.execute(
                    """
                    INSERT INTO watchlist_alerts
                        (id, watchlist_id, check_id, user_id, created_at, message)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (str(uuid.uuid4()), item_id, check_id, user_id, checked_at, message),
                )
        return {
            "id": check_id,
            "checked_at": checked_at,
            "status": "completed",
            "report": report,
            "changes": delta,
        }

    async def _company_report(self, company_name: str) -> dict[str, Any]:
        payload = await self.search(
            f'"{company_name}" official company website scam fraud warning complaints'
        )
        results = payload.get("results", [])
        evidence = []
        if isinstance(results, list):
            for item in results:
                if not isinstance(item, dict):
                    continue
                url = item.get("url")
                if not isinstance(url, str) or canonicalize_url(url) is None:
                    continue
                relevant = company_evidence_is_relevant(
                    company_name,
                    title=str(item.get("title", "")),
                    snippet=str(item.get("snippet", "")),
                    source_url=url,
                    offer_url=None,
                )
                evidence.append(
                    {
                        "title": str(item.get("title", "")),
                        "url": url,
                        "excerpt": str(item.get("snippet", ""))[:1200],
                        "source_type": "search_result",
                        "provider": "TinyFish Search",
                        "relevance": "company_related" if relevant else "unrelated_not_scored",
                    }
                )
        relevant_evidence = [
            item for item in evidence if item["relevance"] == "company_related"
        ]
        return {
            "id": str(uuid.uuid4()),
            "created_at": datetime.now(timezone.utc).isoformat(),
            "investigation_type": "company",
            "target": company_name,
            "analysis_method": "evidence_only",
            "risk_score": 0,
            "risk_category": "Evidence gathered; not scored",
            "scoring_explanation": (
                "Scheduled monitoring collects company-related public sources only; "
                "it does not score or verify identity."
            ),
            "indicators": [],
            "evidence": evidence,
            "sources": [item["url"] for item in evidence],
            "live_research": "completed" if relevant_evidence else "partial",
            "missing_information": (
                [] if relevant_evidence else ["No company-related public search results were returned."]
            ),
        }

    def _changes(
        self,
        item_id: str,
        user_id: str,
        report: dict[str, Any],
    ) -> dict[str, Any]:
        with self._connect() as connection:
            previous = connection.execute(
                """
                SELECT report_json FROM watchlist_monitor_checks
                WHERE watchlist_id = ? AND user_id = ? AND status = 'completed'
                ORDER BY checked_at DESC LIMIT 1
                """,
                (item_id, user_id),
            ).fetchone()
        previous_report = json.loads(previous["report_json"]) if previous else {}
        previous_indicators = {
            str(item.get("name")) for item in previous_report.get("indicators", [])
        }
        current_indicators = {
            str(item.get("name")) for item in report.get("indicators", [])
        }
        previous_urls = {
            str(item.get("url")) for item in previous_report.get("evidence", []) if item.get("url")
        }
        current_urls = {
            str(item.get("url")) for item in report.get("evidence", []) if item.get("url")
        }
        previous_score = int(previous_report.get("risk_score", 0))
        current_score = int(report.get("risk_score", 0))
        return {
            "new_indicators": sorted(current_indicators - previous_indicators),
            "removed_indicators": sorted(previous_indicators - current_indicators),
            "new_evidence_urls": sorted(current_urls - previous_urls),
            "previous_score": previous_score if previous else None,
            "risk_score": current_score,
            "risk_score_delta": current_score - previous_score if previous else 0,
            "previous_category": previous_report.get("risk_category"),
            "risk_category": report.get("risk_category"),
        }

    def _record_check(
        self,
        check_id: str,
        item_id: str,
        user_id: str,
        checked_at: str,
        status: str,
        report: dict[str, Any],
        delta: dict[str, Any],
    ) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO watchlist_monitor_checks
                    (id, watchlist_id, user_id, checked_at, status, report_json, delta_json)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    check_id,
                    item_id,
                    user_id,
                    checked_at,
                    status,
                    json.dumps(report),
                    json.dumps(delta),
                ),
            )

    def _record_failure(
        self,
        item_id: str,
        user_id: str,
        checked_at: str,
        target: str,
        error: str,
    ) -> dict[str, Any]:
        check_id = str(uuid.uuid4())
        report = {
            "id": check_id,
            "created_at": checked_at,
            "investigation_type": "monitoring",
            "target": target,
            "risk_category": "Unable to verify",
            "risk_score": 0,
            "live_research": "failed",
            "error": error,
            "indicators": [],
            "evidence": [],
        }
        delta: dict[str, Any] = {
            "new_indicators": [],
            "removed_indicators": [],
            "new_evidence_urls": [],
            "risk_score_delta": 0,
        }
        self._record_check(
            check_id,
            item_id,
            user_id,
            checked_at,
            "failed",
            report,
            delta,
        )
        return {
            "id": check_id,
            "checked_at": checked_at,
            "status": "failed",
            "report": report,
            "changes": delta,
        }
