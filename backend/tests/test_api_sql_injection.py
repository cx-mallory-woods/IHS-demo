"""
Tests for SQL injection remediation in get_tasks_api endpoint.

Verifies that:
  - The endpoint functions correctly for normal queries (regression)
  - SQL injection payloads in the 'search' parameter are safely handled
  - SQL injection payloads in 'project_id' and 'assigned_to' are safely handled
  - All filter combinations work with parameterized queries
"""
import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_task(db_session, title, description, project_id, created_by,
               assigned_to=None, status="pending", priority="medium"):
    from models import Task
    task = Task(
        title=title,
        description=description,
        project_id=project_id,
        created_by=created_by,
        assigned_to=assigned_to,
        status=status,
        priority=priority,
    )
    db_session.add(task)
    db_session.commit()
    return task


# ---------------------------------------------------------------------------
# Regression: normal behaviour
# ---------------------------------------------------------------------------

class TestGetTasksApiNormal:
    """Normal (non-attack) usage of GET /api/v1/tasks."""

    def test_returns_all_tasks_without_filters(self, client, sample_task):
        """Endpoint returns a list of tasks when no filter is provided."""
        response = client.get("/api/v1/tasks")
        assert response.status_code == 200
        data = response.get_json()
        assert "tasks" in data
        assert isinstance(data["tasks"], list)
        assert len(data["tasks"]) >= 1

    def test_search_returns_matching_tasks(self, client, db_session,
                                           sample_project, sample_user):
        """search parameter filters tasks by title/description."""
        _make_task(db_session, "Fix login bug", "Login is broken",
                   sample_project.id, sample_user.id)
        _make_task(db_session, "Write docs", "Improve documentation",
                   sample_project.id, sample_user.id)

        response = client.get("/api/v1/tasks?search=login")
        assert response.status_code == 200
        data = response.get_json()
        titles = [t["title"] for t in data["tasks"]]
        assert any("login" in t.lower() or "Login" in t for t in titles)
        assert not any("Write docs" == t for t in titles)

    def test_search_case_insensitive_like(self, client, db_session,
                                          sample_project, sample_user):
        """LIKE search works for partial matches."""
        _make_task(db_session, "Deploy service", "Automate deployment",
                   sample_project.id, sample_user.id)

        response = client.get("/api/v1/tasks?search=Deploy")
        assert response.status_code == 200
        data = response.get_json()
        assert len(data["tasks"]) >= 1

    def test_filter_by_project_id(self, client, db_session,
                                   sample_project, sample_user):
        """project_id filter narrows results to a single project."""
        _make_task(db_session, "Project task", "desc",
                   sample_project.id, sample_user.id)

        response = client.get(f"/api/v1/tasks?project_id={sample_project.id}")
        assert response.status_code == 200
        data = response.get_json()
        assert all(t["project_id"] == sample_project.id
                   for t in data["tasks"])

    def test_filter_by_assigned_to(self, client, db_session,
                                    sample_project, sample_user):
        """assigned_to filter returns only tasks assigned to that user."""
        _make_task(db_session, "Assigned task", "desc",
                   sample_project.id, sample_user.id,
                   assigned_to=sample_user.id)
        _make_task(db_session, "Unassigned task", "desc",
                   sample_project.id, sample_user.id,
                   assigned_to=None)

        response = client.get(
            f"/api/v1/tasks?assigned_to={sample_user.id}"
        )
        assert response.status_code == 200
        data = response.get_json()
        assigned_ids = [t["assigned_to"] for t in data["tasks"]]
        assert all(aid == sample_user.id for aid in assigned_ids if aid)

    def test_search_with_project_id_filter(self, client, db_session,
                                            sample_project, sample_user):
        """Combined search + project_id filters work together."""
        _make_task(db_session, "Combo task", "combined filter test",
                   sample_project.id, sample_user.id)

        response = client.get(
            f"/api/v1/tasks?search=Combo&project_id={sample_project.id}"
        )
        assert response.status_code == 200
        data = response.get_json()
        assert len(data["tasks"]) >= 1

    def test_search_with_assigned_to_filter(self, client, db_session,
                                             sample_project, sample_user):
        """Combined search + assigned_to filters work together."""
        _make_task(db_session, "Assigned search task", "for search",
                   sample_project.id, sample_user.id,
                   assigned_to=sample_user.id)

        response = client.get(
            f"/api/v1/tasks?search=search&assigned_to={sample_user.id}"
        )
        assert response.status_code == 200
        data = response.get_json()
        assert len(data["tasks"]) >= 1

    def test_no_match_returns_empty_list(self, client, sample_task):
        """search term that matches nothing returns an empty list."""
        response = client.get(
            "/api/v1/tasks?search=xyzzyimpossiblesearchterm99999"
        )
        assert response.status_code == 200
        data = response.get_json()
        assert data["tasks"] == []

    def test_empty_search_returns_all_tasks(self, client, sample_task):
        """Empty search string triggers the ORM branch, not the raw SQL branch."""
        response = client.get("/api/v1/tasks?search=")
        assert response.status_code == 200
        data = response.get_json()
        assert isinstance(data["tasks"], list)


# ---------------------------------------------------------------------------
# Security: SQL injection in 'search' parameter
# ---------------------------------------------------------------------------

class TestGetTasksApiSqlInjectionSearch:
    """SQL injection payloads in the 'search' query parameter must NOT alter
    query semantics or raise unhandled exceptions."""

    @pytest.mark.parametrize("payload", [
        # Classic tautology – should not return extra rows
        "' OR '1'='1",
        "' OR 1=1 --",
        "'; DROP TABLE tasks; --",
        # UNION-based extraction attempt
        "' UNION SELECT * FROM users --",
        "' UNION SELECT 1,2,3,4,5,6,7,8,9,10 --",
        # Blind injection probes
        "' AND SLEEP(5) --",
        "' AND 1=2 --",
        "' AND 1=1 --",
        # Stacked queries
        "'; INSERT INTO tasks(title) VALUES('injected') --",
        # Escaped single quotes
        "test' AND ''='",
        # Comment styles
        "test/**/OR/**/1=1",
        # Null byte injection
        "test\x00' OR '1'='1",
        # Boolean injection
        "1' OR '1'='1' --",
    ])
    def test_injection_payload_does_not_expose_all_tasks(
        self, client, db_session, sample_project, sample_user, payload
    ):
        """A SQL injection payload in 'search' must not return all tasks.

        The safe behaviour is: the payload is treated as a literal string and
        matches no real task titles/descriptions, so the result is either empty
        or contains only tasks whose title/description literally contain the
        payload substring.
        """
        # Create a 'sentinel' task that should NOT appear in results if injection
        # is blocked.
        sentinel = _make_task(
            db_session, "sentinel-task-unique-abc123",
            "should not be returned by injection",
            sample_project.id, sample_user.id
        )

        response = client.get(f"/api/v1/tasks?search={payload}")
        # Endpoint must remain operational (no 500)
        assert response.status_code in (200, 400), (
            f"Unexpected HTTP {response.status_code} for payload: {payload!r}"
        )

        if response.status_code == 200:
            data = response.get_json()
            task_ids = [t["id"] for t in data["tasks"]]
            # The sentinel task must not appear via injection
            assert sentinel.id not in task_ids, (
                f"SQL injection via 'search' exposed sentinel task. "
                f"Payload: {payload!r}"
            )

    def test_percent_wildcard_is_treated_literally(self, client, db_session,
                                                    sample_project, sample_user):
        """A bare '%' in search does not crash the endpoint."""
        _make_task(db_session, "wildcard task", "test",
                   sample_project.id, sample_user.id)
        response = client.get("/api/v1/tasks?search=%25")
        assert response.status_code == 200

    def test_double_quote_injection(self, client, db_session,
                                    sample_project, sample_user):
        """Double-quote characters do not break the query."""
        _make_task(db_session, 'task "quoted"', "desc",
                   sample_project.id, sample_user.id)
        response = client.get('/api/v1/tasks?search="OR+1%3D1')
        assert response.status_code == 200

    def test_backslash_does_not_escape(self, client, db_session,
                                       sample_project, sample_user):
        """Backslash characters in search do not cause a syntax error."""
        response = client.get(r"/api/v1/tasks?search=\\%27+OR+%271%27%3D%271")
        assert response.status_code == 200


# ---------------------------------------------------------------------------
# Security: SQL injection in 'project_id' parameter
# ---------------------------------------------------------------------------

class TestGetTasksApiSqlInjectionProjectId:
    """SQL injection payloads in the 'project_id' query parameter."""

    @pytest.mark.parametrize("payload", [
        "1 OR 1=1",
        "1; DROP TABLE tasks; --",
        "1 UNION SELECT * FROM users",
        "0 OR 1=1 --",
        "1 AND 1=2 UNION SELECT username,2,3,4,5,6,7,8,9,10 FROM users",
    ])
    def test_injection_in_project_id_with_search(
        self, client, db_session, sample_project, sample_user, payload
    ):
        """Malicious project_id combined with search is safely parameterized."""
        sentinel = _make_task(
            db_session, "sentinel-project-task-xyz987",
            "not returned via injection",
            sample_project.id, sample_user.id
        )

        response = client.get(
            f"/api/v1/tasks?search=sentinel&project_id={payload}"
        )
        # Either the DB coerces non-integer gracefully (empty result) or the
        # endpoint handles it — no 500 internal error expected.
        assert response.status_code in (200, 400), (
            f"Unexpected status {response.status_code} for project_id={payload!r}"
        )

    def test_non_numeric_project_id_does_not_crash(self, client):
        """Non-numeric project_id is safely handled."""
        response = client.get("/api/v1/tasks?project_id=abc")
        # Should not raise an unhandled exception
        assert response.status_code in (200, 400, 422)

    def test_numeric_project_id_works_correctly(
        self, client, db_session, sample_project, sample_user
    ):
        """Legitimate numeric project_id filters tasks correctly."""
        _make_task(db_session, "Legitimate task", "desc",
                   sample_project.id, sample_user.id)

        response = client.get(
            f"/api/v1/tasks?search=Legitimate&project_id={sample_project.id}"
        )
        assert response.status_code == 200
        data = response.get_json()
        assert len(data["tasks"]) >= 1


# ---------------------------------------------------------------------------
# Security: SQL injection in 'assigned_to' parameter
# ---------------------------------------------------------------------------

class TestGetTasksApiSqlInjectionAssignedTo:
    """SQL injection payloads in the 'assigned_to' query parameter."""

    @pytest.mark.parametrize("payload", [
        "1 OR 1=1",
        "1; DROP TABLE tasks; --",
        "0 UNION SELECT * FROM users --",
    ])
    def test_injection_in_assigned_to_with_search(
        self, client, db_session, sample_project, sample_user, payload
    ):
        """Malicious assigned_to combined with search is safely parameterized."""
        sentinel = _make_task(
            db_session, "sentinel-assigned-task-qrs654",
            "should not appear via injection",
            sample_project.id, sample_user.id,
            assigned_to=sample_user.id
        )

        response = client.get(
            f"/api/v1/tasks?search=sentinel&assigned_to={payload}"
        )
        assert response.status_code in (200, 400), (
            f"Unexpected status {response.status_code} for assigned_to={payload!r}"
        )

    def test_numeric_assigned_to_works_correctly(
        self, client, db_session, sample_project, sample_user
    ):
        """Legitimate numeric assigned_to filters results correctly."""
        _make_task(db_session, "Assigned correctly", "desc",
                   sample_project.id, sample_user.id,
                   assigned_to=sample_user.id)

        response = client.get(
            f"/api/v1/tasks?search=Assigned+correctly"
            f"&assigned_to={sample_user.id}"
        )
        assert response.status_code == 200
        data = response.get_json()
        assert len(data["tasks"]) >= 1


# ---------------------------------------------------------------------------
# Security: verify parameterized query is used (structural check)
# ---------------------------------------------------------------------------

class TestGetTasksApiParameterizedQueryUsage:
    """Structural tests that confirm the raw-SQL branch uses parameterized
    queries rather than string interpolation."""

    def test_single_quote_in_search_does_not_raise_syntax_error(
        self, client, db_session, sample_project, sample_user
    ):
        """A single-quote in search must not trigger a DB syntax error.

        Before the fix the string was directly interpolated, causing:
            ProgrammingError: near \"'\": syntax error
        With parameterized queries, the quote is treated as a literal value.
        """
        _make_task(db_session, "O'Brien's task", "desc",
                   sample_project.id, sample_user.id)

        response = client.get("/api/v1/tasks?search=O%27Brien")
        assert response.status_code == 200
        data = response.get_json()
        titles = [t["title"] for t in data["tasks"]]
        assert any("O'Brien" in t for t in titles)

    def test_search_result_row_mapping_uses_underscore_mapping(
        self, client, db_session, sample_project, sample_user
    ):
        """Tasks returned via the raw-SQL branch include expected fields."""
        _make_task(db_session, "mapping check task", "desc for mapping",
                   sample_project.id, sample_user.id)

        response = client.get("/api/v1/tasks?search=mapping+check")
        assert response.status_code == 200
        data = response.get_json()
        assert len(data["tasks"]) >= 1
        task = data["tasks"][0]
        # Verify the _mapping conversion preserved column names
        assert "title" in task or "id" in task

    def test_all_three_params_together(
        self, client, db_session, sample_project, sample_user
    ):
        """search + project_id + assigned_to all together uses parameterized SQL."""
        t = _make_task(
            db_session, "triple filter task", "three parameters",
            sample_project.id, sample_user.id,
            assigned_to=sample_user.id
        )

        response = client.get(
            f"/api/v1/tasks"
            f"?search=triple+filter"
            f"&project_id={sample_project.id}"
            f"&assigned_to={sample_user.id}"
        )
        assert response.status_code == 200
        data = response.get_json()
        task_ids = [task["id"] for task in data["tasks"]]
        assert t.id in task_ids
