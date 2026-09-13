"""
Historical dataset construction (issue #21).

Temporal correctness is the whole point of this dataset, and it is the kind of defect
that produces plausible-looking numbers rather than an error — a leaked label inflates
every method's apparent performance without anything visibly failing. So most of these
tests are about what must be *excluded*: features that postdate the snapshot, labels that
predate it, and CVEs that did not exist yet.

Entirely offline: every input is injected, nothing downloads.
"""

from datetime import date

import pytest

from src.dataset import historical, nvd_cvss, sources

SNAPSHOT = date(2026, 1, 1)
WINDOWS = (30, 60, 90)


def cvss_record(score=7.5, severity="HIGH", version="3.1", published="2025-06-01"):
    return {"cvss_score": score, "cvss_severity": severity,
            "cvss_version": version, "published": published}


class TestKevLabels:
    """`dateAdded` is what makes one current KEV download yield temporal labels."""

    def test_already_kev_is_flagged_and_not_a_target(self):
        """
        Exploitation known at T is an *input* to the decision. Scoring it as a correct
        prediction would credit a method for reading what it was handed.
        """
        kev = {"CVE-A": date(2025, 6, 1)}
        labels = sources.kev_labels(kev, "CVE-A", SNAPSHOT, WINDOWS)
        assert labels["kev_at_snapshot"] is True
        assert labels["eligible"] is False
        assert all(labels[f"later_kev_{n}d"] is False for n in WINDOWS)

    def test_entered_kev_inside_the_window_is_a_positive(self):
        kev = {"CVE-A": date(2026, 1, 20)}          # T + 19 days
        labels = sources.kev_labels(kev, "CVE-A", SNAPSHOT, WINDOWS)
        assert labels["kev_at_snapshot"] is False
        assert labels["eligible"] is True
        assert labels["later_kev_30d"] is True
        assert labels["later_kev_60d"] is True
        assert labels["later_kev_90d"] is True

    def test_windows_are_nested_not_exclusive(self):
        """A 45-day entry is positive at 60d and 90d but not at 30d."""
        kev = {"CVE-A": date(2026, 2, 15)}          # T + 45 days
        labels = sources.kev_labels(kev, "CVE-A", SNAPSHOT, WINDOWS)
        assert labels["later_kev_30d"] is False
        assert labels["later_kev_60d"] is True
        assert labels["later_kev_90d"] is True

    def test_entry_beyond_the_longest_window_is_not_positive(self):
        kev = {"CVE-A": date(2026, 6, 1)}           # T + 151 days
        labels = sources.kev_labels(kev, "CVE-A", SNAPSHOT, WINDOWS)
        assert all(labels[f"later_kev_{n}d"] is False for n in WINDOWS)
        assert labels["eligible"] is True           # still a valid negative/unknown

    def test_never_in_kev_is_unknown_not_negative(self):
        """
        Absence from KEV is not evidence of non-exploitation. The row carries no
        positive label and stays eligible; asserting a negative is the caller's
        decision to document, not the dataset's to make.
        """
        labels = sources.kev_labels({}, "CVE-A", SNAPSHOT, WINDOWS)
        assert labels["eligible"] is True
        assert labels["kev_date_added"] is None
        assert all(labels[f"later_kev_{n}d"] is False for n in WINDOWS)

    def test_boundary_is_inclusive_at_the_horizon(self):
        kev = {"CVE-A": date(2026, 1, 31)}          # exactly T + 30
        assert sources.kev_labels(kev, "CVE-A", SNAPSHOT, (30,))["later_kev_30d"] is True

    def test_entry_on_the_snapshot_date_counts_as_already_known(self):
        """Same-day entry was knowable at T, so it is not a future outcome."""
        kev = {"CVE-A": SNAPSHOT}
        labels = sources.kev_labels(kev, "CVE-A", SNAPSHOT, WINDOWS)
        assert labels["kev_at_snapshot"] is True
        assert labels["eligible"] is False


class TestPublishedBefore:
    def test_published_before_snapshot(self):
        assert nvd_cvss.published_before(cvss_record(published="2025-06-01"), SNAPSHOT)

    def test_published_after_snapshot_is_excluded(self):
        """A CVE that did not exist at T could not have been prioritized at T."""
        assert not nvd_cvss.published_before(cvss_record(published="2026-03-01"), SNAPSHOT)

    def test_published_on_the_snapshot_date_is_included(self):
        assert nvd_cvss.published_before(cvss_record(published="2026-01-01"), SNAPSHOT)

    @pytest.mark.parametrize("bad", ["", "not-a-date", None])
    def test_missing_or_malformed_date_is_excluded(self, bad):
        """Conservative: shrink the population rather than admit an undatable record."""
        assert not nvd_cvss.published_before(cvss_record(published=bad), SNAPSHOT)

    def test_missing_record_is_excluded(self):
        assert not nvd_cvss.published_before(None, SNAPSHOT)


class TestBuildSnapshot:
    """Assembly, with every input injected."""

    def _inputs(self):
        epss = {
            "CVE-OLD-KEV": {"epss": 0.90, "percentile": 0.99},   # already KEV at T
            "CVE-POSITIVE": {"epss": 0.30, "percentile": 0.95},  # enters KEV at T+19
            "CVE-QUIET": {"epss": 0.001, "percentile": 0.10},    # never KEV
            "CVE-FUTURE": {"epss": 0.50, "percentile": 0.97},    # published after T
            "CVE-NO-CVSS": {"epss": 0.40, "percentile": 0.96},   # absent from NVD index
        }
        cvss_index = {
            "CVE-OLD-KEV": cvss_record(9.8, "CRITICAL"),
            "CVE-POSITIVE": cvss_record(7.5, "HIGH"),
            "CVE-QUIET": cvss_record(3.1, "LOW"),
            "CVE-FUTURE": cvss_record(8.0, "HIGH", published="2026-05-01"),
        }
        kev_dates = {
            "CVE-OLD-KEV": date(2025, 5, 1),
            "CVE-POSITIVE": date(2026, 1, 20),
        }
        exploits = {
            "CVE-POSITIVE": date(2025, 12, 1),   # exploit predates T -> feature True
            "CVE-QUIET": date(2026, 4, 1),       # exploit postdates T -> feature False
        }
        return epss, cvss_index, kev_dates, exploits

    def _build(self):
        epss, cvss_index, kev_dates, exploits = self._inputs()
        return historical.build_snapshot(
            SNAPSHOT, WINDOWS, cvss_index=cvss_index, kev_dates=kev_dates,
            exploits=exploits, epss=epss)

    def test_excludes_cves_published_after_the_snapshot(self):
        rows, stats = self._build()
        assert "CVE-FUTURE" not in {r["cve_id"] for r in rows}
        assert stats["skipped_published_after_snapshot"] == 1

    def test_excludes_cves_with_no_cvss_record(self):
        rows, stats = self._build()
        assert "CVE-NO-CVSS" not in {r["cve_id"] for r in rows}
        assert stats["skipped_no_cvss_record"] == 1

    def test_exploit_evidence_is_evaluated_as_of_the_snapshot(self):
        """
        An exploit published after T must not appear as a feature at T — that is the
        same leakage as using a future EPSS score, just via a different signal.
        """
        rows, _ = self._build()
        by_id = {r["cve_id"]: r for r in rows}
        assert by_id["CVE-POSITIVE"]["public_exploit_at_snapshot"] is True
        assert by_id["CVE-QUIET"]["public_exploit_at_snapshot"] is False

    def test_already_kev_row_is_retained_but_ineligible(self):
        """Retained so the manifest can report the exclusion rather than hide it."""
        rows, stats = self._build()
        by_id = {r["cve_id"]: r for r in rows}
        assert by_id["CVE-OLD-KEV"]["kev_at_snapshot"] is True
        assert by_id["CVE-OLD-KEV"]["eligible"] is False
        assert stats["kev_at_snapshot"] == 1

    def test_positive_counts_exclude_already_kev_rows(self):
        rows, stats = self._build()
        assert stats["eligible"] == 2                 # POSITIVE + QUIET
        assert stats["positives"]["30d"] == 1
        assert stats["positives"]["90d"] == 1

    def test_positive_rate_is_over_the_eligible_population(self):
        _, stats = self._build()
        assert stats["positive_rate"]["30d"] == pytest.approx(1 / 2)

    def test_feature_columns_carry_snapshot_values(self):
        rows, _ = self._build()
        row = next(r for r in rows if r["cve_id"] == "CVE-POSITIVE")
        assert row["epss_score"] == 0.30
        assert row["cvss_score"] == 7.5
        assert row["snapshot_date"] == SNAPSHOT.isoformat()

    def test_stats_report_baseline_population_sizes(self):
        """Table D1 needs these; computing them later from the CSV invites drift."""
        _, stats = self._build()
        assert stats["cvss_high_or_above"] == 2      # OLD-KEV 9.8, POSITIVE 7.5
        assert stats["epss_at_or_above_0.1"] == 2    # OLD-KEV 0.90, POSITIVE 0.30


class TestRoundTrip:
    def test_write_then_load_preserves_types(self, tmp_path):
        """
        Booleans survive the CSV round trip. A silently stringified label would make
        every row truthy, so every method would appear to score perfect recall.
        """
        epss = {"CVE-P": {"epss": 0.3, "percentile": 0.9},
                "CVE-Q": {"epss": 0.001, "percentile": 0.1}}
        rows, _ = historical.build_snapshot(
            SNAPSHOT, WINDOWS,
            cvss_index={"CVE-P": cvss_record(), "CVE-Q": cvss_record(3.1, "LOW")},
            kev_dates={"CVE-P": date(2026, 1, 15)}, exploits={}, epss=epss)
        historical.write_snapshot(rows, SNAPSHOT, tmp_path, WINDOWS)

        loaded = historical.load(SNAPSHOT, tmp_path)
        assert len(loaded) == 2
        by_id = {r["cve_id"]: r for r in loaded}
        assert by_id["CVE-P"]["later_kev_30d"] is True
        assert by_id["CVE-Q"]["later_kev_30d"] is False
        assert by_id["CVE-P"]["eligible"] is True
        assert isinstance(by_id["CVE-P"]["epss_score"], float)

    def test_load_missing_file_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            historical.load(SNAPSHOT, tmp_path)


class TestSnapshotGuards:
    def test_snapshot_before_the_archive_is_rejected(self):
        with pytest.raises(ValueError, match="archive starts"):
            sources.fetch_epss_snapshot(date(2020, 1, 1))

    def test_future_snapshot_is_rejected(self):
        """A snapshot whose outcome window has not elapsed has no labels to observe."""
        with pytest.raises(ValueError, match="not in the past"):
            sources.fetch_epss_snapshot(date(2099, 1, 1))
