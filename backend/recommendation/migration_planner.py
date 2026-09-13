"""
Turning per-asset deadlines into a plan somebody can execute.

The risk engine says when each asset has to start and finish. On its own that is
a list of several hundred dates, which is not a plan. This groups them into
waves a team can schedule, and — more usefully — says where the plan does not
work: which waves cannot be completed by their own deadline even starting today,
and which individual assets set the floor on how fast the whole estate can move.

Nothing here invents a constant. Wave boundaries come from the deadlines
themselves, durations come from the Y the risk layer computed, and the
organisation's capacity is only considered when the caller states it.
"""
from datetime import date
from typing import Dict, List, Optional

from backend.analysis.risk_inputs import years_between, years_from
from backend.models import (
    CryptographicArtefact, MigrationPlan, MigrationWave, MoscaRiskAssessment,
)

# An asset taking a year or more is a long-lead item: it has to be started on
# its own schedule rather than when its deadline says, because the duration is
# the constraint. In practice these are hardware modules, vendor binaries and
# dependencies waiting on an upstream release.
LONG_LEAD_YEARS = 1.0

# Horizon bands, in years from today. An asset is placed by when it must start.
_BANDS = [
    (0.0, "Now", "Already past the date this work had to begin, or disallowed "
                 "by a standard that has already taken effect."),
    (1.0, "Within 12 months", "The start date falls inside the current planning "
                              "year, so this needs budget and people now."),
    (3.0, "1 to 3 years", "Inside the normal budget cycle. Plan it; do not "
                          "start it before the wave above is moving."),
    (5.0, "3 to 5 years", "Far enough out to schedule around other work."),
]
_TAIL = ("Beyond 5 years", "No action needed yet beyond keeping the asset in "
                           "the inventory so it is re-assessed each scan.")


def build_migration_plan(
    artefacts: List[CryptographicArtefact],
    risk_assessments: Dict[str, MoscaRiskAssessment],
    today: Optional[date] = None,
    parallel_capacity: Optional[int] = None,
) -> MigrationPlan:
    today = today or date.today()
    notes: List[str] = []

    scheduled = [
        (a, risk_assessments[a.id])
        for a in artefacts
        if a.id in risk_assessments
        and risk_assessments[a.id].must_start_by is not None
    ]

    if not scheduled:
        return MigrationPlan(
            generated_on=today,
            parallel_capacity=parallel_capacity,
            notes=[
                "No asset in this inventory carries a migration deadline. "
                "Either everything is already quantum-safe, or the scan "
                "predates the scheduling model and needs re-running."
            ],
        )

    # ---------------------------------------------------------- assign waves
    buckets: Dict[int, List[tuple]] = {i: [] for i in range(len(_BANDS) + 1)}
    for art, risk in scheduled:
        slack = years_between(today, risk.must_start_by)
        index = len(_BANDS)  # the tail, unless a band claims it
        for i, (limit, _, _) in enumerate(_BANDS):
            if slack < limit or (i == 0 and slack <= 0):
                index = i
                break
        buckets[index].append((art, risk))

    waves: List[MigrationWave] = []
    for index in sorted(buckets):
        members = buckets[index]
        if not members:
            continue

        label, rationale = (
            (_BANDS[index][1], _BANDS[index][2]) if index < len(_BANDS) else _TAIL
        )

        # The wave opens when its first asset must start, but never in the past:
        # work that is already overdue can only begin today.
        earliest_start = min(r.must_start_by for _, r in members)
        starts_on = max(today, earliest_start)
        deadline = min(r.must_complete_by for _, r in members)
        longest = max(a.migration_time_years for a, _ in members)

        # Assets inside a wave run in parallel, so the wave lasts as long as its
        # longest member. If that does not fit before the wave's earliest
        # deadline, the plan is not achievable and says so.
        available = years_between(starts_on, deadline)
        shortfall = round(longest - available, 2)
        # A deadline behind us is a breach, not a tight schedule. Keeping the
        # two apart matters because the responses differ: one is "start now and
        # accept the overrun", the other is "this is already non-compliant".
        already_passed = deadline < starts_on

        distribution: Dict[str, int] = {}
        for _, risk in members:
            key = risk.risk_category.value
            distribution[key] = distribution.get(key, 0) + 1

        waves.append(MigrationWave(
            sequence=len(waves),
            label=label,
            rationale=rationale,
            starts_on=starts_on,
            must_complete_by=deadline,
            artefact_ids=[a.id for a, _ in members],
            asset_count=len(members),
            longest_migration_years=round(longest, 2),
            is_infeasible=shortfall > 0,
            shortfall_years=max(0.0, shortfall),
            deadline_already_passed=already_passed,
            risk_distribution=distribution,
        ))

    # ----------------------------------------------------- constraints and notes
    long_lead = sorted(
        (a for a, _ in scheduled if a.migration_time_years >= LONG_LEAD_YEARS),
        key=lambda a: a.migration_time_years,
        reverse=True,
    )
    critical_path = round(max(a.migration_time_years for a, _ in scheduled), 2)

    breached = [w for w in waves if w.deadline_already_passed]
    if breached:
        assets = sum(w.asset_count for w in breached)
        worst = min(breached, key=lambda w: w.must_complete_by)
        notes.append(
            f"{assets} asset(s) are past a deadline that has already taken "
            f"effect — the earliest was "
            f"{worst.must_complete_by.isoformat()}. These are a compliance "
            f"breach to report, not work to schedule."
        )

    infeasible = [
        w for w in waves if w.is_infeasible and not w.deadline_already_passed
    ]
    if infeasible:
        worst = max(infeasible, key=lambda w: w.shortfall_years)
        notes.append(
            f"{len(infeasible)} of {len(waves)} waves cannot be completed by "
            f"their own deadline even starting today. The largest gap is "
            f"{worst.shortfall_years:g} years in '{worst.label}'. Either the "
            f"deadline moves, the migration is shortened, or the risk is "
            f"formally accepted."
        )

    if long_lead:
        slowest = long_lead[0]
        notes.append(
            f"{len(long_lead)} asset{'s' if len(long_lead) != 1 else ''} take a "
            f"year or more to migrate and set the floor on the whole programme. "
            f"The slowest is '{slowest.name}' at "
            f"{slowest.migration_time_years:g} years — start it on its own "
            f"schedule, not when its wave comes up."
        )

    notes.append(
        f"Critical path {critical_path:g} years: even with every migration run "
        f"in parallel, the estate cannot be finished sooner than "
        f"{years_from(today, critical_path).isoformat()}."
    )

    if parallel_capacity is None:
        notes.append(
            "Concurrent capacity was not stated, so wave sizes have not been "
            "checked against what the organisation can actually run at once."
        )
    else:
        over = [w for w in waves if w.asset_count > parallel_capacity]
        if over:
            notes.append(
                f"{len(over)} wave(s) contain more assets than the stated "
                f"capacity of {parallel_capacity} concurrent migrations, so "
                f"work inside them will queue rather than run in parallel and "
                f"the durations above are optimistic."
            )

    return MigrationPlan(
        generated_on=today,
        waves=waves,
        critical_path_years=critical_path,
        long_lead_artefact_ids=[a.id for a in long_lead],
        parallel_capacity=parallel_capacity,
        notes=notes,
    )
