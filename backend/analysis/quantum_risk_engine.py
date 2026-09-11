"""
Quantum risk assessment.

Four models run over every asset, and the one that binds hardest decides the
schedule:

  Mosca          X + Y > Z. The headline, and the one everybody recognises.
  Probabilistic  Z is not a number but an expert distribution, so the honest
                 output is P(CRQC arrives before migration finishes), as a band.
  Regulatory     A fixed standards deadline. No estimation in it at all, which
                 makes it the only model an auditor can enforce.
  HNDL           How many years of harvest-now-decrypt-later exposure the asset
                 carries. Turns the Mosca boolean into a magnitude.

The engine emits dates, not just bands: the date migration has to start and the
date it has to finish. An asset whose start date has passed is overdue, and says
so by how much.
"""
from datetime import date
from typing import Dict, List, Optional, Tuple

from backend.analysis.risk_inputs import (
    CRQC_CURVE_SOURCE, DEFAULT_Z_YEARS, crqc_probability_within,
    derive_migration_time_y, derive_shelf_life_x, is_classically_broken,
    regulatory_deadline_for,
    years_between, years_from,
)
from backend.models import (
    AlgorithmClass, BusinessCriticality, CryptographicArtefact, CryptoUsage,
    DataSensitivityProfile, ModelVerdict, MoscaRiskAssessment,
    QuantumVulnerabilityStatus, RiskCategory,
    RiskModel,
)


class QuantumRiskEngine:
    """
    Applies Mosca's inequality and three complementary models to compute
    per-artefact quantum risk, and derives a migration schedule from them.
    """

    DEFAULT_Z_TIMELINE = DEFAULT_Z_YEARS

    # Slack, in years, between today and the date work must start. These replace
    # a bare `margin < 2.0`: the bands are about how much runway is left before
    # the schedule breaks, which is the thing a planner acts on.
    #
    # Timing sets the base band and consequence modulates it, rather than the
    # two being conflated. An overdue asset of ordinary criticality is HIGH; the
    # same asset in a payments path is CRITICAL. Collapsing both to CRITICAL
    # would make the HIGH band unreachable again, which was a real defect here.
    SLACK_MOBILISE = 1.0   # overdue, or under a year to get moving
    SLACK_PLANNING = 3.0   # inside a normal budget cycle

    # ------------------------------------------------------------ inputs

    @classmethod
    def prepare_artefact(
        cls,
        art: CryptographicArtefact,
        profile: DataSensitivityProfile = DataSensitivityProfile.FINANCIAL,
        retention_override: Optional[float] = None,
    ) -> CryptographicArtefact:
        """
        Derive X and Y for one artefact and write them back onto it.

        Called before evaluation so that the artefact carried in the CBOM and
        shown in the inventory holds the same numbers the risk engine used.
        """
        x, usage, why = derive_shelf_life_x(
            art,
            profile,
            retention_override=(
                art.shelf_life_override_years
                if art.shelf_life_override_years is not None
                else retention_override
            ),
        )
        y, breakdown = derive_migration_time_y(art)

        art.crypto_usage = usage
        art.data_shelf_life_years = x
        art.shelf_life_rationale = why
        art.migration_time_years = y
        art.migration_time_breakdown = breakdown
        return art

    @classmethod
    def prepare_all(
        cls,
        artefacts: List[CryptographicArtefact],
        profile: DataSensitivityProfile = DataSensitivityProfile.FINANCIAL,
        retention_override: Optional[float] = None,
    ) -> List[CryptographicArtefact]:
        return [
            cls.prepare_artefact(a, profile, retention_override) for a in artefacts
        ]

    # ------------------------------------------------------------- models

    @classmethod
    def _mosca(cls, x: float, y: float, z: float, today: date) -> ModelVerdict:
        """X + Y > Z, expressed as a schedule rather than a boolean."""
        crqc_on = years_from(today, z)
        # Data encrypted on the last day before migration completes must still
        # be secret X years later. So migration has to finish X years before a
        # CRQC exists, and start Y years before that.
        complete_by = years_from(crqc_on, -x)
        start_by = years_from(complete_by, -y)
        slack = round(z - x - y, 2)

        return ModelVerdict(
            model=RiskModel.MOSCA,
            at_risk=slack < 0,
            slack_years=slack,
            must_start_by=start_by,
            must_complete_by=complete_by,
            detail=(
                f"X {x:g}y + Y {y:g}y = {round(x + y, 2):g}y against a {z:g}y "
                f"horizon: {abs(slack):g} years "
                + ("over" if slack < 0 else "of slack") + "."
            ),
            source="Mosca (2018), IEEE Security & Privacy 16(5)",
        )

    @classmethod
    def _probabilistic(cls, x: float, y: float, today: date) -> ModelVerdict:
        """
        P(a CRQC exists before this asset's protection lapses).

        Reported as the expert band, not a midpoint. Collapsing a 28-49% range
        to "38%" invents a precision the underlying survey does not have.
        """
        horizon = x + y
        lo, hi, provenance = crqc_probability_within(horizon)
        return ModelVerdict(
            model=RiskModel.PROBABILISTIC,
            # Treat a better-than-even chance at the optimistic end of the band
            # as the trigger; below that the deterministic model still speaks.
            at_risk=hi >= 0.50,
            probability_low=lo,
            probability_high=hi,
            detail=(
                f"{lo:.0%}-{hi:.0%} chance a CRQC exists within {horizon:g} "
                f"years, the point at which this asset's protection lapses "
                f"({provenance})."
            ),
            source=CRQC_CURVE_SOURCE,
        )

    @classmethod
    def _regulatory(
        cls, art: CryptographicArtefact, y: float, today: date
    ) -> Optional[ModelVerdict]:
        """A fixed standards deadline. The only model with no estimation in it."""
        deadline = regulatory_deadline_for(art)
        if deadline is None or deadline.disallowed_on is None:
            return None

        complete_by = deadline.disallowed_on
        start_by = years_from(complete_by, -y)
        slack = years_between(today, start_by)

        note = deadline.requirement
        if deadline.applies_only_to_nss:
            note += " Applies only where national security system rules bind."

        return ModelVerdict(
            model=RiskModel.REGULATORY,
            # An NSS-only deadline is reported but does not put a general
            # commercial estate at risk.
            at_risk=slack < 0 and not deadline.applies_only_to_nss,
            slack_years=slack,
            must_start_by=start_by,
            must_complete_by=complete_by,
            detail=(
                f"Disallowed after {deadline.disallowed_on.isoformat()}; with a "
                f"{y:g}-year migration, work must start by "
                f"{start_by.isoformat()}. {note}"
            ),
            source=deadline.authority,
        )

    @classmethod
    def _hndl(cls, x: float, y: float, z: float) -> ModelVerdict:
        """
        Years of harvest-now-decrypt-later exposure.

        Mosca says whether you are exposed. This says by how much: the span
        during which data encrypted today is still sensitive after a CRQC
        exists, and therefore readable by anyone who recorded it.
        """
        exposure = round(max(0.0, (x + y) - z), 2)
        return ModelVerdict(
            model=RiskModel.HNDL,
            at_risk=exposure > 0,
            slack_years=round(-exposure, 2) if exposure else None,
            detail=(
                f"{exposure:g} years of data encrypted between now and "
                f"migration would still be sensitive once a CRQC exists."
                if exposure > 0
                else "No harvest-now-decrypt-later exposure at this horizon."
            ),
            source="Mosca (2018); NIST IR 8547 §2",
        )

    # ------------------------------------------------------ quantum safety

    @classmethod
    def _is_quantum_safe(cls, art: CryptographicArtefact) -> bool:
        """
        Whether a quantum adversary gains anything against this asset.

        Two independent ways to be safe, and the engine has to honour both:
        the algorithm is post-quantum by design, or the parameters are large
        enough that Shor and Grover buy nothing useful — AES-256, SHA-384. The
        second is recorded as a vulnerability status rather than an algorithm
        class, which is why testing the class alone missed it.
        """
        if art.algorithm_class in (AlgorithmClass.POST_QUANTUM, AlgorithmClass.HYBRID):
            return True
        return art.quantum_vulnerability in (
            QuantumVulnerabilityStatus.QUANTUM_SAFE,
            QuantumVulnerabilityStatus.HYBRID_PROTECTED,
        )

    @classmethod
    def _safe_explanation(cls, art: CryptographicArtefact) -> str:
        if art.algorithm_class in (AlgorithmClass.POST_QUANTUM, AlgorithmClass.HYBRID):
            return (
                "Post-quantum or hybrid algorithm: resilient to both Shor's and "
                "Grover's algorithms. No migration deadline applies, so Mosca's "
                "inequality has nothing to measure here."
            )
        return (
            "Quantum-safe at these parameters: the best known quantum attack "
            "leaves an adequate security margin, so there is nothing for a "
            "migration to change. X + Y > Z is arithmetic about an adversary "
            "that does not threaten this asset, and is not applied to it."
        )

    # ----------------------------------------------------------- banding

    _ESCALATION = [
        RiskCategory.LOW, RiskCategory.MEDIUM, RiskCategory.HIGH,
        RiskCategory.CRITICAL,
    ]

    @classmethod
    def _band(
        cls, slack: float, criticality: BusinessCriticality
    ) -> Tuple[RiskCategory, str]:
        """Timing sets the band; business consequence moves it one step."""
        if slack < 0:
            base = RiskCategory.HIGH
            why = (
                f"Overdue by {abs(slack):g} years — the date this migration had "
                f"to start has already passed."
            )
        elif slack < cls.SLACK_MOBILISE:
            base = RiskCategory.HIGH
            why = (
                f"Only {slack:g} years before work must begin — inside the time "
                f"it takes to mobilise, so this is effectively due now."
            )
        elif slack < cls.SLACK_PLANNING:
            base = RiskCategory.MEDIUM
            why = (
                f"{slack:g} years of runway — inside a normal budget cycle, so "
                f"this has to be planned for now even though it is not yet urgent."
            )
        else:
            base = RiskCategory.LOW
            why = (
                f"{slack:g} years before work must begin. Migration fits within "
                f"the scheduled lifecycle."
            )

        # Consequence only sharpens a band that is already saying something.
        # An asset with years of runway is low risk on timing however important
        # it is, and escalating it there would push most of a sensitive estate
        # into MEDIUM permanently, which tells a planner nothing.
        if base != RiskCategory.LOW and criticality in (
            BusinessCriticality.CRITICAL, BusinessCriticality.HIGH
        ):
            escalated = cls._ESCALATION[
                min(len(cls._ESCALATION) - 1, cls._ESCALATION.index(base) + 1)
            ]
            if escalated != base:
                why += (
                    f" Raised to {escalated.value} for "
                    f"{criticality.value.lower()} business criticality."
                )
            base = escalated

        return base, why

    # ---------------------------------------------------------- evaluate

    @classmethod
    def evaluate_artefact(
        cls,
        art: CryptographicArtefact,
        global_z: float = DEFAULT_Z_YEARS,
        today: Optional[date] = None,
        profile: DataSensitivityProfile = DataSensitivityProfile.FINANCIAL,
        retention_override: Optional[float] = None,
    ) -> MoscaRiskAssessment:
        today = today or date.today()

        # X and Y are read off the artefact, never re-derived here. Deriving them
        # is prepare_artefact's job and the pipeline calls it explicitly, so an
        # artefact reloaded from storage keeps the inputs it was audited with
        # rather than having them silently rewritten by a later run under a
        # different profile. Changing the profile is an explicit re-preparation.
        x = art.data_shelf_life_years
        y = art.migration_time_years
        z = global_z
        x_plus_y = round(x + y, 2)
        margin = round(z - x_plus_y, 2)
        crqc_on = years_from(today, z)

        verdicts: List[ModelVerdict] = [
            cls._mosca(x, y, z, today),
            cls._probabilistic(x, y, today),
            cls._hndl(x, y, z),
        ]
        regulatory = cls._regulatory(art, y, today)
        if regulatory is not None:
            verdicts.append(regulatory)

        prob = next(v for v in verdicts if v.model == RiskModel.PROBABILISTIC)
        hndl = next(v for v in verdicts if v.model == RiskModel.HNDL)

        # The binding model is whichever demands the earliest start.
        scheduled = [v for v in verdicts if v.must_start_by is not None]
        binding = min(scheduled, key=lambda v: v.must_start_by) if scheduled else None

        def finish(
            category: RiskCategory,
            explanation: str,
            affected: str,
            exposure_text: str,
            at_risk: Optional[bool] = None,
            quantum_safe: bool = False,
        ) -> MoscaRiskAssessment:
            # A safe asset's models are reported as inapplicable rather than as
            # numbers. Left alone they read as real exposure: the probabilistic
            # verdict would say protection "lapses" at X+Y when it does not, and
            # the HNDL verdict would claim years of harvestable data for traffic
            # a quantum computer cannot read.
            verdict_list = verdicts
            if quantum_safe:
                verdict_list = [
                    ModelVerdict(
                        model=v.model,
                        at_risk=False,
                        detail="Not applicable: this asset is quantum-safe.",
                        source=v.source,
                    )
                    for v in verdicts
                ]
            return MoscaRiskAssessment(
                artefact_id=art.id,
                shelf_life_x=x,
                migration_time_y=y,
                threat_timeline_z=z,
                x_plus_y=x_plus_y,
                is_at_risk=(x_plus_y > z) if at_risk is None else at_risk,
                safety_margin_years=margin,
                risk_category=category,
                explanation=explanation,
                affected_data_type=affected,
                system_exposure=exposure_text,
                model_verdicts=verdict_list,
                binding_model=None if quantum_safe else (binding.model if binding else None),
                must_start_by=None if quantum_safe else (binding.must_start_by if binding else None),
                must_complete_by=None if quantum_safe else (binding.must_complete_by if binding else None),
                slack_years=None if quantum_safe else (binding.slack_years if binding else None),
                is_overdue=bool(not quantum_safe and binding
                                and binding.slack_years is not None
                                and binding.slack_years < 0),
                assessed_on=today,
                crqc_estimated_on=crqc_on,
                breach_probability_low=None if quantum_safe else prob.probability_low,
                breach_probability_high=None if quantum_safe else prob.probability_high,
                probability_source=None if quantum_safe else prob.source,
                hndl_exposure_years=0.0 if quantum_safe else max(0.0, round(x_plus_y - z, 2)),
                crypto_usage=art.crypto_usage,
                shelf_life_rationale=art.shelf_life_rationale,
                migration_time_explanation=(
                    (art.migration_time_breakdown or {}).get("explanation")
                ),
            )

        # 1. Already quantum-safe. Mosca's inequality does not apply.
        #
        # This used to test algorithm_class alone, which catches a post-quantum
        # algorithm but not AES-256 or SHA-384 — those are quantum-safe by
        # having enough key or digest length, which is recorded in
        # quantum_vulnerability rather than in the class. They therefore fell
        # through to slack banding and were reported as high risk directly
        # beside a "Quantum-safe" badge, which is the inequality being applied
        # to an asset it says nothing about.
        #
        # A regulatory deadline can still bind on an otherwise safe asset, so
        # that one case falls through rather than being silently cleared.
        if cls._is_quantum_safe(art):
            regulatory = cls._regulatory(art, y, today)
            if regulatory is None or not regulatory.at_risk:
                return finish(
                    RiskCategory.LOW,
                    cls._safe_explanation(art),
                    "Quantum-protected cryptographic payload",
                    "Low risk / no quantum migration required",
                    # X + Y > Z is arithmetically true for a long-lived secret
                    # under any horizon, but the inequality describes exposure to
                    # Shor and Grover. An algorithm neither of them breaks is not
                    # at risk however the numbers fall out.
                    at_risk=False,
                    quantum_safe=True,
                )

        # 2. Classically broken. The quantum horizon is irrelevant — this is
        #    already exploitable today, and the regulatory deadline has passed.
        if is_classically_broken(art):
            return finish(
                RiskCategory.CRITICAL,
                "Broken by classical cryptanalysis and already disallowed by "
                "NIST SP 800-131A. This is overdue remediation, not a quantum "
                "migration — no horizon makes it acceptable.",
                "High-risk legacy data and insecure channels",
                "Immediate: exploitable with today's hardware",
            )

        # 3. Everything else is banded on the binding model's slack.
        slack = binding.slack_years if binding and binding.slack_years is not None else margin
        category, why = cls._band(slack, art.business_criticality)

        if binding is not None:
            why += (
                f" Binding constraint: {binding.model.value} — "
                f"start by {binding.must_start_by.isoformat()}, "
                f"complete by {binding.must_complete_by.isoformat()}."
            )

        # Attribute the quantum mechanism and describe the exposure.
        if art.algorithm_class in (
            AlgorithmClass.ASYMMETRIC_FACTORING,
            AlgorithmClass.ASYMMETRIC_DISCRETE_LOG,
        ):
            why += (
                " Shor's algorithm breaks this primitive outright rather than "
                "weakening it."
            )
            affected = "Asymmetric keys, digital signatures, TLS handshakes"
            exposure = (
                f"Harvest-now-decrypt-later: {hndl.detail}"
                if hndl.at_risk
                else "Vulnerable to Shor's algorithm, but not exposed at this horizon"
            )
        elif art.algorithm_class == AlgorithmClass.SYMMETRIC:
            if art.key_size_bits and art.key_size_bits <= 128:
                why += (
                    " Grover's algorithm halves the effective key length, "
                    "leaving 64-bit security."
                )
                affected = "Symmetric encrypted data at rest and in transit"
                exposure = "Vulnerable to quantum brute-force key recovery"
            else:
                affected = "Bulk encrypted storage"
                exposure = "AES-256 retains a 128-bit margin after Grover"
        elif art.algorithm_class == AlgorithmClass.HASH:
            why += (
                " Grover preimage search and Brassard-Hoyer-Tapp collision "
                "search both apply."
            )
            affected = "Integrity digests and message authentication codes"
            exposure = "Risk of quantum-accelerated preimage or collision forgery"
        else:
            affected = "Cryptographic infrastructure asset"
            exposure = "General quantum transition exposure"

        return finish(category, why, affected, exposure)

    @classmethod
    def evaluate_all(
        cls,
        artefacts: List[CryptographicArtefact],
        global_z: float = DEFAULT_Z_YEARS,
        today: Optional[date] = None,
        profile: DataSensitivityProfile = DataSensitivityProfile.FINANCIAL,
        retention_override: Optional[float] = None,
    ) -> Dict[str, MoscaRiskAssessment]:
        today = today or date.today()
        return {
            art.id: cls.evaluate_artefact(
                art, global_z=global_z, today=today, profile=profile,
                retention_override=retention_override,
            )
            for art in artefacts
        }
