import uuid
from datetime import datetime, timezone
from typing import List, Dict, Any
from backend.models import CryptographicArtefact, ArtefactType


class CBOMBuilder:
    """
    Constructs standardized Cryptography Bill of Materials (CBOM) compliant
    with the CycloneDX 1.6 Cryptography Specification.
    """

    @staticmethod
    def build_cyclonedx_cbom(
        artefacts: List[CryptographicArtefact],
        target_name: str = "Enterprise-System",
        scan_id: str = None
    ) -> Dict[str, Any]:
        """Generate a valid CycloneDX 1.6 CBOM document."""
        bom_serial = f"urn:uuid:{uuid.uuid4()}"
        timestamp = datetime.now(timezone.utc).isoformat()

        components: List[Dict[str, Any]] = []
        vulnerabilities: List[Dict[str, Any]] = []

        for art in artefacts:
            comp_type = "cryptographic-asset"
            if art.type == ArtefactType.LIBRARY:
                comp_type = "library"
            elif art.type == ArtefactType.PROTOCOL:
                comp_type = "protocol"
            elif art.type == ArtefactType.HARDWARE_MODULE:
                comp_type = "device"

            crypto_props: Dict[str, Any] = {
                "assetType": art.type.value,
                "algorithmProperties": {
                    "algorithmFamily": art.algorithm_family,
                    "algorithmClass": art.algorithm_class.value,
                    "keyLength": art.key_size_bits,
                    "curve": art.curve,
                    "mode": art.mode_or_padding,
                    "quantumVulnerability": art.quantum_vulnerability.value,
                    "brokenBy": art.broken_by
                },
                "classification": {
                    "businessCriticality": art.business_criticality.value,
                    "dataShelfLifeYears": art.data_shelf_life_years,
                    "estimatedMigrationYears": art.migration_time_years,
                    "lifetime": art.artefact_lifetime,
                    # A consumer of this CBOM has to be able to tell why X and Y
                    # are what they are. Emitting the numbers without their
                    # derivation makes them unauditable.
                    "cryptoUsage": art.crypto_usage.value,
                    "shelfLifeRationale": art.shelf_life_rationale,
                    "migrationEstimateBasis": (
                        (art.migration_time_breakdown or {}).get("explanation")
                    ),
                }
            }

            if art.hardware_module_ref:
                crypto_props["hardwareReference"] = art.hardware_module_ref
            if art.cloud_service_ref:
                crypto_props["cloudKmsReference"] = art.cloud_service_ref

            component = {
                "bom-ref": art.id,
                "type": comp_type,
                "name": art.name,
                "version": art.version or "1.0",
                "evidence": {
                    "occurrences": [
                        {
                            "location": art.location,
                            "line": art.line_number,
                            "snippet": art.code_snippet
                        }
                    ]
                },
                "cryptoProperties": crypto_props
            }

            # purl is a first-class CycloneDX field and the identifier every
            # vulnerability service keys off. Without it the dependency half of
            # the BOM names packages but cannot be machine-resolved.
            if art.purl:
                component["purl"] = art.purl
                if art.version_is_range:
                    component.setdefault("properties", []).append({
                        "name": "ecdat:version_specifier",
                        "value": "range — the manifest pinned a range, not an exact version",
                    })

            components.append(component)

            # CycloneDX models advisories in a top-level vulnerabilities array
            # that references components by bom-ref, rather than nesting them.
            for vuln in art.known_vulnerabilities:
                entry: Dict[str, Any] = {
                    "bom-ref": f"{art.id}:{vuln.id}",
                    "id": vuln.id,
                    "source": {"name": "OSV", "url": vuln.reference_url or "https://osv.dev"},
                    "affects": [{"ref": art.id}],
                }
                if vuln.summary:
                    entry["description"] = vuln.summary
                if vuln.aliases:
                    entry["references"] = [
                        {"id": alias, "source": {"name": "Alias"}} for alias in vuln.aliases
                    ]
                if vuln.severity and vuln.severity != "Unknown":
                    entry["ratings"] = [{"severity": vuln.severity.lower(), "method": "other"}]
                if vuln.fixed_version:
                    entry["recommendation"] = f"Upgrade to {vuln.fixed_version} or later."
                vulnerabilities.append(entry)

        cbom_document = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "serialNumber": bom_serial,
            "version": 1,
            "metadata": {
                "timestamp": timestamp,
                "tools": [
                    {
                        "vendor": "National Technical Research Organisation (NTRO)",
                        "name": "Enterprise Cryptographic Discovery & Analysis Tool (ECDAT)",
                        "version": "1.0.0"
                    }
                ],
                "component": {
                    "name": target_name,
                    "type": "application",
                    "bom-ref": scan_id or str(uuid.uuid4())
                },
                "properties": [
                    {"name": "ecdat:standard", "value": "CycloneDX-CBOM-v1.6"},
                    {"name": "ecdat:total_assets", "value": str(len(artefacts))}
                ]
            },
            "components": components
        }

        # Only emitted when advisories were actually found, so an absent array
        # is not read as "checked and clean".
        if vulnerabilities:
            cbom_document["vulnerabilities"] = vulnerabilities

        return cbom_document
