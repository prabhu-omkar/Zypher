import os
import json
import uuid
import hashlib
import hmac
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError
from backend.models import DatabaseConfig, ScanResult
from backend.cbom import artefact_register


class EnterpriseStorageManager:
    """
    Manages Enterprise-Owned MongoDB Atlas storage (Bring-Your-Own-Key, NFR1/NFR2),
    with standalone fallback mode, admin authentication, and multi-scan aggregation.
    """

    PBKDF2_ITERATIONS = 600000

    # Read scopes. "own" is what the application shows normally; "all" is only
    # reachable with an unlocked admin session.
    SCOPE_OWN = "own"
    SCOPE_ALL = "all"

    def __init__(self, data_dir: str = "./data_store"):
        self.data_dir = data_dir
        os.makedirs(self.data_dir, exist_ok=True)
        self._installation_id: Optional[str] = None
        self.client: Optional[MongoClient] = None
        self.db = None
        self.config = DatabaseConfig(
            mongo_uri="",
            is_connected=False,
            is_standalone_fallback=True,
            last_validated_at=None
        )

    def configure_mongo(self, mongo_uri: str, db_name: str = "ecdat_enterprise_inventory") -> Dict[str, Any]:
        """Validate and connect to enterprise-supplied MongoDB Atlas instance."""
        if not mongo_uri or not mongo_uri.strip():
            # Enable standalone fallback mode
            self.client = None
            self.db = None
            self.config.is_connected = False
            self.config.is_standalone_fallback = True
            self.config.mongo_uri = ""
            return {
                "success": True,
                "mode": "standalone_local",
                "message": "Operate in Standalone Local Storage Mode (Offline/Demo Mode)."
            }

        try:
            client = MongoClient(mongo_uri, serverSelectionTimeoutMS=5000)
            # Send a ping to confirm a successful connection
            client.admin.command('ping')
            
            self.client = client
            self.db = self.client[db_name]
            self.config.mongo_uri = mongo_uri
            self.config.database_name = db_name
            self.config.is_connected = True
            self.config.is_standalone_fallback = False
            self.config.last_validated_at = datetime.now(timezone.utc)

            # Ensure collections and indexes
            self.db["scans"].create_index("scan_id", unique=True)
            self.db["admin_auth"].create_index("username", unique=True)
            # The artefact register. There used to be an index on this
            # collection and nothing that ever wrote to it, so an estate-wide
            # question could only be answered by loading every scan document
            # into memory and filtering in Python. These are the fields the
            # admin views actually filter and sort on.
            artefacts = self.db["artefacts"]
            artefacts.create_index("scan_id")
            artefacts.create_index("installation_id")
            artefacts.create_index("risk_category")
            artefacts.create_index("must_start_by")
            artefacts.create_index("algorithm_family")
            artefacts.create_index("quantum_vulnerability")
            artefacts.create_index([("system_name", 1), ("name", 1)])

            return {
                "success": True,
                "mode": "enterprise_mongodb_atlas",
                "message": f"Successfully connected and validated enterprise MongoDB Atlas instance: {db_name}"
            }
        except (ConnectionFailure, ServerSelectionTimeoutError, Exception) as e:
            self.config.is_connected = False
            self.config.is_standalone_fallback = True
            return {
                "success": False,
                "mode": "connection_failed",
                "error": str(e),
                "message": f"Failed to connect to MongoDB Atlas instance: {str(e)}"
            }

    # --- INSTALLATION IDENTITY ---------------------------------------------
    #
    # A shared database is shared: without this, pointing two installations at
    # the same MongoDB made every scan visible to both. Each scan is stamped
    # with the installation that produced it, and an ordinary read only returns
    # the ones this installation wrote. Unlocking admin drops the filter.
    #
    # This is application-level scoping, not encryption. Anyone holding the
    # connection string can still read the collection with a Mongo client —
    # closing that off is a database-credentials question, not one this layer
    # can answer.

    @property
    def installation_id(self) -> str:
        """A stable id for this install, generated once and kept on disk."""
        if self._installation_id:
            return self._installation_id

        path = os.path.join(self.data_dir, "installation.json")
        try:
            if os.path.exists(path):
                with open(path, "r", encoding="utf-8") as f:
                    stored = json.load(f).get("installation_id")
                if stored:
                    self._installation_id = stored
                    return stored
        except Exception:
            pass

        new_id = uuid.uuid4().hex
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump({
                    "installation_id": new_id,
                    "created_at": datetime.now(timezone.utc).isoformat(),
                }, f, indent=2)
        except Exception as e:
            # A read-only data directory must not stop the tool working; the id
            # simply does not survive a restart, which scopes reads more
            # tightly rather than more loosely.
            print(f"Could not persist installation id: {e}")
        self._installation_id = new_id
        return new_id

    def _owns(self, summary: Dict[str, Any], from_database: bool) -> bool:
        """
        Whether a stored scan belongs to this installation.

        A scan with no installation id predates the field. On local disk that
        means it is this installation's — it is in this install's own data
        directory. In a shared database it means the origin is unknown, so it
        stays hidden until an admin unlocks the estate. Ambiguity resolves
        towards showing less, never more.
        """
        owner = (summary or {}).get("installation_id")
        if owner is None:
            return not from_database
        return owner == self.installation_id

    def _scope_query(self, scope: str, field: str = "summary.installation_id") -> Dict[str, Any]:
        """The database filter for a scope. Empty when the estate is unlocked."""
        if scope == self.SCOPE_ALL:
            return {}
        return {field: self.installation_id}

    def get_status(self) -> DatabaseConfig:
        return self.config

    # --- ADMIN AUTHENTICATION (PBKDF2 Hashing) ---
    def _hash_password(self, password: str, salt: bytes) -> str:
        key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, self.PBKDF2_ITERATIONS)
        return key.hex()

    def is_admin_setup(self) -> bool:
        """Check if an admin password has been set in MongoDB Atlas or local store."""
        if self.config.is_connected and self.db is not None:
            try:
                record = self.db["admin_auth"].find_one({"username": "admin"})
                return record is not None
            except Exception:
                pass
        
        # Local fallback auth file
        local_auth_file = os.path.join(self.data_dir, "admin_auth.json")
        return os.path.exists(local_auth_file)

    def setup_admin_password(self, password: str) -> bool:
        """Create and store salted PBKDF2 hash of admin password in the enterprise database."""
        salt = os.urandom(32)
        pwd_hash = self._hash_password(password, salt)
        record = {
            "username": "admin",
            "algorithm": "PBKDF2-HMAC-SHA256",
            "iterations": self.PBKDF2_ITERATIONS,
            "salt": salt.hex(),
            "password_hash": pwd_hash,
            "created_at": datetime.now(timezone.utc).isoformat()
        }

        if self.config.is_connected and self.db is not None:
            try:
                self.db["admin_auth"].update_one(
                    {"username": "admin"},
                    {"$set": record},
                    upsert=True
                )
                return True
            except Exception as e:
                print(f"Error saving admin auth to MongoDB: {e}")

        # Local fallback
        local_auth_file = os.path.join(self.data_dir, "admin_auth.json")
        try:
            with open(local_auth_file, "w", encoding="utf-8") as f:
                json.dump(record, f, indent=2)
            return True
        except Exception as e:
            print(f"Error saving local admin auth: {e}")
            return False

    def verify_admin_password(self, password: str) -> bool:
        """Verify password against stored salt and hash using constant-time comparison."""
        record = None
        if self.config.is_connected and self.db is not None:
            try:
                record = self.db["admin_auth"].find_one({"username": "admin"}, {"_id": 0})
            except Exception:
                pass

        if not record:
            local_auth_file = os.path.join(self.data_dir, "admin_auth.json")
            if os.path.exists(local_auth_file):
                try:
                    with open(local_auth_file, "r", encoding="utf-8") as f:
                        record = json.load(f)
                except Exception:
                    pass

        if not record or "salt" not in record or "password_hash" not in record:
            return False

        salt = bytes.fromhex(record["salt"])
        computed_hash = self._hash_password(password, salt)
        return hmac.compare_digest(computed_hash, record["password_hash"])

    # --- SCAN STORAGE ---
    def save_scan_result(self, scan_result: ScanResult) -> bool:
        """Persist scan result into MongoDB Atlas or fallback local store."""
        data = scan_result.model_dump(mode="json")
        scan_id = scan_result.summary.scan_id

        # 1. MongoDB Atlas Storage
        if self.config.is_connected and self.db is not None:
            try:
                self.db["scans"].update_one(
                    {"scan_id": scan_id},
                    {"$set": data},
                    upsert=True
                )
                self._index_artefacts(data)
                return True
            except Exception as e:
                print(f"Error persisting to MongoDB Atlas: {e}")

        # 2. Local Fallback Persistence
        file_path = os.path.join(self.data_dir, f"scan_{scan_id}.json")
        try:
            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, default=str)
            return True
        except Exception as e:
            print(f"Error persisting locally: {e}")
            return False

    def get_scan_result(self, scan_id: str, scope: str = SCOPE_OWN) -> Optional[Dict[str, Any]]:
        """
        Retrieve one scan, if this scope is allowed to see it.

        A scan belonging to another installation reads as absent rather than
        forbidden: the caller is not entitled to know it exists.
        """
        if self.config.is_connected and self.db is not None:
            try:
                query = {"scan_id": scan_id}
                query.update(self._scope_query(scope))
                doc = self.db["scans"].find_one(query, {"_id": 0})
                if doc:
                    return doc
            except Exception:
                pass

        file_path = os.path.join(self.data_dir, f"scan_{scan_id}.json")
        if os.path.exists(file_path):
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                if scope == self.SCOPE_ALL or self._owns(
                    data.get("summary"), from_database=False
                ):
                    return data
            except Exception:
                pass
        return None

    def delete_scan_result(self, scan_id: str, scope: str = SCOPE_OWN) -> bool:
        """
        Remove a stored scan.

        Scoped for the same reason reads are: without it, a shared database
        lets any installation delete another's work.
        """
        deleted = False
        if self.config.is_connected and self.db is not None:
            try:
                query = {"scan_id": scan_id}
                query.update(self._scope_query(scope))
                deleted = self.db["scans"].delete_one(query).deleted_count > 0
                # The register is derived from the scans, so it has to go with
                # them. Rows left behind would show assets from a deleted scan.
                self.db["artefacts"].delete_many({"scan_id": scan_id})
            except Exception as e:
                print(f"Error deleting from MongoDB Atlas: {e}")

        file_path = os.path.join(self.data_dir, f"scan_{scan_id}.json")
        if os.path.exists(file_path) and self.get_scan_result(scan_id, scope) is not None:
            try:
                os.remove(file_path)
                deleted = True
            except OSError as e:
                print(f"Error deleting local scan file: {e}")
        return deleted

    def list_all_scans(self, scope: str = SCOPE_OWN) -> List[Dict[str, Any]]:
        """Summaries of the scans this scope can see."""
        scans: List[Dict[str, Any]] = []
        if self.config.is_connected and self.db is not None:
            try:
                cursor = self.db["scans"].find(
                    self._scope_query(scope), {"summary": 1, "_id": 0}
                ).sort("summary.created_at", -1)
                return [
                    doc["summary"] for doc in cursor
                    if "summary" in doc
                    and (scope == self.SCOPE_ALL
                         or self._owns(doc["summary"], from_database=True))
                ]
            except Exception:
                pass

        for file in os.listdir(self.data_dir):
            if file.startswith("scan_") and file.endswith(".json"):
                try:
                    with open(os.path.join(self.data_dir, file), "r", encoding="utf-8") as f:
                        data = json.load(f)
                        summary = data.get("summary")
                        if summary and (scope == self.SCOPE_ALL
                                        or self._owns(summary, from_database=False)):
                            scans.append(summary)
                except Exception:
                    pass

        # Sort by creation timestamp descending
        scans.sort(key=lambda s: s.get("created_at", ""), reverse=True)
        return scans

    # --- ESTATE-WIDE ARTEFACT REGISTER -------------------------------------

    def _index_artefacts(self, data):
        """Replace this scan's rows in the register. A no-op without MongoDB."""
        if not (self.config.is_connected and self.db is not None):
            return
        scan_id = data.get("summary", {}).get("scan_id")
        if not scan_id:
            return
        try:
            # Replace rather than merge: rescanning the same target must not
            # leave rows behind for assets that no longer exist.
            self.db["artefacts"].delete_many({"scan_id": scan_id})
            rows = artefact_register.rows_for_scan(data)
            if rows:
                self.db["artefacts"].insert_many(rows, ordered=False)
        except Exception as e:
            print(f"Error indexing artefacts: {e}")

    def _iter_local_scans(self):
        """Yield each stored scan one at a time, rather than all at once."""
        try:
            names = sorted(os.listdir(self.data_dir))
        except OSError:
            return
        for file in names:
            if not (file.startswith("scan_") and file.endswith(".json")):
                continue
            try:
                with open(os.path.join(self.data_dir, file), "r", encoding="utf-8") as f:
                    yield json.load(f)
            except Exception:
                continue

    def rebuild_artefact_register(self) -> int:
        """
        Re-project every stored scan into the register.

        Needed once after connecting a database that already holds scans written
        before the register existed, and harmless to run again.
        """
        if not (self.config.is_connected and self.db is not None):
            return 0
        indexed = 0
        try:
            self.db["artefacts"].delete_many({})
            for doc in self.db["scans"].find({}, {"_id": 0}):
                rows = artefact_register.rows_for_scan(doc)
                if rows:
                    self.db["artefacts"].insert_many(rows, ordered=False)
                    indexed += len(rows)
        except Exception as e:
            print(f"Error rebuilding artefact register: {e}")
        return indexed

    def query_artefacts(
        self,
        page: int = 1,
        page_size: int = 50,
        sort_by: str = "risk",
        scope: str = SCOPE_OWN,
        **filters,
    ):
        """
        One page of the estate-wide asset register.

        Returns the page, the total number of matches, and whether the match set
        hit its cap — never a silently shortened estate.
        """
        page, page_size = artefact_register.clamp_paging(page, page_size)
        criteria = artefact_register.ArtefactFilter(**filters)

        matched = []
        capped = False
        used_database = False

        if self.config.is_connected and self.db is not None:
            try:
                query = criteria.as_mongo_query()
                query.update(self._scope_query(scope, "installation_id"))
                cursor = self.db["artefacts"].find(
                    query, {"_id": 0}
                ).limit(artefact_register.MAX_MATCHED_ROWS + 1)
                for row in cursor:
                    used_database = True
                    # Free-text search is applied here rather than as a database
                    # regex, so both backends agree on what a search means.
                    if not criteria.matches(row):
                        continue
                    if len(matched) >= artefact_register.MAX_MATCHED_ROWS:
                        capped = True
                        break
                    matched.append(row)
            except Exception as e:
                print(f"Error querying artefact register: {e}")
                matched, used_database = [], False

        if not used_database:
            # No database, or a database whose register is empty because these
            # scans predate it. Derive the rows from the stored scans instead.
            for data in self._iter_local_scans():
                if scope != self.SCOPE_ALL and not self._owns(
                    data.get("summary"), from_database=False
                ):
                    continue
                for row in artefact_register.rows_for_scan(data):
                    row.pop("_id", None)
                    if not criteria.matches(row):
                        continue
                    if len(matched) >= artefact_register.MAX_MATCHED_ROWS:
                        capped = True
                        break
                    matched.append(row)
                if capped:
                    break

        return artefact_register.paginate(matched, page, page_size, sort_by, capped)

    def artefact_facets(self, scope: str = SCOPE_OWN):
        """
        The distinct values worth offering as filters, drawn from real rows.

        Scoped like every other read: an unauthenticated caller must not learn
        the names of other installations' systems from a filter dropdown.
        """
        systems, families, vulns = set(), set(), set()

        if self.config.is_connected and self.db is not None:
            try:
                where = self._scope_query(scope, "installation_id")
                systems = set(filter(None, self.db["artefacts"].distinct("system_name", where)))
                families = set(filter(None, self.db["artefacts"].distinct("algorithm_family", where)))
                vulns = set(filter(None, self.db["artefacts"].distinct("quantum_vulnerability", where)))
            except Exception:
                pass

        if not systems and not families:
            for data in self._iter_local_scans():
                if scope != self.SCOPE_ALL and not self._owns(
                    data.get("summary"), from_database=False
                ):
                    continue
                summary = data.get("summary", {})
                if summary.get("target_name"):
                    systems.add(summary["target_name"])
                for art in data.get("artefacts") or []:
                    if art.get("algorithm_family"):
                        families.add(art["algorithm_family"])
                    if art.get("quantum_vulnerability"):
                        vulns.add(art["quantum_vulnerability"])

        return {
            "systems": sorted(systems),
            "algorithm_families": sorted(families),
            "quantum_vulnerabilities": sorted(vulns),
        }

    def get_enterprise_aggregated_metrics(self, scope: str = SCOPE_ALL) -> Dict[str, Any]:
        """
        Aggregate metrics across the scans this scope can see.

        Defaults to the whole estate because the only caller is the admin
        overview, which is already gated behind an unlocked session.
        """
        all_scans_data: List[Dict[str, Any]] = []

        if self.config.is_connected and self.db is not None:
            try:
                cursor = self.db["scans"].find(self._scope_query(scope), {"_id": 0})
                all_scans_data = [
                    doc for doc in cursor
                    if scope == self.SCOPE_ALL
                    or self._owns(doc.get("summary"), from_database=True)
                ]
            except Exception:
                pass

        if not all_scans_data:
            # Fallback to local files
            for data in self._iter_local_scans():
                if scope == self.SCOPE_ALL or self._owns(
                    data.get("summary"), from_database=False
                ):
                    all_scans_data.append(data)

        total_scans = len(all_scans_data)
        total_artefacts = 0
        total_critical_risks = 0
        total_high_risks = 0
        total_medium_risks = 0
        total_low_risks = 0
        readiness_scores = []

        vuln_breakdown = {
            "fully_broken": 0,
            "degraded": 0,
            "classically_broken": 0,
            "quantum_safe": 0,
            "hybrid_protected": 0,
            "unknown": 0
        }

        all_artefacts_master = []
        systems_summary = []

        for s in all_scans_data:
            summary = s.get("summary", {})
            total_artefacts += summary.get("total_artefacts", 0)
            risk_dist = summary.get("risk_distribution", {})
            total_critical_risks += risk_dist.get("Critical", 0)
            total_high_risks += risk_dist.get("High", 0)
            total_medium_risks += risk_dist.get("Medium", 0)
            total_low_risks += risk_dist.get("Low", 0)

            score = summary.get("quantum_readiness_score")
            if score is not None:
                readiness_scores.append(score)

            v_dist = summary.get("vulnerability_distribution", {})
            for k in vuln_breakdown:
                vuln_breakdown[k] += v_dist.get(k, 0)

            systems_summary.append({
                "scan_id": summary.get("scan_id"),
                "system_name": summary.get("target_name"),
                "total_assets": summary.get("total_artefacts", 0),
                "readiness_score": summary.get("quantum_readiness_score", 0),
                "critical_risks": risk_dist.get("Critical", 0),
                "high_risks": risk_dist.get("High", 0),
                "created_at": summary.get("created_at")
            })

            # Tag artefacts with system name
            system_name = summary.get("target_name", "Unknown System")
            scan_id = summary.get("scan_id", "")
            for art in s.get("artefacts", []):
                risk = s.get("risk_assessments", {}).get(art.get("id"), {})
                rec = s.get("recommendations", {}).get(art.get("id"), {})
                all_artefacts_master.append({
                    **art,
                    "system_name": system_name,
                    "scan_id": scan_id,
                    "risk_category": risk.get("risk_category", "Unknown"),
                    "x_plus_y": risk.get("x_plus_y"),
                    "threat_timeline_z": risk.get("threat_timeline_z"),
                    "recommended_pqc": rec.get("recommended_standard", "N/A")
                })

        avg_readiness = round(sum(readiness_scores) / max(1, len(readiness_scores)), 1) if readiness_scores else 0.0

        return {
            "is_cloud_connected": self.config.is_connected,
            "database_name": self.config.database_name if self.config.is_connected else "Local Standalone Store",
            "total_systems_scanned": total_scans,
            "total_enterprise_assets": total_artefacts,
            "average_quantum_readiness": avg_readiness,
            "total_critical_risks": total_critical_risks,
            "total_high_risks": total_high_risks,
            "total_medium_risks": total_medium_risks,
            "total_low_risks": total_low_risks,
            "vulnerability_breakdown": vuln_breakdown,
            "systems_summary": systems_summary,
            "master_artefacts": all_artefacts_master
        }
