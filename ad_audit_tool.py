from __future__ import annotations
import argparse
import csv
import os
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Dict, Iterable, List, Optional

DATE_FORMATS = [
   "%Y-%m-%d %H:%M:%S",
   "%Y-%m-%d",
   "%m/%d/%Y %H:%M",
   "%m/%d/%Y",
   "%m/%d/%Y %I:%M:%S %p",
   "%m/%d/%Y %I:%M %p",
   "%Y-%m-%dT%H:%M:%S",
   "%Y-%m-%dT%H:%M:%S.%f",
   "%Y-%m-%dT%H:%M:%S%z",
]
TRUE_VALUES = {"true", "yes", "1", "enabled", "active"}
FALSE_VALUES = {"false", "no", "0", "disabled", "inactive"}
PRIVILEGED_GROUP_KEYWORDS = [
   "domain admins",
   "enterprise admins",
   "schema admins",
   "administrators",
   "account operators",
   "server operators",
   "backup operators",
   "print operators",
   "dnsadmins",
   "group policy creator owners",
]

@dataclass
class AuditResult:
   inactive_accounts: List[Dict[str, Any]]
   stale_passwords: List[Dict[str, Any]]
   never_logged_in: List[Dict[str, Any]]
   expired_accounts: List[Dict[str, Any]]
   privileged_accounts: List[Dict[str, Any]]
   total_users: int
   enabled_users: int
   disabled_users: int

class ADAuditTool:
   def __init__(self, inactive_days: int = 90, password_days: int = 180) -> None:
       self.inactive_days = inactive_days
       self.password_days = password_days
       self.now = datetime.now()
   def load_csv(self, file_path: str) -> List[Dict[str, Any]]:
       if not os.path.exists(file_path):
           raise FileNotFoundError(f"Input file not found: {file_path}")
       with open(file_path, "r", encoding="utf-8-sig", newline="") as f:
           reader = csv.DictReader(f)
           rows = [self._normalize_row(row) for row in reader]
       if not rows:
           raise ValueError("CSV appears to be empty or unreadable.")
       return rows
   def _normalize_row(self, row: Dict[str, str]) -> Dict[str, Any]:
       normalized = {self._clean_key(k): (v.strip() if isinstance(v, str) else v) for k, v in row.items()}
       return normalized
   def _clean_key(self, key: Optional[str]) -> str:
       if not key:
           return ""
       return "".join(ch.lower() for ch in key if ch.isalnum())
   def _get_value(self, row: Dict[str, Any], aliases: Iterable[str], default: Any = "") -> Any:
       for alias in aliases:
           clean_alias = self._clean_key(alias)
           if clean_alias in row and row[clean_alias] not in (None, ""):
               return row[clean_alias]
       return default
   def _parse_bool(self, value: Any, default: bool = True) -> bool:
       if isinstance(value, bool):
           return value
       if value is None:
           return default
       text = str(value).strip().lower()
       if text in TRUE_VALUES:
           return True
       if text in FALSE_VALUES:
           return False
       return default
   def _parse_date(self, value: Any) -> Optional[datetime]:
       if value in (None, "", "never", "n/a", "null"):
           return None
       text = str(value).strip()
       # Some exports may use Windows filetime as an integer.
       if text.isdigit() and len(text) >= 16:
           try:
               filetime = int(text)
               if filetime == 0:
                   return None
               return datetime(1601, 1, 1) + timedelta(microseconds=filetime // 10)
           except Exception:
               pass
       for fmt in DATE_FORMATS:
           try:
               dt = datetime.strptime(text, fmt)
               return dt.replace(tzinfo=None)
           except ValueError:
               continue
       return None
   def _user_record(self, row: Dict[str, Any]) -> Dict[str, Any]:
       username = self._get_value(row, ["SamAccountName", "sAMAccountName", "Username", "UserLogonName", "User"])
       name = self._get_value(row, ["Name", "DisplayName", "FullName"])
       enabled_raw = self._get_value(row, ["Enabled", "AccountEnabled", "IsEnabled"], default="true")
       last_logon_raw = self._get_value(row, ["LastLogonDate", "Last Logon", "LastLogon", "LastSignInDateTime"])
       pwd_last_set_raw = self._get_value(row, ["PasswordLastSet", "PwdLastSet", "Password Last Set"])
       expires_raw = self._get_value(row, ["AccountExpirationDate", "Account Expires", "ExpirationDate"])
       groups = self._get_value(row, ["MemberOf", "Groups", "GroupMembership"], default="")
       department = self._get_value(row, ["Department"])
       title = self._get_value(row, ["Title", "JobTitle"])
       email = self._get_value(row, ["EmailAddress", "Mail", "Email"])
       dn = self._get_value(row, ["DistinguishedName", "OU"])
       return {
           "username": username,
           "name": name,
           "enabled": self._parse_bool(enabled_raw, default=True),
           "last_logon": self._parse_date(last_logon_raw),
           "password_last_set": self._parse_date(pwd_last_set_raw),
           "account_expires": self._parse_date(expires_raw),
           "groups": groups,
           "department": department,
           "title": title,
           "email": email,
           "distinguished_name": dn,
       }
   def audit_users(self, rows: List[Dict[str, Any]]) -> AuditResult:
       inactive_accounts: List[Dict[str, Any]] = []
       stale_passwords: List[Dict[str, Any]] = []
       never_logged_in: List[Dict[str, Any]] = []
       expired_accounts: List[Dict[str, Any]] = []
       privileged_accounts: List[Dict[str, Any]] = []
       enabled_users = 0
       disabled_users = 0
       for row in rows:
           user = self._user_record(row)
           if user["enabled"]:
               enabled_users += 1
           else:
               disabled_users += 1
           self._check_inactive(user, inactive_accounts)
           self._check_stale_password(user, stale_passwords)
           self._check_never_logged_in(user, never_logged_in)
           self._check_expired(user, expired_accounts)
           self._check_privileged(user, privileged_accounts)
       return AuditResult(
           inactive_accounts=inactive_accounts,
           stale_passwords=stale_passwords,
           never_logged_in=never_logged_in,
           expired_accounts=expired_accounts,
           privileged_accounts=privileged_accounts,
           total_users=len(rows),
           enabled_users=enabled_users,
           disabled_users=disabled_users,
       )
   def _days_since(self, dt: Optional[datetime]) -> Optional[int]:
       if not dt:
           return None
       return (self.now - dt).days
   def _check_inactive(self, user: Dict[str, Any], bucket: List[Dict[str, Any]]) -> None:
       if not user["enabled"]:
           return
       days = self._days_since(user["last_logon"])
       if days is not None and days >= self.inactive_days:
           record = dict(user)
           record["days_since_last_logon"] = days
           bucket.append(record)
   def _check_stale_password(self, user: Dict[str, Any], bucket: List[Dict[str, Any]]) -> None:
       if not user["enabled"]:
           return
       days = self._days_since(user["password_last_set"])
       if days is not None and days >= self.password_days:
           record = dict(user)
           record["days_since_password_change"] = days
           bucket.append(record)
   def _check_never_logged_in(self, user: Dict[str, Any], bucket: List[Dict[str, Any]]) -> None:
       if not user["enabled"]:
           return
       if user["last_logon"] is None:
           bucket.append(dict(user))
   def _check_expired(self, user: Dict[str, Any], bucket: List[Dict[str, Any]]) -> None:
       expires = user["account_expires"]
       if expires and expires < self.now:
           record = dict(user)
           record["expired_days_ago"] = (self.now - expires).days
           bucket.append(record)
   def _check_privileged(self, user: Dict[str, Any], bucket: List[Dict[str, Any]]) -> None:
       groups_text = str(user.get("groups", "")).lower()
       matched = [kw for kw in PRIVILEGED_GROUP_KEYWORDS if kw in groups_text]
       if matched:
           record = dict(user)
           record["matched_privileged_groups"] = "; ".join(matched)
           bucket.append(record)
   def write_csv(self, file_path: str, rows: List[Dict[str, Any]]) -> None:
       if not rows:
           with open(file_path, "w", encoding="utf-8", newline="") as f:
               writer = csv.writer(f)
               writer.writerow(["message"])
               writer.writerow(["No records found"])
           return
       fieldnames: List[str] = []
       seen = set()
       for row in rows:
           for key in row.keys():
               if key not in seen:
                   seen.add(key)
                   fieldnames.append(key)
       with open(file_path, "w", encoding="utf-8", newline="") as f:
           writer = csv.DictWriter(f, fieldnames=fieldnames)
           writer.writeheader()
           for row in rows:
               serializable = {
                   k: self._serialize_value(v)
                   for k, v in row.items()
               }
               writer.writerow(serializable)
   def _serialize_value(self, value: Any) -> Any:
       if isinstance(value, datetime):
           return value.strftime("%Y-%m-%d %H:%M:%S")
       return value
   def write_summary(self, result: AuditResult, file_path: str) -> None:
       lines = [
           "ACTIVE DIRECTORY AUDIT SUMMARY",
           "=" * 32,
           f"Generated: {self.now.strftime('%Y-%m-%d %H:%M:%S')}",
           "",
           f"Total users: {result.total_users}",
           f"Enabled users: {result.enabled_users}",
           f"Disabled users: {result.disabled_users}",
           "",
           f"Inactive accounts (>{self.inactive_days} days): {len(result.inactive_accounts)}",
           f"Stale passwords (>{self.password_days} days): {len(result.stale_passwords)}",
           f"Never logged in: {len(result.never_logged_in)}",
           f"Expired accounts: {len(result.expired_accounts)}",
           f"Potentially privileged accounts: {len(result.privileged_accounts)}",
           "",
           "Recommended review order:",
           "1. Privileged accounts",
           "2. Expired enabled accounts",
           "3. Never logged in enabled accounts",
           "4. Inactive enabled accounts",
           "5. Stale passwords",
       ]
       with open(file_path, "w", encoding="utf-8") as f:
           f.write("\n".join(lines))

def parse_args() -> argparse.Namespace:
   parser = argparse.ArgumentParser(description="Audit Active Directory users from CSV export.")
   parser.add_argument("--input", required=True, help="Path to AD export CSV file")
   parser.add_argument("--inactive-days", type=int, default=90, help="Days since last logon to flag inactive accounts")
   parser.add_argument("--password-days", type=int, default=180, help="Days since password change to flag stale passwords")
   parser.add_argument("--output-dir", default="ad_audit_output", help="Directory to save audit files")
   return parser.parse_args()

def ensure_output_dir(path: str) -> None:
   os.makedirs(path, exist_ok=True)

def main() -> None:
   args = parse_args()
   ensure_output_dir(args.output_dir)
   auditor = ADAuditTool(inactive_days=args.inactive_days, password_days=args.password_days)
   rows = auditor.load_csv(args.input)
   result = auditor.audit_users(rows)
   summary_path = os.path.join(args.output_dir, "audit_summary.txt")
   inactive_path = os.path.join(args.output_dir, "inactive_accounts.csv")
   stale_pwd_path = os.path.join(args.output_dir, "stale_passwords.csv")
   never_logged_in_path = os.path.join(args.output_dir, "never_logged_in.csv")
   expired_path = os.path.join(args.output_dir, "expired_accounts.csv")
   privileged_path = os.path.join(args.output_dir, "privileged_accounts.csv")
   auditor.write_summary(result, summary_path)
   auditor.write_csv(inactive_path, result.inactive_accounts)
   auditor.write_csv(stale_pwd_path, result.stale_passwords)
   auditor.write_csv(never_logged_in_path, result.never_logged_in)
   auditor.write_csv(expired_path, result.expired_accounts)
   auditor.write_csv(privileged_path, result.privileged_accounts)
   print("AD audit complete.")
   print(f"Summary: {summary_path}")
   print(f"Inactive accounts: {inactive_path}")
   print(f"Stale passwords: {stale_pwd_path}")
   print(f"Never logged in: {never_logged_in_path}")
   print(f"Expired accounts: {expired_path}")
   print(f"Privileged accounts: {privileged_path}")

if __name__ == "__main__":
   main()