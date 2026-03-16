import os
import altair as alt
import pandas as pd
import streamlit as st
from datetime import datetime
st.set_page_config(page_title="AD Audit Dashboard", layout="wide")
st.title("Active Directory Audit Dashboard")
st.caption("Review inactive accounts, stale passwords, expired users, never-logged-in accounts, and privileged memberships from a CSV export.")
DEFAULT_FILE = "ad_users_sample.csv"
DATE_COLUMNS = ["LastLogonDate", "PasswordLastSet", "AccountExpirationDate"]
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

def normalize_columns(df: pd.DataFrame) -> pd.DataFrame:
   rename_map = {}
   for col in df.columns:
       clean = "".join(ch.lower() for ch in str(col) if ch.isalnum())
       rename_map[col] = clean
   return df.rename(columns=rename_map)

def find_column(df: pd.DataFrame, aliases: list[str]) -> str | None:
   for alias in aliases:
       clean_alias = "".join(ch.lower() for ch in alias if ch.isalnum())
       if clean_alias in df.columns:
           return clean_alias
   return None

def parse_bool(series: pd.Series) -> pd.Series:
   true_values = {"true", "yes", "1", "enabled", "active"}
   false_values = {"false", "no", "0", "disabled", "inactive"}
   def convert(value):
       if pd.isna(value):
           return True
       text = str(value).strip().lower()
       if text in true_values:
           return True
       if text in false_values:
           return False
       return True
   return series.apply(convert)

def load_data(file) -> pd.DataFrame:
   df = pd.read_csv(file)
   original_df = df.copy()
   df = normalize_columns(df)
   username_col = find_column(df, ["SamAccountName", "sAMAccountName", "Username", "User"])
   name_col = find_column(df, ["Name", "DisplayName", "FullName"])
   enabled_col = find_column(df, ["Enabled", "AccountEnabled", "IsEnabled"])
   last_logon_col = find_column(df, ["LastLogonDate", "Last Logon", "LastLogon", "LastSignInDateTime"])
   pwd_last_set_col = find_column(df, ["PasswordLastSet", "PwdLastSet", "Password Last Set"])
   expires_col = find_column(df, ["AccountExpirationDate", "Account Expires", "ExpirationDate"])
   groups_col = find_column(df, ["MemberOf", "Groups", "GroupMembership"])
   dept_col = find_column(df, ["Department"])
   title_col = find_column(df, ["Title", "JobTitle"])
   email_col = find_column(df, ["EmailAddress", "Mail", "Email"])
   out = pd.DataFrame()
   out["username"] = df[username_col] if username_col else ""
   out["name"] = df[name_col] if name_col else ""
   out["enabled"] = parse_bool(df[enabled_col]) if enabled_col else True
   out["last_logon"] = pd.to_datetime(df[last_logon_col], errors="coerce") if last_logon_col else pd.NaT
   out["password_last_set"] = pd.to_datetime(df[pwd_last_set_col], errors="coerce") if pwd_last_set_col else pd.NaT
   out["account_expires"] = pd.to_datetime(df[expires_col], errors="coerce") if expires_col else pd.NaT
   out["groups"] = df[groups_col].fillna("") if groups_col else ""
   out["department"] = df[dept_col].fillna("") if dept_col else ""
   out["title"] = df[title_col].fillna("") if title_col else ""
   out["email"] = df[email_col].fillna("") if email_col else ""
   return out

def enrich_data(df: pd.DataFrame, inactive_days: int, password_days: int) -> pd.DataFrame:
   now = pd.Timestamp(datetime.now())
   out = df.copy()
   out["days_since_last_logon"] = (now - out["last_logon"]).dt.days
   out["days_since_password_change"] = (now - out["password_last_set"]).dt.days
   out["expired_days_ago"] = (now - out["account_expires"]).dt.days
   out["is_inactive"] = out["enabled"] & out["days_since_last_logon"].ge(inactive_days).fillna(False)
   out["is_stale_password"] = out["enabled"] & out["days_since_password_change"].ge(password_days).fillna(False)
   out["never_logged_in"] = out["enabled"] & out["last_logon"].isna()
   out["is_expired"] = out["account_expires"].notna() & (out["account_expires"] < now)
   def privileged_match(group_text: str) -> str:
       text = str(group_text).lower()
       matches = [kw for kw in PRIVILEGED_GROUP_KEYWORDS if kw in text]
       return "; ".join(matches)
   out["matched_privileged_groups"] = out["groups"].apply(privileged_match)
   out["is_privileged"] = out["matched_privileged_groups"] != ""
   return out

def download_frame(df: pd.DataFrame) -> bytes:
   return df.to_csv(index=False).encode("utf-8")

with st.sidebar:
   st.header("Settings")
   uploaded_file = st.file_uploader("Upload AD users CSV", type=["csv"])
   inactive_days = st.slider("Inactive threshold (days)", min_value=30, max_value=365, value=90, step=15)
   password_days = st.slider("Stale password threshold (days)", min_value=30, max_value=365, value=180, step=15)
   show_disabled = st.checkbox("Include disabled accounts in tables", value=False)
file_to_use = uploaded_file if uploaded_file is not None else (DEFAULT_FILE if os.path.exists(DEFAULT_FILE) else None)
if file_to_use is None:
   st.warning("Upload a CSV or place ad_users_sample.csv in the same folder as this dashboard.")
   st.stop()
try:
   df = load_data(file_to_use)
   audit_df = enrich_data(df, inactive_days, password_days)
except Exception as exc:
   st.error(f"Could not load CSV: {exc}")
   st.stop()
if not show_disabled:
   display_df = audit_df[audit_df["enabled"]].copy()
else:
   display_df = audit_df.copy()
# Summary metrics
col1, col2, col3, col4, col5, col6 = st.columns(6)
col1.metric("Total Users", len(audit_df))
col2.metric("Enabled", int(audit_df["enabled"].sum()))
col3.metric("Inactive", int(audit_df["is_inactive"].sum()))
col4.metric("Stale Passwords", int(audit_df["is_stale_password"].sum()))
col5.metric("Never Logged In", int(audit_df["never_logged_in"].sum()))
col6.metric("Privileged", int(audit_df["is_privileged"].sum()))
col7, col8 = st.columns(2)
with col7:
   st.subheader("Risk Overview")
   risk_counts = pd.DataFrame(
       {
           "Category": [
               "Inactive Accounts",
               "Stale Passwords",
               "Never Logged In",
               "Expired Accounts",
               "Privileged Accounts",
           ],
           "Count": [
               int(audit_df["is_inactive"].sum()),
               int(audit_df["is_stale_password"].sum()),
               int(audit_df["never_logged_in"].sum()),
               int(audit_df["is_expired"].sum()),
               int(audit_df["is_privileged"].sum()),
           ],
       }
   )
   chart = alt.Chart(risk_counts).mark_bar().encode(
       x=alt.X("Count:Q", title="Count"),
       y=alt.Y("Category:N", sort='-x', title="Category")
   )
   st.altair_chart(chart, use_container_width=True)
with col8:
   st.subheader("Departments with Most Flagged Users")
   dept_summary = display_df.copy()
   dept_summary["any_flag"] = (
       dept_summary["is_inactive"]
       | dept_summary["is_stale_password"]
       | dept_summary["never_logged_in"]
       | dept_summary["is_expired"]
       | dept_summary["is_privileged"]
   )
   dept_summary = (
       dept_summary[dept_summary["any_flag"]]
       .groupby("department", dropna=False)
       .size()
       .reset_index(name="flagged_users")
       .sort_values("flagged_users", ascending=False)
   )
   if len(dept_summary) > 0:
       dept_chart = alt.Chart(dept_summary).mark_bar().encode(
           x=alt.X("flagged_users:Q", title="Flagged Users"),
           y=alt.Y("department:N", sort='-x', title="Department")
       )
       st.altair_chart(dept_chart, use_container_width=True)
   else:
       st.info("No flagged users found for the current filters.")
st.divider()
search = st.text_input("Search by username, name, department, title, or email")
filtered_df = display_df.copy()
if search:
   pattern = search.lower()
   searchable_cols = ["username", "name", "department", "title", "email"]
   mask = filtered_df[searchable_cols].fillna("").astype(str).apply(lambda col: col.str.lower().str.contains(pattern, na=False))
   filtered_df = filtered_df[mask.any(axis=1)]
# Tabs for each audit category
inactive_df = filtered_df[filtered_df["is_inactive"]].sort_values("days_since_last_logon", ascending=False)
stale_df = filtered_df[filtered_df["is_stale_password"]].sort_values("days_since_password_change", ascending=False)
never_df = filtered_df[filtered_df["never_logged_in"]].copy()
expired_df = filtered_df[filtered_df["is_expired"]].sort_values("expired_days_ago", ascending=False)
priv_df = filtered_df[filtered_df["is_privileged"]].copy()
all_flagged_df = filtered_df[
   filtered_df[["is_inactive", "is_stale_password", "never_logged_in", "is_expired", "is_privileged"]].any(axis=1)
].copy()

def show_table(title: str, df_to_show: pd.DataFrame, filename: str):
   st.subheader(title)
   if len(df_to_show) == 0:
       st.info("No records found.")
       return
   st.dataframe(
       df_to_show[
           [
               "username",
               "name",
               "enabled",
               "department",
               "title",
               "email",
               "last_logon",
               "days_since_last_logon",
               "password_last_set",
               "days_since_password_change",
               "account_expires",
               "expired_days_ago",
               "matched_privileged_groups",
               "groups",
           ]
       ],
       use_container_width=True,
       hide_index=True,
   )
   st.download_button(
       f"Download {title} CSV",
       data=download_frame(df_to_show),
       file_name=filename,
       mime="text/csv",
   )

tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs(
   [
       "All Flagged Users",
       "Inactive Accounts",
       "Stale Passwords",
       "Never Logged In",
       "Expired Accounts",
       "Privileged Accounts",
   ]
)
with tab1:
   show_table("All Flagged Users", all_flagged_df, "all_flagged_users.csv")
with tab2:
   show_table("Inactive Accounts", inactive_df, "inactive_accounts.csv")
with tab3:
   show_table("Stale Passwords", stale_df, "stale_passwords.csv")
with tab4:
   show_table("Never Logged In", never_df, "never_logged_in.csv")
with tab5:
   show_table("Expired Accounts", expired_df, "expired_accounts.csv")
with tab6:
   show_table("Privileged Accounts", priv_df, "privileged_accounts.csv")
st.divider()
st.subheader("Recommended Cleanup Workflow")
st.markdown(
   """
1. Review privileged accounts first and confirm each membership is still required.  
2. Check expired enabled accounts and disable or remove them if appropriate.  
3. Review never-logged-in accounts to catch unused new accounts or provisioning mistakes.  
4. Investigate inactive accounts older than the selected threshold.  
5. Review stale passwords and confirm policy exceptions or service account usage.
"""
)