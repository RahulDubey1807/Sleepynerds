# main.py
import os
import uuid
import hmac
import hashlib
import secrets
import smtplib
from email.message import EmailMessage
from datetime import datetime, timedelta
from typing import List, Optional, Tuple

import httpx
from bson import ObjectId
from fastapi import (
    FastAPI,
    Form,
    Request,
    Response,
    UploadFile,
    File,
    Depends,
    HTTPException,
)
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from motor.motor_asyncio import AsyncIOMotorClient
from passlib.context import CryptContext
from pydantic import BaseModel

# ------------------------
# Config
# ------------------------
APP_SECRET = os.environ.get("APP_SECRET_KEY", "change_this_secret_for_demo")
AUTH_COOKIE_NAME = "hack_auth"
COOKIE_MAX_AGE = 60 * 60 * 24 * 7  # 7 days

# Optional SMTP settings for real email sending (demo will show password on-screen if not provided)
SMTP_HOST = os.environ.get("SMTP_HOST")
SMTP_PORT = int(os.environ.get("SMTP_PORT", 587)) if os.environ.get("SMTP_PORT") else None
SMTP_USER = os.environ.get("SMTP_USER")
SMTP_PASS = os.environ.get("SMTP_PASS")
FROM_EMAIL = os.environ.get("FROM_EMAIL", SMTP_USER or "no-reply@example.com")

# ------------------------
# App + templates + uploads
# ------------------------
app = FastAPI()
templates = Jinja2Templates(directory="templates")

UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)
app.mount("/uploads", StaticFiles(directory=UPLOAD_DIR), name="uploads")

# ------------------------
# Mongo
# ------------------------
MONGO_URI = os.environ.get("MONGO_URI", "mongodb://localhost:27017")
client = AsyncIOMotorClient(MONGO_URI)
db = client.hackathon_db
users_collection = db.users
companies_collection = db.companies
expenses_collection = db.expenses
approvals_collection = db.approvals
approval_rules_collection = db.approval_rules  # per-company rules & sequences

# ------------------------
# Password hashing
# ------------------------
pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")

# ------------------------
# Pydantic models
# ------------------------
class ExpenseCreate(BaseModel):
    employee_id: str
    description: str
    category: str
    paid_by: str
    amount: float
    currency: str
    date: datetime
    remarks: Optional[str] = None
    receipt_filename: Optional[str] = None
    status: Optional[str] = None

class Expense(ExpenseCreate):
    id: str
    converted_amount: float
    status: str
    created_at: datetime

# ------------------------
# Utility: cookie signing
# ------------------------
def _sign_message(msg: str) -> str:
    return hmac.new(APP_SECRET.encode(), msg.encode(), hashlib.sha256).hexdigest()

def create_cookie_value(email: str, role: str) -> str:
    ts = str(int(datetime.utcnow().timestamp()))
    msg = f"{email}|{role}|{ts}"
    sig = _sign_message(msg)
    return f"{email}|{role}|{ts}|{sig}"

def verify_cookie(cookie_value: str) -> Optional[Tuple[str,str]]:
    try:
        parts = cookie_value.split("|")
        if len(parts) != 4:
            return None
        email, role, ts, sig = parts
        msg = f"{email}|{role}|{ts}"
        if not hmac.compare_digest(_sign_message(msg), sig):
            return None
        # expiry
        if datetime.utcnow().timestamp() - int(ts) > COOKIE_MAX_AGE:
            return None
        return email, role
    except Exception:
        return None

# ------------------------
# Helpers for users/companies
# ------------------------
async def get_user_by_email(email: str) -> Optional[dict]:
    return await users_collection.find_one({"email": email.lower()})

async def create_company(name: str = "Demo Company", currency: str = "INR"):
    comp = {"_id": ObjectId(), "name": name, "currency": currency, "created_at": datetime.utcnow()}
    await companies_collection.insert_one(comp)
    return comp

async def fetch_countries_and_currencies():
    try:
        url = "https://restcountries.com/v3.1/all?fields=name,currencies,cca2"
        async with httpx.AsyncClient() as c:
            resp = await c.get(url, timeout=15.0)
            data = resp.json()
            out = []
            for it in data:
                if "currencies" in it and "cca2" in it:
                    for code, val in it["currencies"].items():
                        out.append({"cca2": it.get("cca2"), "code": code, "name": val.get("name", "")})
            # unique by cca2 or code
            seen = {}
            unique = []
            for e in out:
                key = e["code"]
                if key not in seen:
                    seen[key] = True
                    unique.append(e)
            unique_sorted = sorted(unique, key=lambda x: x["code"])
            return unique_sorted
    except Exception:
        # fallback minimal
        return [{"cca2":"IN","code":"INR","name":"Indian rupee"}, {"cca2":"US","code":"USD","name":"United States dollar"}]

# ------------------------
# Currency conversion
# ------------------------
async def convert_currency(amount: float, from_currency: str, to_currency: str) -> float:
    if from_currency == to_currency:
        return round(amount,2)
    try:
        url = f"https://api.exchangerate-api.com/v4/latest/{from_currency}"
        async with httpx.AsyncClient() as c:
            resp = await c.get(url, timeout=10.0)
            data = resp.json()
            rate = data.get("rates", {}).get(to_currency, 1)
            return round(amount * rate, 2)
    except Exception:
        # fallback: no conversion
        return round(amount,2)

# ------------------------
# Email helper (demo)
# ------------------------
def send_email(to_email: str, subject: str, body: str) -> bool:
    """
    Attempts to send mail if SMTP is set; otherwise returns False.
    """
    if not (SMTP_HOST and SMTP_PORT and SMTP_USER and SMTP_PASS):
        # SMTP not configured in env — caller should handle fallback
        print("SMTP not configured; email not sent. Body:\n", body)
        return False
    try:
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = FROM_EMAIL
        msg["To"] = to_email
        msg.set_content(body)
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as s:
            s.starttls()
            s.login(SMTP_USER, SMTP_PASS)
            s.send_message(msg)
        return True
    except Exception as e:
        print("SMTP send failed:", e)
        return False

# ------------------------
# Auth dependency
# ------------------------
async def current_user(request: Request) -> Optional[dict]:
    cookie = request.cookies.get(AUTH_COOKIE_NAME)
    if not cookie:
        return None
    verified = verify_cookie(cookie)
    if not verified:
        return None
    email, role = verified
    u = await get_user_by_email(email)
    if not u:
        return None
    return u

def require_login(user: Optional[dict]):
    if not user:
        raise HTTPException(status_code=401, detail="Login required")

def require_role(user: Optional[dict], role: str):
    require_login(user)
    if user.get("role") != role and user.get("role") != "Admin":
        raise HTTPException(status_code=403, detail="Forbidden")

# ------------------------
# Helpers for rendering docs
# ------------------------
def expense_helper(exp) -> dict:
    receipt_filename = exp.get("receipt_filename")
    receipt_url = f"/uploads/{receipt_filename}" if receipt_filename else None
    return {
        "id": str(exp["_id"]),
        "employee_id": exp.get("employee_id"),
        "description": exp.get("description"),
        "category": exp.get("category"),
        "paid_by": exp.get("paid_by"),
        "amount": exp.get("amount"),
        "currency": exp.get("currency"),
        "converted_amount": exp.get("converted_amount"),
        "status": exp.get("status"),
        "date": exp.get("date"),
        "created_at": exp.get("created_at"),
        "remarks": exp.get("remarks"),
        "receipt_filename": receipt_filename,
        "receipt_url": receipt_url
    }

def approval_doc_helper(a) -> dict:
    return {
        "id": str(a["_id"]),
        "expense_id": a.get("expense_id"),
        "approver_email": a.get("approver_email"),
        "order": a.get("order"),
        "status": a.get("status"),
        "comment": a.get("comment"),
        "acted_at": a.get("acted_at")
    }

# ------------------------
# Routes: Signup (Admin/Company creation)
# ------------------------
@app.get("/signup", response_class=HTMLResponse)
async def signup_page(request: Request):
    countries = await fetch_countries_and_currencies()
    return templates.TemplateResponse("signup.html", {"request": request, "countries": countries})

@app.post("/signup")
async def do_signup(response: Response,
                    name: str = Form(...),
                    email: str = Form(...),
                    password: str = Form(...),
                    confirm_password: str = Form(...),
                    country_currency: str = Form(...),
                    role: str = Form(...)):
    email = email.lower().strip()
    if password != confirm_password:
        raise HTTPException(status_code=400, detail="Passwords do not match")
    if await get_user_by_email(email):
        raise HTTPException(status_code=400, detail="User already exists; please login")

    # Truncate password to 72 chars for bcrypt
    if len(password) > 72:
        password = password[:72]

    # If no company exists -> create company and make this user Admin
    comp = await companies_collection.find_one({})
    if not comp:
        comp = await create_company(name="Demo Company", currency=country_currency)
        assigned_role = "Admin"
    else:
        assigned_role = role if role in ("Admin", "Manager", "Employee") else "Employee"

    hashed = pwd_ctx.hash(password)
    user_doc = {
        "_id": ObjectId(),
        "name": name,
        "email": email,
        "password": hashed,
        "role": assigned_role,
        "company_id": comp["_id"],
        "created_at": datetime.utcnow(),
    }
    await users_collection.insert_one(user_doc)

    cookie_val = create_cookie_value(email, assigned_role)
    redirect = RedirectResponse(url="/post-login-redirect", status_code=302)
    redirect.set_cookie(AUTH_COOKIE_NAME, cookie_val, max_age=COOKIE_MAX_AGE, httponly=True, samesite="lax")
    return redirect

# ------------------------
# Login / logout
# ------------------------
@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.post("/login")
async def do_login(response: Response, email: str = Form(...), password: str = Form(...)):
    email = email.lower().strip()
    user = await get_user_by_email(email)
    if not user or not pwd_ctx.verify(password, user["password"]):
        # naive for demo - you can add lockouts later
        return templates.TemplateResponse("login.html", {"request": Request, "error": "Invalid credentials"})
    cookie_val = create_cookie_value(email, user.get("role", "Employee"))
    redirect = RedirectResponse(url="/post-login-redirect", status_code=302)
    redirect.set_cookie(AUTH_COOKIE_NAME, cookie_val, max_age=COOKIE_MAX_AGE, httponly=True, samesite="lax")
    return redirect

@app.get("/post-login-redirect")
async def post_login_redirect(user: dict = Depends(current_user)):
    if not user:
        return RedirectResponse(url="/login", status_code=303)
    if user.get("role") == "Admin":
        return RedirectResponse(url="/admin", status_code=303)
    if user.get("role") == "Manager":
        return RedirectResponse(url="/manager", status_code=303)
    return RedirectResponse(url="/ui", status_code=303)

@app.get("/logout")
async def logout():
    r = RedirectResponse(url="/login", status_code=302)
    r.delete_cookie(AUTH_COOKIE_NAME)
    return r

# ------------------------
# Admin: dashboard to manage users and approval rules
# ------------------------
@app.get("/admin", response_class=HTMLResponse)
async def admin_dashboard(request: Request, user: dict = Depends(current_user)):
    require_role(user, "Admin")
    company_id = user["company_id"]
    users = []
    async for u in users_collection.find({"company_id": company_id}):
        users.append(u)
    # approval rules (one per company) and sequence stored in approval_rules_collection
    rule = await approval_rules_collection.find_one({"company_id": company_id})
    return templates.TemplateResponse("admin.html", {"request": request, "users": users, "rule": rule, "current_user": user})

@app.post("/admin/create-user")
async def admin_create_user(name: str = Form(...), email: str = Form(...), role: str = Form(...), user: dict = Depends(current_user)):
    require_role(user, "Admin")
    email = email.lower().strip()
    company_id = user["company_id"]
    existing = await get_user_by_email(email)
    if existing:
        raise HTTPException(status_code=400, detail="User already exists")
    # generate temp password
    temp_password = secrets.token_urlsafe(8)
    hashed = pwd_ctx.hash(temp_password)
    udoc = {
        "_id": ObjectId(),
        "name": name,
        "email": email,
        "password": hashed,
        "role": role if role in ("Manager","Employee","Admin") else "Employee",
        "company_id": company_id,
        "created_at": datetime.utcnow(),
    }
    await users_collection.insert_one(udoc)
    # try to email; if smtp not configured, return password in response
    sent = send_email(email, "Your account password", f"Your temporary password: {temp_password}")
    # return admin dashboard with info: for simplicity redirect back and show a cookie message
    redirect = RedirectResponse(url="/admin?pw_sent=" + ("1" if sent else temp_password), status_code=302)
    return redirect

@app.post("/admin/set-approval-rule")
async def admin_set_rule(
    seq_emails: str = Form(...),  # comma separated emails for approver sequence order
    rule_type: str = Form(...),   # "all" / "percentage" / "specific" / "hybrid"
    percentage_threshold: Optional[int] = Form(None),  # integer 0-100
    specific_approver: Optional[str] = Form(None),  # email
    user: dict = Depends(current_user)
):
    require_role(user, "Admin")
    company_id = user["company_id"]
    seq = [e.strip().lower() for e in seq_emails.split(",") if e.strip()]
    rule_doc = {
        "_id": ObjectId(),
        "company_id": company_id,
        "sequence": seq,
        "rule_type": rule_type,
        "percentage_threshold": int(percentage_threshold) if percentage_threshold else None,
        "specific_approver": specific_approver.lower() if specific_approver else None,
        "updated_at": datetime.utcnow()
    }
    # upsert
    await approval_rules_collection.update_one({"company_id": company_id}, {"$set": rule_doc}, upsert=True)
    return RedirectResponse(url="/admin", status_code=303)

# ------------------------
# Employee UI (submit & list)
# ------------------------
@app.get("/ui", response_class=HTMLResponse)
async def employee_ui(request: Request, user: dict = Depends(current_user)):
    require_login(user)
    company_id = user["company_id"]
    # employees should see their own expenses
    expenses = []
    async for e in expenses_collection.find({"employee_id": user["email"]}).sort("created_at", -1):
        expenses.append(expense_helper(e))
    # show currencies for dropdown
    currencies = await fetch_countries_and_currencies()
    return templates.TemplateResponse("employee.html", {"request": request, "expenses": expenses, "currencies": currencies, "current_user": user})

@app.post("/ui/submit")
async def submit_ui(
    request: Request,
    employee_email: str = Form(...),
    description: str = Form(...),
    category: str = Form(...),
    paid_by: str = Form(...),
    amount: float = Form(...),
    currency: str = Form(...),
    date: Optional[str] = Form(None),
    remarks: Optional[str] = Form(None),
    receipt: Optional[UploadFile] = File(None),
    action: str = Form("submit"),
    user: dict = Depends(current_user)
):
    require_login(user)
    status = "Draft" if action == "draft" else "Pending"
    if date:
        try:
            dt = datetime.fromisoformat(date)
        except Exception:
            dt = datetime.utcnow()
    else:
        dt = datetime.utcnow()
    receipt_filename = None
    if receipt:
        ext = os.path.splitext(receipt.filename or "file")[1]
        saved = f"{uuid.uuid4().hex}{ext}"
        path = os.path.join(UPLOAD_DIR, saved)
        contents = await receipt.read()
        with open(path, "wb") as f:
            f.write(contents)
        receipt_filename = saved

    company = await companies_collection.find_one({"_id": user["company_id"]})
    to_currency = company.get("currency", "INR") if company else "INR"
    converted = await convert_currency(amount, currency, to_currency)

    exp = {
        "_id": ObjectId(),
        "employee_id": employee_email.lower(),
        "description": description,
        "category": category,
        "paid_by": paid_by,
        "amount": amount,
        "currency": currency,
        "converted_amount": converted,
        "status": status,
        "date": dt,
        "created_at": datetime.utcnow(),
        "remarks": remarks,
        "receipt_filename": receipt_filename,
        "company_id": user["company_id"]
    }
    await expenses_collection.insert_one(exp)

    # If submitted (not draft) create approval placeholders according to company's approval rule/sequence
    if status != "Draft":
        rule = await approval_rules_collection.find_one({"company_id": user["company_id"]})
        if rule and rule.get("sequence"):
            # create approval docs in order, each initial status "Pending" but only first will be actionable
            seq = rule["sequence"]
            for idx, approver_email in enumerate(seq):
                a = {
                    "_id": ObjectId(),
                    "expense_id": str(exp["_id"]),
                    "approver_email": approver_email,
                    "order": idx,
                    "status": "Pending",
                    "comment": None,
                    "acted_at": None
                }
                await approvals_collection.insert_one(a)
        else:
            # default: single Manager placeholder (find any manager in company)
            manager = await users_collection.find_one({"company_id": user["company_id"], "role": "Manager"})
            if manager:
                a = {
                    "_id": ObjectId(),
                    "expense_id": str(exp["_id"]),
                    "approver_email": manager["email"],
                    "order": 0,
                    "status": "Pending",
                    "comment": None,
                    "acted_at": None
                }
                await approvals_collection.insert_one(a)
    return RedirectResponse(url="/ui", status_code=303)

@app.get("/ui/expense/{expense_id}", response_class=HTMLResponse)
async def expense_detail(request: Request, expense_id: str, user: dict = Depends(current_user)):
    require_login(user)
    exp = await expenses_collection.find_one({"_id": ObjectId(expense_id)})
    if not exp:
        return RedirectResponse(url="/ui", status_code=303)
    approvals = []
    async for a in approvals_collection.find({"expense_id": expense_id}).sort("order", 1):
        approvals.append(approval_doc_helper(a))
    return templates.TemplateResponse("detail.html", {"request": request, "expense": expense_helper(exp), "approvals": approvals, "current_user": user})

# ------------------------
# Manager: view pending for them & approve/reject
# ------------------------
@app.get("/manager", response_class=HTMLResponse)
async def manager_ui(request: Request, user: dict = Depends(current_user)):
    require_role(user, "Manager")
    # find approvals where approver_email == user's email and status == Pending
    pending = []
    async for a in approvals_collection.find({"approver_email": user["email"], "status": "Pending"}):
        exp = await expenses_collection.find_one({"_id": ObjectId(a["expense_id"])})
        pending.append({"approval": approval_doc_helper(a), "expense": expense_helper(exp)})
    return templates.TemplateResponse("manager.html", {"request": request, "pending": pending, "current_user": user})

@app.post("/manager/decide")
async def manager_decide(expense_id: str = Form(...), approval_id: str = Form(...), action: str = Form(...), comment: Optional[str] = Form(None), user: dict = Depends(current_user)):
    require_role(user, "Manager")
    # update this approval doc
    app_doc = await approvals_collection.find_one({"_id": ObjectId(approval_id)})
    if not app_doc:
        raise HTTPException(status_code=404, detail="Approval not found")
    if app_doc["approver_email"] != user["email"] and user.get("role") != "Admin":
        raise HTTPException(status_code=403, detail="Not your approval to act on")
    # set status & acted_at & comment
    await approvals_collection.update_one({"_id": app_doc["_id"]}, {"$set": {"status": action, "comment": comment, "acted_at": datetime.utcnow()}})
    # evaluate next steps:
    # 1) If rejected -> set expense status Rejected and skip others
    if action == "Rejected":
        await expenses_collection.update_one({"_id": ObjectId(expense_id)}, {"$set": {"status": "Rejected"}})
        return RedirectResponse(url="/manager", status_code=303)

    # 2) If approved -> consult approval_rules for company and sequence
    exp = await expenses_collection.find_one({"_id": ObjectId(expense_id)})
    rule = await approval_rules_collection.find_one({"company_id": exp.get("company_id")})
    # mark progression: check if sequence exists, else simple: mark Approved
    if not rule or not rule.get("sequence"):
        # simple single-approver flow: mark expense Approved
        await expenses_collection.update_one({"_id": ObjectId(expense_id)}, {"$set": {"status": "Approved"}})
        return RedirectResponse(url="/manager", status_code=303)

    # rule exists: check statuses of approvals for this expense
    approvals = []
    async for a in approvals_collection.find({"expense_id": expense_id}).sort("order", 1):
        approvals.append(a)
    # Check conditional rules:
    rule_type = rule.get("rule_type", "all")
    if rule_type == "all":
        # require all approvers approved
        if all(a.get("status") == "Approved" for a in approvals):
            await expenses_collection.update_one({"_id": ObjectId(expense_id)}, {"$set": {"status": "Approved"}})
            return RedirectResponse(url="/manager", status_code=303)
        else:
            # move to next approver if current approver had order k
            # find next approval with same expense and status Pending and lower order > current
            cur_order = app_doc.get("order")
            next_approval = await approvals_collection.find_one({"expense_id": expense_id, "order": {"$gt": cur_order}, "status": "Pending"})
            # nothing special needed; it's created already during expense creation
            return RedirectResponse(url="/manager", status_code=303)
    elif rule_type == "percentage":
        threshold = rule.get("percentage_threshold", 100)
        total = len(approvals)
        approved_count = sum(1 for a in approvals if a.get("status") == "Approved")
        if (approved_count / total) * 100 >= threshold:
            await expenses_collection.update_one({"_id": ObjectId(expense_id)}, {"$set": {"status": "Approved"}})
        return RedirectResponse(url="/manager", status_code=303)
    elif rule_type == "specific":
        spec = rule.get("specific_approver")
        # if the specific approver has Approved -> expense Approved
        spec_approval = None
        for a in approvals:
            if a.get("approver_email") == spec:
                spec_approval = a
                break
        if spec_approval and spec_approval.get("status") == "Approved":
            await expenses_collection.update_one({"_id": ObjectId(expense_id)}, {"$set": {"status": "Approved"}})
        return RedirectResponse(url="/manager", status_code=303)
    elif rule_type == "hybrid":
        # hybrid: if specific approver approves OR percentage threshold reached
        spec = rule.get("specific_approver")
        threshold = rule.get("percentage_threshold", 100)
        total = len(approvals)
        approved_count = sum(1 for a in approvals if a.get("status") == "Approved")
        percent_ok = (approved_count / total) * 100 >= threshold
        spec_ok = False
        for a in approvals:
            if a.get("approver_email") == spec and a.get("status") == "Approved":
                spec_ok = True
                break
        if percent_ok or spec_ok:
            await expenses_collection.update_one({"_id": ObjectId(expense_id)}, {"$set": {"status": "Approved"}})
        return RedirectResponse(url="/manager", status_code=303)
    else:
        # default fallback
        return RedirectResponse(url="/manager", status_code=303)
