print("✅ Loaded main.py from:", __file__)

from fastapi import Depends, FastAPI, HTTPException, UploadFile, Form, status, Cookie
from contextlib import asynccontextmanager
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, RedirectResponse, JSONResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
import os
import uuid
from datetime import datetime
import httpx
from jose import JWTError, jwt
import bcrypt
from datetime import timedelta
from typing import Optional
from typing_extensions import Annotated
from pymongo import MongoClient
from pydantic import BaseModel

from config import settings

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Code to run on startup
    print("INFO:     Application startup complete.")
    # --- MongoDB Setup ---
    MONGO_URI = "mongodb://localhost:27017/"
    client = MongoClient(MONGO_URI)
    db = client.users_db
    # Separate collections for different user categories
    app.state.admins = db.admin_db
    app.state.makers = db.maker_db
    app.state.checkers = db.auth_db
    app.state.submission_collection = db.submissions

    # Seed data
    if app.state.admins.count_documents({}) == 0:
        app.state.admins.insert_one({
            "username": "admin",
            "full_name": "Admin User",
            "email": "admin@example.com",
            "hashed_password": hash_password("password123"),
            "disabled": False,
            "role": "ADMIN", # Default role for the bootstrap user
        })
        print("✅ Default user 'admin' seeded in MongoDB.")
    yield
    # Code to run on shutdown
    client.close()

app = FastAPI(lifespan=lifespan)
# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Uploads directory
UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

# --- Security & Authentication Setup ---

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))

def get_user(username: str):
    # Search for the user across the categorized collections
    user = app.state.admins.find_one({"username": username})
    if user: return user
    user = app.state.makers.find_one({"username": username})
    if user: return user
    user = app.state.checkers.find_one({"username": username})
    if user: return user
    return None

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt

async def get_current_user_from_cookie(access_token: Optional[str] = Cookie(None)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    if not access_token:
        raise credentials_exception
    
    token = access_token
    if token.startswith("Bearer "):
        token = token.split(" ")[1]

    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = get_user(username)
    if user is None:
        raise credentials_exception
    return user

@app.post("/token")
async def login_for_access_token(form_data: Annotated[OAuth2PasswordRequestForm, Depends()]):
    user = get_user(form_data.username)
    if not user or not verify_password(form_data.password, user["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user["username"]}, expires_delta=access_token_expires
    )
    
    # Return a JSON response and set the token in an HTTPOnly cookie for security
    response = JSONResponse(content={
        "message": "Login successful",
        "user": {
            "full_name": user.get("full_name", user["username"]),
            "role": user.get("role", "MAKER") # Return the role to the frontend
        }
    })
    response.set_cookie(key="access_token", value=f"Bearer {access_token}", httponly=True)
    return response


@app.get("/users/me")
async def read_users_me(current_user: dict = Depends(get_current_user_from_cookie)):
    return {
        "username": current_user["username"],
        "full_name": current_user.get("full_name", "User"),
        "email": current_user.get("email", ""),
        "role": current_user.get("role", "MAKER")
    }

@app.post("/logout")
async def logout():
    response = JSONResponse(content={"message": "Logged out successfully"})
    response.delete_cookie("access_token")
    return response

# --- User Management Endpoints (Admin Only) ---

class UserCreate(BaseModel):
    username: str
    full_name: str
    email: str
    password: str
    role: str

@app.post("/users/")
async def create_user_endpoint(user: UserCreate, current_user: dict = Depends(get_current_user_from_cookie)):
    if current_user.get("role") != "ADMIN":
        raise HTTPException(status_code=403, detail="Not authorized. Admin access required.")
    
    if get_user(user.username):
        raise HTTPException(status_code=400, detail="Username already exists")

    user_doc = {
        "username": user.username,
        "full_name": user.full_name,
        "email": user.email,
        "role": user.role,
        "hashed_password": hash_password(user.password),
        "disabled": False
    }

    if user.role == "ADMIN":
        app.state.admins.insert_one(user_doc)
    elif user.role == "MAKER":
        app.state.makers.insert_one(user_doc)
    elif user.role == "CHECKER":
        app.state.checkers.insert_one(user_doc)
    else:
        raise HTTPException(status_code=400, detail="Invalid role specified.")
    
    return {"message": f"User {user.username} created successfully"}

@app.get("/users/")
async def list_users(current_user: dict = Depends(get_current_user_from_cookie)):
    if current_user.get("role") != "ADMIN":
        raise HTTPException(status_code=403, detail="Not authorized")
    
    users = []
    # Fetch from all collections
    # We include _id temporarily to sort by creation time
    for u in app.state.admins.find({}, {"hashed_password": 0}):
        u["role"] = "ADMIN"
        users.append(u)
    for u in app.state.makers.find({}, {"hashed_password": 0}):
        u["role"] = "MAKER"
        users.append(u)
    for u in app.state.checkers.find({}, {"hashed_password": 0}):
        u["role"] = "CHECKER"
        users.append(u)
    
    # Sort by _id descending (newest first) and take only the top 2
    users.sort(key=lambda x: x["_id"], reverse=True)
    users = users[:2]

    # Remove _id before returning to frontend
    for u in users:
        del u["_id"]

    return {"users": users}

# --- API Endpoints ---

@app.get("/currencies/")
async def get_currencies():
    """
    Fetches a list of world currencies from an online source.
    """
    # This URL points to a well-maintained JSON file of currency data
    CURRENCY_API_URL = "https://raw.githubusercontent.com/umpirsky/currency-list/master/data/en_US/currency.json"
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(CURRENCY_API_URL)
            response.raise_for_status()  # Raise an exception for bad status codes (4xx or 5xx)
            currency_data = response.json()
            # Transform the data into the format the frontend expects: {code: 'USD', name: 'United States Dollar'}
            formatted_currencies = [{"code": code, "name": name} for code, name in currency_data.items()]
            return {"currencies": formatted_currencies}
    except httpx.RequestError as e:
        print(f"Error fetching currencies: {e}")
        return {"currencies": [], "error": "Could not fetch currency data."}

@app.post("/submit-guarantee/")
async def submit_guarantee(
    application_date: str = Form(...),
    customer_name: str = Form(...),
    customer_postal_address: str = Form(...),
    customer_physical_address: str = Form(...),
    customer_telephone: str = Form(...),
    customer_email: str = Form(...),
    applicant_name: str = Form(...),
    applicant_postal_address: str = Form(...),
    applicant_physical_address: str = Form(...),
    applicant_relationship: str = Form(...),
    applicant_contact_name: str = Form(...),
    applicant_contact_phone: str = Form(...),
    applicant_contact_email: str = Form(...),
    beneficiary_name: str = Form(...),
    beneficiary_postal_address: str = Form(...), 
    beneficiary_physical_address: str = Form(...),
    beneficiary_telephone: str = Form(...),
    issuance_manner: str = Form(...),
    local_guarantee_expiry_date: str = Form(None),
    counter_guarantee_expiry_date: str = Form(None),
    advising_bank_swift_address: str = Form(None),
    reissuing_bank_swift_address: str = Form(None),
    first_advising_bank_swift_address: str = Form(None),
    second_advising_bank_swift_address: str = Form(None), 
    guarantee_currency: str = Form(...),
    guarantee_amount: str = Form(...),
    collateral_type: str = Form(...),
    collateral_account_number: str = Form(None),
    collateral_sum: str = Form(None),
    wording_format: str = Form(...),
    guarantee_type: str = Form(...),
    guarantee_purpose: str = Form(None),
    counter_guarantee_term: str = Form(None),
    collect_trade_counter: str = Form(None),
    collect_branch: str = Form(None),
    collect_agent_info: str = Form(None),
    identification_type: str = Form(None),
    identification_number: str = Form(None),
    wording_file: UploadFile = None,
    status: str = Form("Draft")  # Default status
    # current_user: dict = Depends(get_current_user_from_cookie) # This protects the endpoint
):
    ref_no = f"GUA-{uuid.uuid4().hex[:8].upper()}"
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    file_path = None
    if wording_file:
        filename = f"{ref_no}_{wording_file.filename}"
        file_path = os.path.join(UPLOAD_DIR, filename)
        with open(file_path, "wb") as f:
            f.write(await wording_file.read())

    submission = {
        "reference_no": ref_no,
        "timestamp": timestamp,
        "application_date": application_date,
        "customer_name": customer_name,
        "customer_postal_address": customer_postal_address,
        "customer_physical_address": customer_physical_address,
        "customer_telephone": customer_telephone,
        "customer_email": customer_email,
        "applicant_name": applicant_name,
        "applicant_postal_address": applicant_postal_address,
        "applicant_physical_address": applicant_physical_address,
        "applicant_relationship": applicant_relationship,
        "applicant_contact_name": applicant_contact_name,
        "applicant_contact_phone": applicant_contact_phone,
        "applicant_contact_email": applicant_contact_email,
        "beneficiary_name": beneficiary_name,
        "beneficiary_postal_address": beneficiary_postal_address,
        "beneficiary_physical_address": beneficiary_physical_address,
        "beneficiary_telephone": beneficiary_telephone,
        "issuance_manner": issuance_manner,
        "local_guarantee_expiry_date": local_guarantee_expiry_date,
        "counter_guarantee_expiry_date": counter_guarantee_expiry_date,
        "advising_bank_swift_address": advising_bank_swift_address,
        "reissuing_bank_swift_address": reissuing_bank_swift_address,
        "first_advising_bank_swift_address": first_advising_bank_swift_address,
        "second_advising_bank_swift_address": second_advising_bank_swift_address,
        "guarantee_currency": guarantee_currency,
        "guarantee_amount": guarantee_amount,
        "collateral_type": collateral_type,
        "collateral_account_number": collateral_account_number,
        "collateral_sum": collateral_sum,
        "wording_format": wording_format,
        "guarantee_type": guarantee_type,
        "guarantee_purpose": guarantee_purpose,
        "counter_guarantee_term": counter_guarantee_term,
        "collect_trade_counter": collect_trade_counter,
        "collect_branch": collect_branch,
        "collect_agent_info": collect_agent_info,
        "identification_type": identification_type,
        "identification_number": identification_number,
        "file_path": file_path,
        "status": status
    }

    app.state.submission_collection.insert_one(submission)

    return {
        "reference_no": ref_no,
        "timestamp": timestamp,
        "customer_name": customer_name,
        "file_uploaded": bool(file_path),
        "status": status
    }

@app.get("/submissions/")
def get_submissions():
    submissions = list(app.state.submission_collection.find({}, {"_id": 0}))
    return {"submissions": submissions}

@app.get("/submissions/{customer_name}")
def get_customer_summary(customer_name: str):
    """Returns summary of guarantees per status for a given customer"""
    customer_records = list(app.state.submission_collection.find({"customer_name": {"$regex": f"^{customer_name}$", "$options": "i"}}, {"_id": 0}))
    summary = {
        "Issued": 0,
        "Draft": 0,
        "Pending Legal Review": 0,
        "Pending Customer Sign-off": 0,
        "Pending Credit Checks": 0
    }

    for record in customer_records:
        status = record.get("status", "Draft")
        if status in summary:
            summary[status] += 1

    return {
        "customer_name": customer_name,
        "postal_address": customer_records[0]["customer_postal_address"] if customer_records else None,
        "physical_address": customer_records[0]["customer_physical_address"] if customer_records else None,
        "summary": summary
    }

@app.get("/customers/")
def list_customers():
    """Returns all customers with their summaries"""
    customers = {}
    submissions_cursor = app.state.submission_collection.find({}, {"_id": 0})
    for s in submissions_cursor:
        name = s["customer_name"]
        if name not in customers:
            customers[name] = {
                "customer_name": name,
                "postal_address": s["customer_postal_address"],
                "physical_address": s.get("customer_physical_address"),
                "summary": {
                    "Issued": 0,
                    "Draft": 0,
                    "Pending Legal Review": 0,
                    "Pending Customer Sign-off": 0,
                    "Pending Credit Checks": 0
                }
            }
        status = s.get("status", "Draft")
        if status in customers[name]["summary"]:
            customers[name]["summary"][status] += 1

    return {"customers": list(customers.values())}

@app.get("/download/{ref_no}")
def download_file(ref_no: str):
    submission = app.state.submission_collection.find_one({"reference_no": ref_no})
    if submission and submission["file_path"] and os.path.exists(submission["file_path"]):
        return FileResponse(submission["file_path"], filename=os.path.basename(submission["file_path"]))
    return {"error": "File not found or submission does not exist."}

# This must be placed AFTER all other API routes.
# It tells FastAPI to serve the HTML/CSS files from the current directory.
app.mount("/", StaticFiles(directory=".", html=True), name="static")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)