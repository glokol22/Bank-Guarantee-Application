print("✅ Loaded main.py from:", __file__)

from fastapi import Depends, FastAPI, HTTPException, UploadFile, Form, status
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
from passlib.context import CryptContext
from datetime import timedelta
from typing import Optional
from typing_extensions import Annotated
from pymongo import MongoClient


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Code to run on startup
    print("INFO:     Application startup complete.")
    # --- MongoDB Setup ---
    MONGO_URI = "mongodb://localhost:27017/"
    client = MongoClient(MONGO_URI)
    db = client.gtee_db
    app.state.user_collection = db.users

    # Seed data
    if app.state.user_collection.count_documents({}) == 0:
        app.state.user_collection.insert_one({
            "username": "admin",
            "full_name": "Admin User",
            "email": "admin@example.com",
            "hashed_password": pwd_context.hash("password123"),
            "disabled": False,
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

# In-memory storage for submissions
submissions = []

# --- Security & Authentication Setup ---

SECRET_KEY = os.urandom(32).hex()  # In a real app, load this from a config file
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_user(username: str):
    return app.state.user_collection.find_one({"username": username})

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user_from_cookie(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
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
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user["username"]}, expires_delta=access_token_expires
    )
    
    # Return a JSON response and set the token in an HTTPOnly cookie for security
    response = JSONResponse(content={"message": "Login successful"})
    response.set_cookie(key="access_token", value=f"Bearer {access_token}", httponly=True)
    return response


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

    submissions.append(submission)

    return {
        "reference_no": ref_no,
        "timestamp": timestamp,
        "customer_name": customer_name,
        "file_uploaded": bool(file_path),
        "status": status
    }

@app.get("/submissions/")
def get_submissions():
    return {"submissions": submissions}

@app.get("/submissions/{customer_name}")
def get_customer_summary(customer_name: str):
    """Returns summary of guarantees per status for a given customer"""
    customer_records = [s for s in submissions if s["customer_name"].lower() == customer_name.lower()]
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
    for s in submissions:
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
    submission = next((s for s in submissions if s["reference_no"] == ref_no), None)
    if submission and submission["file_path"] and os.path.exists(submission["file_path"]):
        return FileResponse(submission["file_path"], filename=os.path.basename(submission["file_path"]))
    return {"error": "File not found or submission does not exist."}

# This must be placed AFTER all other API routes.
# It tells FastAPI to serve the HTML/CSS files from the current directory.
app.mount("/", StaticFiles(directory=".", html=True), name="static")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)