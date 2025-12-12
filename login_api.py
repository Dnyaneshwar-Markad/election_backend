from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from jose import jwt, JWTError
from datetime import datetime, timedelta
import psycopg
from typing import Optional, List, Any, Dict, Tuple

token_blacklist = set()

# ==================== CONFIG ====================
SECRET_KEY = "your-secret-key-change-this-12345"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 10080  # 7 days

# Database connection string (your NeonDB)
DATABASE_URL = "postgresql://neondb_owner:npg_rs1bVogh7EtU@ep-weathered-math-a1pj9ocn-pooler.ap-southeast-1.aws.neon.tech/neondb?sslmode=require"

app = FastAPI(title="Login API")

# CORS - Allow all origins (change in production)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")

# ==================== MODELS ====================
class LoginResponse(BaseModel):
    access_token: str
    token_type: str
    user_id: int
    username: str
    role: str
    main_admin_id: int
    section_no: Optional[int] = None

class UserResponse(BaseModel):
    user_id: int
    username: str
    role: str
    main_admin_id: int
    section_no: Optional[int] = None


class SurveyInput(BaseModel):
    VoterID: Optional[int]
    VEName: Optional[str]
    Sex: Optional[str]
    HouseNo: Optional[str]
    Landmark: Optional[str]
    VAddress: Optional[str]
    Mobile: Optional[str]
    PartNo: Optional[int]
    SectionNo: Optional[int]
    VotersCount: Optional[int]
    Male: Optional[int]
    Female: Optional[int]
    Caste: Optional[str]
    Age: Optional[int]


class SurveySubmissionRequest(BaseModel):
    """Request body for submitting survey and marking voters as visited."""
    family_head_id: int
    selected_family_ids: list[int] = []
    house_number: str = ""
    landmark: Optional[str] = None
    mobile: Optional[str] = None
    caste: Optional[str] = None
    visited: int = 1
    main_admin_id: Optional[int] = None


class SurveySubmissionResponse(BaseModel):
    """Response after survey submission."""
    success: bool
    message: str
    survey_id: Optional[int] = None

# ==================== DATABASE ====================
def get_connection():
    return psycopg.connect(DATABASE_URL)

def validate_user(username: str, password: str):
    """Check username and password in database"""
    try:
        with get_connection() as conn:
            with conn.cursor() as cur:  
                cur.execute("""
                    SELECT "UserID", "Username", "Role", "ParentID","SectionNo"
                    FROM "User"
                    WHERE "Username" = %s AND "Password" = %s
                """, (username, password))
                
                row = cur.fetchone()
                if not row:
                    return None
                
                user_id, username, role, parent_id, section_no = row
                
                # Determine main_admin_id
                if parent_id in (None, 0):
                    main_admin_id = user_id
                else:
                    main_admin_id = parent_id
                
                return {
                    "user_id": user_id,
                    "username": username,
                    "role": role,
                    "main_admin_id": main_admin_id,
                    "section_no": section_no
                }
    except Exception as e:
        print(f"Database error: {e}")
        return None

def get_current_user(token: str = Depends(oauth2_scheme)):
    if token in token_blacklist:
        raise HTTPException(status_code=401, detail="Logged out token")

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    

# ==================== JWT FUNCTIONS ====================
def create_access_token(data: dict):
    """Create JWT token"""
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(token: str = Depends(oauth2_scheme)):
    """Validate JWT token and return user info"""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return {
            "user_id": payload.get("user_id"),
            "username": payload.get("username"),
            "role": payload.get("role"),
            "main_admin_id": payload.get("main_admin_id"),
            "section_no": payload.get("section_no"),
        }
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

# ==================== ENDPOINTS ====================
@app.get("/")
def root():
    return {"message": "Login API is running", "docs": "/docs"}

@app.post("/login", response_model=LoginResponse)
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    """
    Login endpoint
    - username: Your username
    - password: Your password
    """
    user = validate_user(form_data.username, form_data.password)
    
    if not user:
        raise HTTPException(
            status_code=401,
            detail="Invalid username or password"
        )
    
    # Create JWT token
    token = create_access_token({
        "user_id": user["user_id"],
        "username": user["username"],
        "role": user["role"],
        "main_admin_id": user["main_admin_id"],
        "section_no": user["section_no"]
    })
    
    return {
        "access_token": token,
        "token_type": "bearer",
        "user_id": user["user_id"],
        "username": user["username"],
        "role": user["role"],
        "main_admin_id": user["main_admin_id"],
        "section_no": user["section_no"]
    }

@app.get("/me", response_model=UserResponse)
def get_me(current_user = Depends(get_current_user)):
    """Get current logged-in user info"""
    return current_user

@app.get("/protected")
def protected_route(current_user = Depends(get_current_user)):
    """Example protected route - requires valid JWT token"""
    return {
        "message": f"Hello {current_user['username']}!",
        "user": current_user
    }


# -------------------- Data endpoints (for Streamlit client) --------------------
@app.get("/voters")
def get_voters(search: Optional[str] = None, limit: int = 500, offset: int = 0, current_user = Depends(get_current_user)):
    """Return voter list (paginated). Protected endpoint.

    - `search` (optional): case-insensitive substring search on `EName` or `VEName`
    - `limit`, `offset`: pagination
    The endpoint returns JSON: {"total": <int>, "rows": [ ... ]}
    """
    try:
        main_admin_id = current_user.get("main_admin_id") or current_user.get("user_id")
        visited_col = f"Visited_{main_admin_id}"

        with get_connection() as conn:
            # check column existence once
            with conn.cursor() as meta:
                meta.execute(
                    """
                    SELECT column_name FROM information_schema.columns
                    WHERE table_name = %s AND column_name = %s
                    """,
                    ("VoterList", visited_col)
                )
                col_exists = meta.fetchone() is not None

            visited_expr = f'"{visited_col}"' if col_exists else '"Visited"'

            # Build WHERE clause and parameters consistently
            where_clauses = ["TRUE"]
            where_params: list = []
            section_no = current_user.get("section_no")
            where_clauses.append('"SectionNo" = %s')
            where_params.append(section_no)
            if search:
                where_clauses.append('("EName" ILIKE %s OR "VEName" ILIKE %s)')
                where_params.extend([f"%{search}%", f"%{search}%"])

            where_sql = " AND ".join(where_clauses)

            # Data query (with limit/offset)
            data_sql = f'''
                SELECT "VoterID","PartNo","SectionNo","EName","VEName","Sex","Age",
                "Address","VAddress",{visited_expr} AS "Visited"
                FROM "VoterList"
                WHERE {where_sql}
                ORDER BY "VoterID"
                LIMIT %s OFFSET %s
            '''

            data_params = tuple(where_params + [limit, offset])

            with conn.cursor() as cur:
                cur.execute(data_sql, data_params)
                rows = cur.fetchall()
                columns = [d[0] for d in cur.description]
                data = [dict(zip(columns, r)) for r in rows]

            # Total count (use same WHERE params)
            count_sql = f'SELECT COUNT(*) FROM "VoterList" WHERE {where_sql}'
            with conn.cursor() as c2:
                c2.execute(count_sql, tuple(where_params))
                total = c2.fetchone()[0]

            return {"total": total, "rows": data}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/surveys")
def get_surveys(limit: int = 500, offset: int = 0, current_user = Depends(get_current_user)):
    """Return survey data for the current user's admin (paginated).

    Returns JSON: {"total": <int>, "rows": [ ... ]}
    """
    try:
        user_id = current_user.get("main_admin_id") or current_user.get("user_id")
        with get_connection() as conn:
            with conn.cursor() as cur:
                sql = '''
                    SELECT "SurveyNo","VoterID","VEName","Sex","HouseNo","Landmark","VAddress","Mobile","PartNo","SectionNo","VotersCount","Male","Female","Caste","Submission_Time","Age"
                    FROM "SurveyData"
                    WHERE "UserID" = %s
                    ORDER BY "SurveyNo"
                    LIMIT %s OFFSET %s
                '''
                cur.execute(sql, (user_id, limit, offset))
                rows = cur.fetchall()
                columns = [d[0] for d in cur.description]
                data = [dict(zip(columns, r)) for r in rows]

                # total
                cur.execute('SELECT COUNT(*) FROM "SurveyData" WHERE "UserID" = %s', (user_id,))
                total = cur.fetchone()[0]

                return {"total": total, "rows": data}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# -------------------- NEW: Summary / Paginated List / Filters APIs --------------------

@app.get("/voters/summary")
def get_voter_summary(current_user = Depends(get_current_user)):
    """
    Returns summary statistics needed for the dashboard:
    - total voters
    - visited count (Visited_<admin_id>)
    - male / female counts
    - top addresses (total, visited, not_visited) limited to top 50 (changeable)
    """
    try:
        main_admin_id = current_user.get("main_admin_id") or current_user.get("user_id")
        section_no = current_user.get("section_no")
        visited_col = f'Visited_{main_admin_id}'

        with get_connection() as conn:
            cur = conn.cursor()

            # total
            if section_no is not None:
                cur.execute('SELECT COUNT(*) FROM "VoterList" WHERE "SectionNo" = %s', (section_no,))
            else:
                cur.execute('SELECT COUNT(*) FROM "VoterList"')
            total = cur.fetchone()[0] or 0
            
            # visited (if column exists)
            cur.execute(
                """
                SELECT column_name FROM information_schema.columns
                WHERE table_name = %s AND column_name = %s
                """,
                ("VoterList", visited_col)
            )
            col_exists = cur.fetchone() is not None

            if col_exists:
                if section_no is not None:
                    cur.execute(f'SELECT COUNT(*) FROM "VoterList" WHERE "{visited_col}" = TRUE AND "SectionNo" = %s', (section_no,))
                else:
                    cur.execute(f'SELECT COUNT(*) FROM "VoterList" WHERE "{visited_col}" = TRUE')
                visited = cur.fetchone()[0] or 0
            else:
                # fallback to generic Visited column if present
                cur.execute(
                    """
                    SELECT column_name FROM information_schema.columns
                    WHERE table_name = %s AND column_name = %s
                    """,
                    ("VoterList", "Visited")
                )
                if cur.fetchone():
                    if section_no is not None:
                        cur.execute('SELECT COUNT(*) FROM "VoterList" WHERE "Visited" = TRUE AND "SectionNo" = %s', (section_no,))
                    else:
                        cur.execute('SELECT COUNT(*) FROM "VoterList" WHERE "Visited" = TRUE')
                    visited = cur.fetchone()[0] or 0
                else:
                    visited = 0                

            # sex breakdown (respect section)
            if section_no is not None:
                cur.execute('SELECT "Sex", COUNT(*) FROM "VoterList" WHERE "SectionNo" = %s GROUP BY "Sex"', (section_no,))
            else:
                cur.execute('SELECT "Sex", COUNT(*) FROM "VoterList" GROUP BY "Sex"')
            sex_rows = cur.fetchall()
            sex_breakdown = {r[0]: r[1] for r in sex_rows}
            
            # top addresses (by total voters) - include visited/not_visited counts
            address_sql = f'''
                SELECT "Address",
                       COUNT(*) AS total,
                       SUM(CASE WHEN "{visited_col}" = TRUE THEN 1 ELSE 0 END) AS visited,
                       SUM(CASE WHEN "{visited_col}" = FALSE THEN 1 ELSE 0 END) AS not_visited
                FROM "VoterList"
            '''
            if section_no is not None:
                address_sql += ' WHERE "SectionNo" = %s '
                address_sql += ' GROUP BY "Address" ORDER BY total DESC LIMIT 50'
                cur.execute(address_sql, (section_no,))
            else:
                address_sql += ' GROUP BY "Address" ORDER BY total DESC LIMIT 50'
                cur.execute(address_sql)

            address_rows = cur.fetchall()
            address_chart = []
            for row in address_rows:
                address_chart.append({
                    "Address": row[0],
                    "Total": int(row[1] or 0),
                    "Visited": int(row[2] or 0),
                    "NotVisited": int(row[3] or 0)
                })

        return {
            "total": int(total),
            "visited": int(visited),
            "not_visited": int(total) - int(visited),
            "sex_breakdown": sex_breakdown,
            "address_chart": address_chart
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/voters/list")
def get_voter_list(
    search: Optional[str] = None,
    address: Optional[str] = None,
    partno: Optional[str] = None,
    min_age: Optional[int] = None,
    max_age: Optional[int] = None,
    offset: int = 0,
    limit: int = 100,
    current_user = Depends(get_current_user)
):
    """
    Paginated, filterable voter list for UI.
    Returns {"total": <int>, "rows": [ ... ]} (total is count of matched rows)
    """
    try:
        main_admin_id = current_user.get("main_admin_id") or current_user.get("user_id")
        visited_col = f'Visited_{main_admin_id}'

        where_clauses = ["TRUE"]
        params: List[Any] = []
        section_no = current_user.get("section_no")
        where_clauses.append('"SectionNo" = %s')
        params.append(section_no)

        if search:
            where_clauses.append('("EName" ILIKE %s OR "VEName" ILIKE %s)')
            params.extend([f"%{search}%", f"%{search}%"])

        if address:
            where_clauses.append('"Address" = %s')
            params.append(address)

        if partno:
            where_clauses.append('"PartNo" = %s')
            params.append(partno)

        if min_age is not None:
            where_clauses.append('"Age" >= %s')
            params.append(min_age)

        if max_age is not None:
            where_clauses.append('"Age" <= %s')
            params.append(max_age)

        where_sql = " AND ".join(where_clauses)

        data_sql = f'''
            SELECT "VoterID","PartNo","SectionNo","EName","VEName","Sex","Age",
            "Address","VAddress", "{visited_col}" AS "Visited"
            FROM "VoterList"
            WHERE {where_sql}
            ORDER BY "VoterID"
            LIMIT %s OFFSET %s
        '''
        data_params = tuple(params + [limit, offset])

        count_sql = f'''SELECT COUNT(*) FROM "VoterList" WHERE {where_sql}'''

        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(data_sql, data_params)
                rows = cur.fetchall()
                columns = [d[0] for d in cur.description]
                data = [dict(zip(columns, r)) for r in rows]

                # total matched
                cur.execute(count_sql, tuple(params))
                total = cur.fetchone()[0]

        return {"total": total, "rows": data}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/voters_surname")
def get_voters_by_surname(
    surname: Optional[str] = None,
    offset: int = 0,
    limit: int = 500,
    current_user = Depends(get_current_user)
):

    try:
        with get_connection() as conn:
            with conn.cursor() as cur:

                # Build WHERE clause
                where_clause = "TRUE"
                params = []
                if surname:
                    where_clause = '"SectionNo" = %s AND "Surname" ILIKE %s'
                    params = [current_user.get("section_no"), f"%{surname}%"]


                # Fetch rows ordered by surname for grouping
                sql = f'''
                    SELECT "VEName", "Surname", "IDCardNo", "Sex" AS "Gender", "Age"
                    FROM "VoterList"
                    WHERE {where_clause}
                    ORDER BY "Surname" ASC, "VEName" ASC
                    LIMIT %s OFFSET %s
                '''
                params.extend([limit, offset])

                cur.execute(sql, params)
                rows = cur.fetchall()
                columns = [d[0] for d in cur.description]

                # Convert rows to dictionary
                raw = [dict(zip(columns, row)) for row in rows]

                # GROUP BY surname
                grouped = {}
                for r in raw:
                    s = r["Surname"].upper().strip()
                    if s not in grouped:
                        grouped[s] = []
                    grouped[s].append({
                        "VEName": r["VEName"],
                        "IDCardNo": r["IDCardNo"],
                        "Gender": r["Gender"],
                        "Age": r["Age"]
                    })

                # Convert to list
                result = [
                    {"surname": s, "members": grouped[s]}
                    for s in sorted(grouped.keys())
                ]

                # Count distinct surnames for pagination
                count_sql = f'''
                    SELECT COUNT(DISTINCT "Surname")
                    FROM "VoterList"
                    WHERE {where_clause}
                '''
                count_params = params[:-2] if surname else []
                cur.execute(count_sql, count_params)
                total = cur.fetchone()[0]

        return {
            "total": int(total),
            "surnames": result
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/voters/filters")
def get_voter_filters(current_user = Depends(get_current_user)):
    """
    Return unique filter lists (addresses, part numbers) and age range.
    Lightweight endpoints that avoid loading entire voter list.
    """
    try:
        section_no = current_user.get("section_no")
        with get_connection() as conn:
            with conn.cursor() as cur:
                if section_no is not None:
                    cur.execute('SELECT DISTINCT "Address" FROM "VoterList" WHERE "SectionNo" = %s', (section_no,))
                else:
                    cur.execute('SELECT DISTINCT "Address" FROM "VoterList"')
                addresses = [r[0] for r in cur.fetchall() if r[0] is not None]

                if section_no is not None:
                    cur.execute('SELECT DISTINCT "PartNo" FROM "VoterList" WHERE "SectionNo" = %s', (section_no,))
                else:
                    cur.execute('SELECT DISTINCT "PartNo" FROM "VoterList"')
                parts = [r[0] for r in cur.fetchall() if r[0] is not None]

                if section_no is not None:
                    cur.execute('SELECT MIN("Age"), MAX("Age") FROM "VoterList" WHERE "SectionNo" = %s', (section_no,))
                else:
                    cur.execute('SELECT MIN("Age"), MAX("Age") FROM "VoterList"')
                min_age, max_age = cur.fetchone()


        return {
            "address_list": sorted(addresses),
            "part_list": sorted(parts),
            "min_age": int(min_age) if min_age is not None else 0,
            "max_age": int(max_age) if max_age is not None else 100
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# -------------------- SUBMIT SURVEY (kept logic but hardened) --------------------
@app.post("/submit-survey", response_model=SurveySubmissionResponse)
def submit_survey(request: SurveySubmissionRequest, current_user = Depends(get_current_user)):
    """Submit survey form data and mark voters as visited.
    
    - Fetches family head details from VoterList
    - Counts male/female family members
    - Inserts survey into SurveyData
    - Updates Visited_<admin_id> column for all selected family members
    """
    try:
        main_admin_id = request.main_admin_id or current_user.get("main_admin_id") or current_user.get("user_id")
        section_no = current_user.get("section_no")
        

        with get_connection() as conn:
            with conn.cursor() as cur:
                # Fetch family head details
                cur.execute("""
                    SELECT "EName", "VEName", "SectionNo", "Sex", "Age", 
                    "VAddress", "PartNo"
                    FROM "VoterList"
                    WHERE "VoterID" = %s
                """, (request.family_head_id,))
                
                head_row = cur.fetchone()
                if not head_row:
                    raise HTTPException(status_code=404, detail="Family head not found")
                
                head = dict(zip([d[0] for d in cur.description], head_row))
                if section_no is not None and head.get("SectionNo") != section_no:
                    raise HTTPException(status_code=403, detail="Family head does not belong to your Section")
                
                # Get family member counts (only if ids provided)
                if request.selected_family_ids:
                    placeholders = ",".join(["%s"] * len(request.selected_family_ids))
                    cur.execute(
                        f'SELECT "Sex" FROM "VoterList" WHERE "VoterID" IN ({placeholders})',
                        request.selected_family_ids
                    )
                    fam_rows = cur.fetchall()
                    family_members = [dict(zip([d[0] for d in cur.description], row)) for row in fam_rows]
                    male_count = len([m for m in family_members if m["Sex"] in ("M", "Male")])
                    female_count = len([m for m in family_members if m["Sex"] in ("F", "Female")])
                    total_voters = len(family_members)
                else:
                    male_count = female_count = 0
                    total_voters = 0
                
                # Prepare head choice display name
                head_choice = f'{head["EName"]} ({head["VEName"]}) - {request.house_number}'
                
                # Insert into SurveyData
                cur.execute("""
                    INSERT INTO "SurveyData"
                    ("VoterID", "VEName", "HouseNo", "Landmark", "VAddress", "Mobile",
                    "SectionNo", "VotersCount", "Male", "Female", "Caste",
                    "Sex", "PartNo", "Age", "UserID")
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    RETURNING "SurveyNo"
                """, (
                    request.family_head_id,
                    head_choice,
                    request.house_number,
                    request.landmark,
                    head["VAddress"],
                    request.mobile,
                    head["SectionNo"],
                    total_voters,
                    male_count,
                    female_count,
                    request.caste,
                    head["Sex"],
                    head["PartNo"],
                    head["Age"],
                    main_admin_id
                ))
                
                survey_row = cur.fetchone()
                survey_id = survey_row[0] if survey_row else None
                
                # Mark voters as visited in the Visited_<admin_id> column
                if request.selected_family_ids:
                    visited_col = f'Visited_{main_admin_id}'

                    # check visited column exists before updating
                    cur.execute(
                        """
                        SELECT column_name FROM information_schema.columns
                        WHERE table_name = %s AND column_name = %s
                        """,
                        ("VoterList", visited_col)
                    )
                    if cur.fetchone() is None:
                        # If column doesn't exist, raise user-friendly error
                        raise HTTPException(status_code=400, detail=f"Visited column '{visited_col}' does not exist in VoterList")

                    placeholders = ",".join(["%s"] * len(request.selected_family_ids))
                    # Cast visited value to boolean - accept 0/1 or True/False
                    cur.execute(
                        f'UPDATE "VoterList" SET "{visited_col}" = %s::boolean WHERE "VoterID" IN ({placeholders})',
                        [bool(request.visited)] + request.selected_family_ids
                    )
                
                conn.commit()
        
        return SurveySubmissionResponse(
            success=True,
            message="Survey submitted successfully",
            survey_id=survey_id
        )
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error submitting survey: {str(e)}")


@app.post("/logout")
def logout(token: str = Depends(oauth2_scheme)):
    token_blacklist.add(token)
    return {"status": "success", "message": "Logged out successfully"}


# ==================== USER MANAGEMENT ENDPOINTS ====================
@app.post("/users")
def create_user(username: str, password: str, role: str, parent_id: Optional[int] = None, current_user = Depends(get_current_user)):
    """Create a new user under the current admin (parent)."""
    try:
        with get_connection() as conn:
            with conn.cursor() as cur:
                # Verify current user is admin
                current_admin = current_user.get("main_admin_id") or current_user.get("user_id")
                
                # Check if username already exists
                cur.execute('SELECT "UserID" FROM "User" WHERE "Username" = %s', (username,))
                if cur.fetchone():
                    raise HTTPException(status_code=400, detail="Username already exists")
                
                # Insert new user
                cur.execute("""
                    INSERT INTO "User" ("Username", "Password", "Role", "ParentID", "CreatedAt")
                    VALUES (%s, %s, %s, %s, NOW())
                    RETURNING "UserID"
                """, (username, password, role, parent_id or current_admin))
                
                new_user_id = cur.fetchone()[0]
                conn.commit()
        
        return {"success": True, "user_id": new_user_id, "username": username}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error creating user: {str(e)}")


@app.get("/users")
def list_users(parent_id: Optional[int] = None, current_user = Depends(get_current_user)):
    """List users created under a parent admin (for settings page)."""
    try:
        admin_id = parent_id or current_user.get("user_id")
        
        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT "UserID", "Username", "Role", "CreatedAt"
                    FROM "User"
                    WHERE "ParentID" = %s
                    ORDER BY "CreatedAt" DESC
                """, (admin_id,))
                
                rows = cur.fetchall()
                columns = [d[0] for d in cur.description]
                users = [dict(zip(columns, row)) for row in rows]
        
        return users
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching users: {str(e)}")


# ==================== RUN ====================
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

# from fastapi import FastAPI, HTTPException, Depends
# from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
# from fastapi.middleware.cors import CORSMiddleware
# from pydantic import BaseModel
# from jose import jwt, JWTError
# from datetime import datetime, timedelta
# import psycopg
# from typing import Optional, List, Any, Dict

# # ==================== CONFIG ====================
# SECRET_KEY = "your-secret-key-change-this-12345"
# ALGORITHM = "HS256"
# ACCESS_TOKEN_EXPIRE_MINUTES = 10080  # 7 days

# # Database connection string (update to your actual DB string)
# DATABASE_URL = "postgresql://neondb_owner:npg_rs1bVogh7EtU@ep-weathered-math-a1pj9ocn-pooler.ap-southeast-1.aws.neon.tech/neondb?sslmode=require"

# app = FastAPI(title="Login API")

# # CORS - Allow all origins (change in production)
# app.add_middleware(
#     CORSMiddleware,
#     allow_origins=["*"],
#     allow_credentials=True,
#     allow_methods=["*"],
#     allow_headers=["*"],
# )

# oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")

# # ==================== MODELS ====================
# class LoginResponse(BaseModel):
#     access_token: str
#     token_type: str
#     user_id: int
#     username: str
#     role: str
#     main_admin_id: int
#     section_no: Optional[int] = None


# class UserResponse(BaseModel):
#     user_id: int
#     username: str
#     role: str
#     main_admin_id: int
#     section_no: Optional[int] = None


# class SurveyInput(BaseModel):
#     VoterID: Optional[int]
#     VEName: Optional[str]
#     Sex: Optional[str]
#     HouseNo: Optional[str]
#     Landmark: Optional[str]
#     VAddress: Optional[str]
#     Mobile: Optional[str]
#     PartNo: Optional[int]
#     SectionNo: Optional[int]
#     VotersCount: Optional[int]
#     Male: Optional[int]
#     Female: Optional[int]
#     Caste: Optional[str]
#     Age: Optional[int]


# class SurveySubmissionRequest(BaseModel):
#     family_head_id: int
#     selected_family_ids: list[int] = []
#     house_number: str = ""
#     landmark: Optional[str] = None
#     mobile: Optional[str] = None
#     caste: Optional[str] = None
#     visited: int = 1
#     main_admin_id: Optional[int] = None


# class SurveySubmissionResponse(BaseModel):
#     success: bool
#     message: str
#     survey_id: Optional[int] = None

# # Simple token blacklist in-memory (rudimentary)
# token_blacklist = set()

# # ==================== DATABASE ====================

# def get_connection():
#     return psycopg.connect(DATABASE_URL)


# def validate_user(username: str, password: str):
#     """Check username and password in database and return user info including SectionNo"""
#     try:
#         with get_connection() as conn:
#             with conn.cursor() as cur:
#                 cur.execute("""
#                     SELECT "UserID", "Username", "Role", "ParentID", "SectionNo"
#                     FROM "User"
#                     WHERE "Username" = %s AND "Password" = %s
#                 """, (username, password))

#                 row = cur.fetchone()
#                 if not row:
#                     return None

#                 user_id, username_db, role, parent_id, section_no = row

#                 # Determine main_admin_id
#                 if parent_id in (None, 0):
#                     main_admin_id = user_id
#                 else:
#                     main_admin_id = parent_id

#                 return {
#                     "user_id": user_id,
#                     "username": username_db,
#                     "role": role,
#                     "main_admin_id": main_admin_id,
#                     "section_no": section_no,
#                 }
#     except Exception as e:
#         print(f"Database error: {e}")
#         return None


# # ==================== JWT FUNCTIONS ====================

# def create_access_token(data: dict):
#     """Create JWT token"""
#     to_encode = data.copy()
#     expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
#     to_encode.update({"exp": expire})
#     return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


# def get_current_user(token: str = Depends(oauth2_scheme)):
#     """Validate JWT token and return user info (including section_no)

#     This will be used as dependency for protected routes.
#     """
#     if token in token_blacklist:
#         raise HTTPException(status_code=401, detail="Logged out token")

#     try:
#         payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
#         return {
#             "user_id": payload.get("user_id"),
#             "username": payload.get("username"),
#             "role": payload.get("role"),
#             "main_admin_id": payload.get("main_admin_id"),
#             "section_no": payload.get("section_no"),
#         }
#     except JWTError:
#         raise HTTPException(status_code=401, detail="Invalid token")


# # ==================== ENDPOINTS ====================
# @app.get("/")
# def root():
#     return {"message": "Login API is running", "docs": "/docs"}


# @app.post("/login", response_model=LoginResponse)
# def login(form_data: OAuth2PasswordRequestForm = Depends()):
#     """
#     Login endpoint
#     - username: Your username
#     - password: Your password
#     """
#     user = validate_user(form_data.username, form_data.password)

#     if not user:
#         raise HTTPException(
#             status_code=401,
#             detail="Invalid username or password"
#         )

#     # Create JWT token (include section_no)
#     token = create_access_token({
#         "user_id": user["user_id"],
#         "username": user["username"],
#         "role": user["role"],
#         "main_admin_id": user["main_admin_id"],
#         "section_no": user.get("section_no")
#     })

#     return {
#         "access_token": token,
#         "token_type": "bearer",
#         "user_id": user["user_id"],
#         "username": user["username"],
#         "role": user["role"],
#         "main_admin_id": user["main_admin_id"],
#         "section_no": user.get("section_no")
#     }


# @app.get("/me", response_model=UserResponse)
# def get_me(current_user = Depends(get_current_user)):
#     """Get current logged-in user info"""
#     return current_user


# @app.post("/logout")
# def logout(token: str = Depends(oauth2_scheme)):
#     token_blacklist.add(token)
#     return {"status": "success", "message": "Logged out successfully"}


# # -------------------- Data endpoints (for Streamlit client) --------------------
# @app.get("/voters")
# def get_voters(search: Optional[str] = None, limit: int = 500, offset: int = 0, current_user = Depends(get_current_user)):
#     """Return voter list (paginated). Protected endpoint.

#     - `search` (optional): case-insensitive substring search on `EName` or `VEName`
#     - `limit`, `offset`: pagination
#     The endpoint returns JSON: {"total": <int>, "rows": [ ... ]}
#     """
#     try:
#         main_admin_id = current_user.get("main_admin_id") or current_user.get("user_id")
#         section_no = current_user.get("section_no")
#         visited_col = f"Visited_{main_admin_id}"

#         with get_connection() as conn:
#             # check column existence once
#             with conn.cursor() as meta:
#                 meta.execute(
#                     """
#                     SELECT column_name FROM information_schema.columns
#                     WHERE table_name = %s AND column_name = %s
#                     """,
#                     ("VoterList", visited_col)
#                 )
#                 col_exists = meta.fetchone() is not None

#             visited_expr = f'"{visited_col}"' if col_exists else '"Visited"'

#             # Build WHERE clause and parameters consistently
#             where_clauses = ["TRUE"]
#             where_params: list = []

#             # restrict by user's SectionNo if present
#             if section_no is not None:
#                 where_clauses.append('"SectionNo" = %s')
#                 where_params.append(section_no)

#             if search:
#                 where_clauses.append('("EName" ILIKE %s OR "VEName" ILIKE %s)')
#                 where_params.extend([f"%{search}%", f"%{search}%"])

#             where_sql = " AND ".join(where_clauses)

#             # Data query (with limit/offset)
#             data_sql = f'''
#                 SELECT "VoterID","PartNo","SectionNo","EName","VEName","Sex","Age",
#                 "Address","VAddress",{visited_expr} AS "Visited"
#                 FROM "VoterList"
#                 WHERE {where_sql}
#                 ORDER BY "VoterID"
#                 LIMIT %s OFFSET %s
#             '''

#             data_params = tuple(where_params + [limit, offset])

#             with conn.cursor() as cur:
#                 cur.execute(data_sql, data_params)
#                 rows = cur.fetchall()
#                 columns = [d[0] for d in cur.description]
#                 data = [dict(zip(columns, r)) for r in rows]

#             # Total count (use same WHERE params)
#             count_sql = f'SELECT COUNT(*) FROM "VoterList" WHERE {where_sql}'
#             with conn.cursor() as c2:
#                 c2.execute(count_sql, tuple(where_params))
#                 total = c2.fetchone()[0]

#             return {"total": total, "rows": data}
#     except Exception as e:
#         raise HTTPException(status_code=500, detail=str(e))


# @app.get("/voters/list")
# def get_voter_list(
#     search: Optional[str] = None,
#     address: Optional[str] = None,
#     partno: Optional[str] = None,
#     min_age: Optional[int] = None,
#     max_age: Optional[int] = None,
#     offset: int = 0,
#     limit: int = 100,
#     current_user = Depends(get_current_user)
# ):
#     """
#     Paginated, filterable voter list for UI. Returns {"total": <int>, "rows": [ ... ]}
#     """
#     try:
#         main_admin_id = current_user.get("main_admin_id") or current_user.get("user_id")
#         section_no = current_user.get("section_no")
#         visited_col = f'Visited_{main_admin_id}'

#         where_clauses = ["TRUE"]
#         params: List[Any] = []

#         # restrict by section
#         if section_no is not None:
#             where_clauses.append('"SectionNo" = %s')
#             params.append(section_no)

#         if search:
#             where_clauses.append('("EName" ILIKE %s OR "VEName" ILIKE %s)')
#             params.extend([f"%{search}%", f"%{search}%"])

#         if address:
#             where_clauses.append('"Address" = %s')
#             params.append(address)

#         if partno:
#             where_clauses.append('"PartNo" = %s')
#             params.append(partno)

#         if min_age is not None:
#             where_clauses.append('"Age" >= %s')
#             params.append(min_age)

#         if max_age is not None:
#             where_clauses.append('"Age" <= %s')
#             params.append(max_age)

#         where_sql = " AND ".join(where_clauses)

#         data_sql = f'''
#             SELECT "VoterID","PartNo","SectionNo","EName","VEName","Sex","Age",
#                    "Address","VAddress", "{visited_col}" AS "Visited"
#             FROM "VoterList"
#             WHERE {where_sql}
#             ORDER BY "VoterID"
#             LIMIT %s OFFSET %s
#         '''
#         data_params = tuple(params + [limit, offset])

#         count_sql = f'''SELECT COUNT(*) FROM "VoterList" WHERE {where_sql}'''

#         with get_connection() as conn:
#             with conn.cursor() as cur:
#                 cur.execute(data_sql, data_params)
#                 rows = cur.fetchall()
#                 columns = [d[0] for d in cur.description]
#                 data = [dict(zip(columns, r)) for r in rows]

#                 # total matched
#                 cur.execute(count_sql, tuple(params))
#                 total = cur.fetchone()[0]

#         return {"total": total, "rows": data}
#     except Exception as e:
#         raise HTTPException(status_code=500, detail=str(e))


# @app.get("/voters_surname")
# def get_voters_by_surname(
#     surname: Optional[str] = None,
#     offset: int = 0,
#     limit: int = 500,
#     current_user = Depends(get_current_user)
# ):
#     """
#     Get voters grouped by surname for the current user's SectionNo.
#     Returns grouped list with case-insensitive grouping.
#     """
#     try:
#         section_no = current_user.get("section_no")

#         with get_connection() as conn:
#             with conn.cursor() as cur:

#                 # Build WHERE clause
#                 where_clause = '"SectionNo" = %s' if section_no is not None else 'TRUE'
#                 params = [section_no] if section_no is not None else []
#                 if surname:
#                     where_clause += ' AND "Surname" ILIKE %s'
#                     params.append(f"%{surname}%")

#                 # Fetch rows ordered by surname for grouping
#                 sql = f'''
#                     SELECT "VEName", "Surname", "IDCardNo", "Sex" AS "Gender", "Age"
#                     FROM "VoterList"
#                     WHERE {where_clause}
#                     ORDER BY "Surname" ASC, "VEName" ASC
#                     LIMIT %s OFFSET %s
#                 '''
#                 params.extend([limit, offset])

#                 cur.execute(sql, params)
#                 rows = cur.fetchall()
#                 columns = [d[0] for d in cur.description]

#                 # Convert rows to dictionary
#                 raw = [dict(zip(columns, row)) for row in rows]

#                 # GROUP BY surname (case-insensitive)
#                 grouped: Dict[str, List[Dict[str, Any]]] = {}
#                 for r in raw:
#                     s_raw = r.get("Surname") or ""
#                     s = s_raw.upper().strip()
#                     if s == "":
#                         s = "UNKNOWN"
#                     if s not in grouped:
#                         grouped[s] = []
#                     grouped[s].append({
#                         "VEName": r["VEName"],
#                         "IDCardNo": r["IDCardNo"],
#                         "Gender": r["Gender"],
#                         "Age": r["Age"]
#                     })

#                 # Convert to list sorted by surname
#                 result = [
#                     {"surname": s, "members": grouped[s]}
#                     for s in sorted(grouped.keys())
#                 ]

#                 # Count distinct surnames for pagination (respecting section filter)
#                 count_sql = f'''
#                     SELECT COUNT(DISTINCT "Surname")
#                     FROM "VoterList"
#                     WHERE {where_clause}
#                 '''
#                 # When counting, avoid passing limit/offset
#                 count_params = params[:-2] if len(params) >= 2 else params
#                 cur.execute(count_sql, count_params)
#                 total = cur.fetchone()[0] or 0

#         return {
#             "total": int(total),
#             "surnames": result
#         }

#     except Exception as e:
#         raise HTTPException(status_code=500, detail=str(e))


# @app.get("/voters/summary")
# def get_voter_summary(current_user = Depends(get_current_user)):
#     """
#     Returns summary statistics needed for the dashboard, restricted to user's SectionNo.
#     """
#     try:
#         main_admin_id = current_user.get("main_admin_id") or current_user.get("user_id")
#         section_no = current_user.get("section_no")
#         visited_col = f'Visited_{main_admin_id}'

#         with get_connection() as conn:
#             cur = conn.cursor()

#             # total
#             if section_no is not None:
#                 cur.execute('SELECT COUNT(*) FROM "VoterList" WHERE "SectionNo" = %s', (section_no,))
#             else:
#                 cur.execute('SELECT COUNT(*) FROM "VoterList"')
#             total = cur.fetchone()[0] or 0

#             # visited (if column exists)
#             cur.execute(
#                 """
#                 SELECT column_name FROM information_schema.columns
#                 WHERE table_name = %s AND column_name = %s
#                 """,
#                 ("VoterList", visited_col)
#             )
#             col_exists = cur.fetchone() is not None

#             if col_exists:
#                 if section_no is not None:
#                     cur.execute(f'SELECT COUNT(*) FROM "VoterList" WHERE "{visited_col}" = TRUE AND "SectionNo" = %s', (section_no,))
#                 else:
#                     cur.execute(f'SELECT COUNT(*) FROM "VoterList" WHERE "{visited_col}" = TRUE')
#                 visited = cur.fetchone()[0] or 0
#             else:
#                 # fallback to generic Visited column if present
#                 cur.execute(
#                     """
#                     SELECT column_name FROM information_schema.columns
#                     WHERE table_name = %s AND column_name = %s
#                     """,
#                     ("VoterList", "Visited")
#                 )
#                 if cur.fetchone():
#                     if section_no is not None:
#                         cur.execute('SELECT COUNT(*) FROM "VoterList" WHERE "Visited" = TRUE AND "SectionNo" = %s', (section_no,))
#                     else:
#                         cur.execute('SELECT COUNT(*) FROM "VoterList" WHERE "Visited" = TRUE')
#                     visited = cur.fetchone()[0] or 0
#                 else:
#                     visited = 0

#             # sex breakdown (respect section)
#             if section_no is not None:
#                 cur.execute('SELECT "Sex", COUNT(*) FROM "VoterList" WHERE "SectionNo" = %s GROUP BY "Sex"', (section_no,))
#             else:
#                 cur.execute('SELECT "Sex", COUNT(*) FROM "VoterList" GROUP BY "Sex"')
#             sex_rows = cur.fetchall()
#             sex_breakdown = {r[0]: r[1] for r in sex_rows}

#             # top addresses (by total voters) - include visited/not_visited counts
#             address_sql = f'''
#                 SELECT "Address",
#                        COUNT(*) AS total,
#                        SUM(CASE WHEN "{visited_col}" = TRUE THEN 1 ELSE 0 END) AS visited,
#                        SUM(CASE WHEN "{visited_col}" = FALSE THEN 1 ELSE 0 END) AS not_visited
#                 FROM "VoterList"
#             '''
#             if section_no is not None:
#                 address_sql += ' WHERE "SectionNo" = %s '
#                 address_sql += ' GROUP BY "Address" ORDER BY total DESC LIMIT 50'
#                 cur.execute(address_sql, (section_no,))
#             else:
#                 address_sql += ' GROUP BY "Address" ORDER BY total DESC LIMIT 50'
#                 cur.execute(address_sql)

#             address_rows = cur.fetchall()
#             address_chart = []
#             for row in address_rows:
#                 address_chart.append({
#                     "Address": row[0],
#                     "Total": int(row[1] or 0),
#                     "Visited": int(row[2] or 0),
#                     "NotVisited": int(row[3] or 0)
#                 })

#         return {
#             "total": int(total),
#             "visited": int(visited),
#             "not_visited": int(total) - int(visited),
#             "sex_breakdown": sex_breakdown,
#             "address_chart": address_chart
#         }
#     except Exception as e:
#         raise HTTPException(status_code=500, detail=str(e))


# @app.get("/voters/filters")
# def get_voter_filters(current_user = Depends(get_current_user)):
#     """
#     Return unique filter lists (addresses, part numbers) and age range.
#     """
#     try:
#         section_no = current_user.get("section_no")
#         with get_connection() as conn:
#             with conn.cursor() as cur:
#                 if section_no is not None:
#                     cur.execute('SELECT DISTINCT "Address" FROM "VoterList" WHERE "SectionNo" = %s', (section_no,))
#                 else:
#                     cur.execute('SELECT DISTINCT "Address" FROM "VoterList"')
#                 addresses = [r[0] for r in cur.fetchall() if r[0] is not None]

#                 if section_no is not None:
#                     cur.execute('SELECT DISTINCT "PartNo" FROM "VoterList" WHERE "SectionNo" = %s', (section_no,))
#                 else:
#                     cur.execute('SELECT DISTINCT "PartNo" FROM "VoterList"')
#                 parts = [r[0] for r in cur.fetchall() if r[0] is not None]

#                 if section_no is not None:
#                     cur.execute('SELECT MIN("Age"), MAX("Age") FROM "VoterList" WHERE "SectionNo" = %s', (section_no,))
#                 else:
#                     cur.execute('SELECT MIN("Age"), MAX("Age") FROM "VoterList"')
#                 min_age, max_age = cur.fetchone()

#         return {
#             "address_list": sorted(addresses),
#             "part_list": sorted(parts),
#             "min_age": int(min_age) if min_age is not None else 0,
#             "max_age": int(max_age) if max_age is not None else 100
#         }
#     except Exception as e:
#         raise HTTPException(status_code=500, detail=str(e))


# # -------------------- SUBMIT SURVEY (kept logic but hardened) --------------------
# @app.post("/submit-survey", response_model=SurveySubmissionResponse)
# def submit_survey(request: SurveySubmissionRequest, current_user = Depends(get_current_user)):
#     """Submit survey form data and mark voters as visited.
#     """
#     try:
#         main_admin_id = request.main_admin_id or current_user.get("main_admin_id") or current_user.get("user_id")
#         section_no = current_user.get("section_no")

#         with get_connection() as conn:
#             with conn.cursor() as cur:
#                 # Fetch family head details and ensure section matches
#                 cur.execute("""
#                     SELECT "EName", "VEName", "SectionNo", "Sex", "Age",
#                            "VAddress", "PartNo"
#                     FROM "VoterList"
#                     WHERE "VoterID" = %s
#                 """, (request.family_head_id,))

#                 head_row = cur.fetchone()
#                 if not head_row:
#                     raise HTTPException(status_code=404, detail="Family head not found")

#                 head = dict(zip([d[0] for d in cur.description], head_row))

#                 if section_no is not None and head.get("SectionNo") != section_no:
#                     raise HTTPException(status_code=403, detail="Family head does not belong to your Section")

#                 # Get family member counts (only if ids provided) - ensure members belong to same section
#                 if request.selected_family_ids:
#                     placeholders = ",".join(["%s"] * len(request.selected_family_ids))
#                     cur.execute(
#                         f'SELECT "Sex" FROM "VoterList" WHERE "VoterID" IN ({placeholders})',
#                         request.selected_family_ids
#                     )
#                     fam_rows = cur.fetchall()
#                     family_members = [dict(zip([d[0] for d in cur.description], row)) for row in fam_rows]
#                     male_count = len([m for m in family_members if m["Sex"] in ("M", "Male")])
#                     female_count = len([m for m in family_members if m["Sex"] in ("F", "Female")])
#                     total_voters = len(family_members)
#                 else:
#                     male_count = female_count = 0
#                     total_voters = 0

#                 # Prepare head choice display name
#                 head_choice = f'{head["EName"]} ({head["VEName"]}) - {request.house_number}'

#                 # Insert into SurveyData
#                 cur.execute("""
#                     INSERT INTO "SurveyData"
#                     ("VoterID", "VEName", "HouseNo", "Landmark", "VAddress", "Mobile",
#                     "SectionNo", "VotersCount", "Male", "Female", "Caste",
#                     "Sex", "PartNo", "Age", "UserID")
#                     VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
#                     RETURNING "SurveyNo"
#                 """, (
#                     request.family_head_id,
#                     head_choice,
#                     request.house_number,
#                     request.landmark,
#                     head["VAddress"],
#                     request.mobile,
#                     head["SectionNo"],
#                     total_voters,
#                     male_count,
#                     female_count,
#                     request.caste,
#                     head["Sex"],
#                     head["PartNo"],
#                     head["Age"],
#                     main_admin_id
#                 ))

#                 survey_row = cur.fetchone()
#                 survey_id = survey_row[0] if survey_row else None

#                 # Mark voters as visited in the Visited_<admin_id> column
#                 if request.selected_family_ids:
#                     visited_col = f'Visited_{main_admin_id}'

#                     # check visited column exists before updating
#                     cur.execute(
#                         """
#                         SELECT column_name FROM information_schema.columns
#                         WHERE table_name = %s AND column_name = %s
#                         """,
#                         ("VoterList", visited_col)
#                     )
#                     if cur.fetchone() is None:
#                         # If column doesn't exist, raise user-friendly error
#                         raise HTTPException(status_code=400, detail=f"Visited column '{visited_col}' does not exist in VoterList")

#                     placeholders = ",".join(["%s"] * len(request.selected_family_ids))
#                     # Cast visited value to boolean - accept 0/1 or True/False
#                     cur.execute(
#                         f'UPDATE "VoterList" SET "{visited_col}" = %s::boolean WHERE "VoterID" IN ({placeholders})',
#                         [bool(request.visited)] + request.selected_family_ids
#                     )

#                 conn.commit()

#         return SurveySubmissionResponse(
#             success=True,
#             message="Survey submitted successfully",
#             survey_id=survey_id
#         )

#     except HTTPException:
#         raise
#     except Exception as e:
#         raise HTTPException(status_code=500, detail=f"Error submitting survey: {str(e)}")


# # ==================== USER MANAGEMENT ENDPOINTS ====================
# @app.post("/users")
# def create_user(username: str, password: str, role: str, parent_id: Optional[int] = None, section_no: Optional[int] = None, current_user = Depends(get_current_user)):
#     """Create a new user under the current admin (parent)."""
#     try:
#         with get_connection() as conn:
#             with conn.cursor() as cur:
#                 # Verify current user is admin
#                 current_admin = current_user.get("main_admin_id") or current_user.get("user_id")

#                 # Check if username already exists
#                 cur.execute('SELECT "UserID" FROM "User" WHERE "Username" = %s', (username,))
#                 if cur.fetchone():
#                     raise HTTPException(status_code=400, detail="Username already exists")

#                 # Insert new user
#                 cur.execute("""
#                     INSERT INTO "User" ("Username", "Password", "Role", "ParentID", "SectionNo", "CreatedAt")
#                     VALUES (%s, %s, %s, %s, %s, NOW())
#                     RETURNING "UserID"
#                 """, (username, password, role, parent_id or current_admin, section_no))

#                 new_user_id = cur.fetchone()[0]
#                 conn.commit()

#         return {"success": True, "user_id": new_user_id, "username": username}
#     except HTTPException:
#         raise
#     except Exception as e:
#         raise HTTPException(status_code=500, detail=f"Error creating user: {str(e)}")


# @app.get("/users")
# def list_users(parent_id: Optional[int] = None, current_user = Depends(get_current_user)):
#     """List users created under a parent admin (for settings page)."""
#     try:
#         admin_id = parent_id or current_user.get("user_id")

#         with get_connection() as conn:
#             with conn.cursor() as cur:
#                 cur.execute("""
#                     SELECT "UserID", "Username", "Role", "CreatedAt", "SectionNo"
#                     FROM "User"
#                     WHERE "ParentID" = %s
#                     ORDER BY "CreatedAt" DESC
#                 """, (admin_id,))

#                 rows = cur.fetchall()
#                 columns = [d[0] for d in cur.description]
#                 users = [dict(zip(columns, row)) for row in rows]

#         return users
#     except Exception as e:
#         raise HTTPException(status_code=500, detail=f"Error fetching users: {str(e)}")


# # ==================== RUN ====================
# if __name__ == "__main__":
#     import uvicorn
#     uvicorn.run(app, host="0.0.0.0", port=8000)
