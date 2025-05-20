from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Date
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.exc import IntegrityError
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta

# DATABASE SETUP
DATABASE_URL = "sqlite:///./emp_tracking.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)
Base = declarative_base()

# MODELS
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    password = Column(String)
    role = Column(String)

class Movement(Base):
    __tablename__ = "movements"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String)
    from_location = Column(String)
    to_location = Column(String)
    timestamp = Column(DateTime, default=datetime.utcnow)

class Leave(Base):
    __tablename__ = "leaves"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String)
    from_date = Column(Date)
    to_date = Column(Date)
    reason = Column(String)

Base.metadata.drop_all(bind=engine)  # 🔁 DROP existing schema
Base.metadata.create_all(bind=engine)

# AUTH SETUP
SECRET_KEY = "supersecret"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def verify_password(plain, hashed):
    return pwd_context.verify(plain, hashed)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if not username:
            raise credentials_exception
        user = db.query(User).filter(User.username == username).first()
        if not user:
            raise credentials_exception
        return user
    except JWTError:
        raise credentials_exception

# SCHEMAS
class UserCreate(BaseModel):
    username: str
    password: str
    role: str

class MovementCreate(BaseModel):
    from_location: str
    to_location: str

class LeaveCreate(BaseModel):
    from_date: str
    to_date: str
    reason: str

# APP SETUP
app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ENDPOINTS

@app.post("/register")
def register(user: UserCreate, db: Session = Depends(get_db)):
    try:
        normalized_username = user.username.strip().lower()
        print(f"Registering: {normalized_username}")

        existing = db.query(User).filter(User.username == normalized_username).first()
        if existing:
            raise HTTPException(status_code=400, detail="Username already exists")

        hashed_pw = get_password_hash(user.password)
        db_user = User(username=normalized_username, password=hashed_pw, role=user.role)
        db.add(db_user)
        db.commit()
        db.refresh(db_user)
        return {"message": "User created successfully"}

    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=400, detail="Username already exists (DB constraint)")
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Registration failed: {e}")

@app.post("/token")
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    username = form_data.username.strip().lower()
    user = db.query(User).filter(User.username == username).first()
    if not user or not verify_password(form_data.password, user.password):
        raise HTTPException(status_code=400, detail="Invalid credentials")
    access_token = create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/movements")
def get_movements(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    return db.query(Movement).all()

@app.post("/movement")
def add_movement(movement: MovementCreate, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    move = Movement(
        username=current_user.username,
        from_location=movement.from_location,
        to_location=movement.to_location,
    )
    db.add(move)
    db.commit()
    db.refresh(move)
    return {"message": "Movement added"}

@app.get("/leaves")
def get_leaves(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    return db.query(Leave).all()

@app.post("/leave")
def apply_leave(lv: LeaveCreate, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    leave = Leave(
        username=current_user.username,
        from_date=datetime.strptime(lv.from_date, "%Y-%m-%d").date(),
        to_date=datetime.strptime(lv.to_date, "%Y-%m-%d").date(),
        reason=lv.reason,
    )
    db.add(leave)
    db.commit()
    db.refresh(leave)
    return {"message": "Leave applied"}

@app.get("/users")
def get_users(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Only admin can view users")
    return db.query(User).all()

@app.get("/")
def home():
    return {"message": "✅ Employee Tracking API is running"}
