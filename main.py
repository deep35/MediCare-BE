import os
import secrets
import hmac
import hashlib
import uuid
import logging
from bson import ObjectId
from datetime import datetime, timedelta
from fastapi import FastAPI, HTTPException, BackgroundTasks, Depends 
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.encoders import jsonable_encoder
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
import redis.asyncio as aioredis
import phonenumbers
import jwt
from dotenv import load_dotenv
from twilio.rest import Client
from motor.motor_asyncio import AsyncIOMotorClient

# Load env
load_dotenv()

# Config (from env)
REDIS_URL = os.getenv("REDIS_URL")
TWILIO_ACCOUNT_SID = os.getenv("TWILIO_ACCOUNT_SID")
TWILIO_AUTH_TOKEN = os.getenv("TWILIO_AUTH_TOKEN")
TWILIO_PHONE_NUMBER = os.getenv("TWILIO_PHONE_NUMBER")
HMAC_SECRET = os.getenv("HMAC_SECRET") or secrets.token_hex(32)
SECRET_KEY = os.getenv("SECRET_KEY") or secrets.token_hex(32)
ALGORITHM = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_SECONDS = int(os.getenv("ACCESS_TOKEN_EXPIRE_SECONDS", 3600))
OTP_TTL_SECONDS = int(os.getenv("OTP_TTL_SECONDS", 300))  # 5 minutes
# MongoDB Setup
MONGO_URI = os.getenv("MONGO_URI")
MONGO_DB = os.getenv("MONGO_DB", "medicine_cart")

mongo_client = None
db = None

# Twilio client (optional; for local dev you can print OTP instead)
twilio_client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN) if TWILIO_ACCOUNT_SID and TWILIO_AUTH_TOKEN else None

# Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("auth_service")

app = FastAPI(title="Backend for MedicineCart")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/static", StaticFiles(directory="static"), name="static")

redis =None  # will be set on startup



# Models
class PhoneRequest(BaseModel):
    phone_number: str

class VerifyRequest(BaseModel):
    phone_number: str
    otp: str
# ----- MODELS -----
class AddToCartRequest(BaseModel):
    product_id: int
    quantity: int

class UserDetails(BaseModel):
    name: str
    email: str
    address: str


class VerifyOrderDeliveryRequest(BaseModel):
    order_id: str
    otp: str

# Helpers
def normalize_phone_e164(phone: str) -> str:
    try:
        parsed = phonenumbers.parse(phone, None)  # expects +country format or tries to parse
        if not phonenumbers.is_valid_number(parsed):
            raise ValueError("Invalid phone number")
        return phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
    except Exception as exc:
        raise ValueError("Invalid phone number format") from exc

def generate_otp(length: int = 6) -> str:
    digits = "0123456789"
    return "".join(secrets.choice(digits) for _ in range(length))

def hmac_hash(value: str) -> str:
    return hmac.new(HMAC_SECRET.encode(), value.encode(), hashlib.sha256).hexdigest()

def create_access_token(phone: str) -> str:
    now = datetime.utcnow()
    jti = str(uuid.uuid4())
    payload = {
        "sub": phone,
        "iat": now,
        "nbf": now,
        "exp": now + timedelta(seconds=ACCESS_TOKEN_EXPIRE_SECONDS),
        "jti": jti,
        "typ": "access"
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    return token

async def deliver_otp(phone: str, otp: str):
    # background delivery -- replace or expand with retries / delivery checks
    try:
        if twilio_client:
            twilio_client.messages.create(to=phone, from_=TWILIO_PHONE_NUMBER, body=f"Your OTP is {otp}")
            logger.info("OTP sent via Twilio to %s", phone)
        else:
            # for local development: log to console
            logger.info("[DEV OTP] phone=%s otp=%s", phone, otp)
    except Exception:
        logger.exception("Failed to deliver OTP to %s", phone)
        # optionally: increment a failure metric or retry

# Redis key helpers
def otp_key(phone: str) -> str:
    return f"otp:{phone}"

# ----- AUTH DEPENDENCY -----
security = HTTPBearer()

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload["sub"]
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

def delivery_otp_key(order_id: str) -> str:
    return f"delivery_otp:{order_id}"

# Startup/shutdown
@app.on_event("startup")
async def startup():
    global redis, mongo_client, db, users_col, products_collection, carts_col, orders_col
    redis = await aioredis.from_url(REDIS_URL, decode_responses=True)
    mongo_client = AsyncIOMotorClient(MONGO_URI)
    db = mongo_client[MONGO_DB]
    
    users_col = lambda: db["users"]
    products_collection = db["products_collection"]
    carts_col = lambda: db["carts"]
    orders_col = lambda: db["orders"]
    logger.info("Startup: Connected to Redis and MongoDB")

@app.on_event("shutdown")
async def shutdown():
    global redis, mongo_client, db, users_col, products_collection, carts_col, orders_col
    if redis:
        await redis.close()
    if mongo_client:
        mongo_client.close()
    logger.info("Shutdown: Connections to Redis and MongoDB closed")


# Endpoints
@app.post("/send-otp")
async def send_otp_route(req: PhoneRequest, background_tasks: BackgroundTasks):
    logger.info("Received OTP request for phone number: %s", req.phone_number)
    try:
        phone = normalize_phone_e164(req.phone_number)
    except ValueError as e:
        logger.warning("Invalid phone number format: %s", req.phone_number)
        raise HTTPException(status_code=400, detail=str(e))

    otp = generate_otp(6)
    hashed = hmac_hash(otp)
    await redis.set(otp_key(phone), hashed, ex=OTP_TTL_SECONDS)
    logger.info("OTP generated and stored (hashed) in Redis for phone: %s", phone)

    background_tasks.add_task(deliver_otp, phone, otp)
    logger.info("OTP delivery task added to background for phone: %s", phone)

    return {"detail": "OTP dispatched", "ttl_seconds": OTP_TTL_SECONDS}


@app.post("/verify-otp")
async def verify_otp_route(req: VerifyRequest):
    logger.info("Verifying OTP for phone: %s", req.phone_number)
    try:
        phone = normalize_phone_e164(req.phone_number)
    except ValueError:
        logger.warning("Invalid phone number format during verification: %s", req.phone_number)
        raise HTTPException(status_code=400, detail="Invalid phone number")

    stored = await redis.get(otp_key(phone))
    if not stored:
        logger.warning("OTP not found or expired for phone: %s", phone)
        raise HTTPException(status_code=400, detail="OTP not found or expired")

    provided_h = hmac_hash(req.otp)
    if not hmac.compare_digest(provided_h, stored):
        logger.warning("Invalid OTP provided for phone: %s", phone)
        raise HTTPException(status_code=400, detail="Invalid OTP")

    await redis.delete(otp_key(phone))
    logger.info("OTP verified and deleted for phone: %s", phone)

    access_token = create_access_token(phone)
    logger.info("Access token generated for phone: %s", phone)
    return {"access_token": access_token, "token_type": "bearer"}



# ----- PRODUCTS API -----
@app.get("/products")
async def get_products():
    products = await products_collection.find(
        {}, 
        {"_id": 0, "id": 1, "name": 1, "price": 1, "quantity": 1, "image": 1}
    ).to_list(length=None)  # convert async cursor to list
    return {"products": products}


# ----- ADD TO CART -----
@app.post("/cart/add")
async def add_to_cart(req: AddToCartRequest, user_phone: str = Depends(get_current_user)):
    logger.info("User %s is adding product %s (qty=%s) to cart", user_phone, req.product_id, req.quantity)
    product = await products_collection.find_one({"id": str(req.product_id)})  # IDs are strings now
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")

    if req.quantity <= 0:
        raise HTTPException(status_code=400, detail="Quantity must be positive")

    cart = await carts_col().find_one({"phone": user_phone})
    if not cart:
        cart = {"phone": user_phone, "items": []}

    for item in cart["items"]:
        if item["id"] == str(req.product_id):
            item["qty"] += req.quantity
            break
    else:
        cart["items"].append({"id": str(req.product_id), "qty": req.quantity})

    await carts_col().update_one({"phone": user_phone}, {"$set": cart}, upsert=True)
    logger.info("Cart updated for user: %s", user_phone)
    return {"message": "Added to cart", "cart": cart["items"]}


@app.get("/cart")
async def get_cart(user_phone: str = Depends(get_current_user)):
    logger.info("Fetching cart for user: %s", user_phone)
    # Get user cart
    cart = await carts_col().find_one({"phone": user_phone}, {"_id": 0, "items": 1})
    if not cart or not cart.get("items"):
        return {"cart": []}

    detailed_items = []
    for item in cart["items"]:
        # Fetch product details by ID
        product = await products_collection.find_one({"id": str(item["id"])}, {"_id": 0})
        if product:
            detailed_items.append({
                "id": product["id"],
                "name": product.get("name"),
                "image": product.get("image"),
                "price": product.get("price"),
                "quantity": item["qty"],  # quantity user added in cart
            })

    return {"cart": detailed_items}


# ----- USER DETAILS -----
@app.post("/user/details")
async def save_user_details(details: UserDetails, user_phone: str = Depends(get_current_user)):
    logger.info("Saving user details for phone: %s", user_phone)
    user_data = {**details.dict(), "phone": user_phone}
    await users_col().update_one(
        {"phone": user_phone},
        {"$set": user_data},
        upsert=True
    )
    logger.info("User details saved for phone: %s", user_phone)
    return {"message": "User details saved", "user": user_data}


@app.get("/user/details")
async def get_user_details(user_phone: str = Depends(get_current_user)):
    logger.info("Fetching user details for phone: %s", user_phone)
    user = await users_col().find_one({"phone": user_phone}, {"_id": 0})
    return {"user": user or {}}


# ----- PLACE ORDER -----
@app.post("/order/place")
async def place_order(user_phone: str = Depends(get_current_user)):
    logger.info("User %s is placing an order", user_phone)
    # Fetch cart
    cart = await carts_col().find_one({"phone": user_phone})
    if not cart or not cart.get("items"):
        raise HTTPException(status_code=400, detail="Cart is empty")

    # Fetch user details (excluding _id)
    user = await users_col().find_one({"phone": user_phone}, {"_id": 0})
    if not user:
        raise HTTPException(status_code=400, detail="User details missing")

    total = 0
    items = []

    # Build order items and calculate total
    for item in cart["items"]:
        product = await products_collection.find_one({"id": str(item["id"])})
        if product:
            total += product["price"] * item["qty"]
            items.append({
                "id": product["id"],
                "name": product["name"],
                "qty": item["qty"],
                "price": product["price"]
            })

    order = {
        "user": user,
        "items": items,
        "total": total,
        "status": "Order Placed",
        "created_at": datetime.utcnow().isoformat(),
    }

    # Insert order in MongoDB
    result = await orders_col().insert_one(order)

    # Clear user cart
    await carts_col().delete_one({"phone": user_phone})
    logger.info("Order created with ID %s for user %s", str(result.inserted_id), user_phone)

    # Return response safely, converting ObjectIds to string if any
    response_data = {
        "message": "Order placed successfully",
        "order_id": str(result.inserted_id),
        "order": order
    }
    logger.info("Cart cleared after order placed for user %s", user_phone)

    return jsonable_encoder(response_data, custom_encoder={ObjectId: str})

@app.get("/orders")
async def get_orders(user_phone: str = Depends(get_current_user)):
    orders = await orders_col().find({"user.phone": user_phone}, {"_id": 0}).to_list(None)
    return {"orders": orders}


@app.get("/admin/orders")
async def get_all_orders():
    """This is for admin side Order list getting"""
    logger.info("Fetching all orders for admin")

    cursor = orders_col().find({}, {"_id": 1, "status": 1, "created_at": 1, "user.phone": 1})

    orders = []
    async for order in cursor:
        orders.append({
            "order_id": str(order["_id"]),
            "status": order.get("status", "Unknown"),
            "created_at": order.get("created_at"),
            "phone": order.get("user", {}).get("phone", "Unknown")
        })

    return {"orders": orders}

# ----- ORDER STATUS + DELIVERY OTP -----
@app.post("/order/update-status/{order_id}")
async def update_order_status(order_id: str, status: str):
    logger.info("Updating status for order %s to %s", order_id, status)
    if status not in ["Order Placed", "Dispatched", "Delivered", "Cancelled"]:
        raise HTTPException(status_code=400, detail="Invalid order status")

    try:
        obj_id = ObjectId(order_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid order ID format")

    order = await orders_col().find_one({"_id": obj_id})
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")

    await orders_col().update_one({"_id": obj_id}, {"$set": {"status": status}})
    logger.info("Order %s status updated to %s", order_id, status)
    return {"message": f"Order status updated to {status}"}


@app.post("/order/send-delivery-otp/{order_id}")
async def send_delivery_otp(order_id: str, background_tasks: BackgroundTasks):
    logger.info("Request to send delivery OTP for order: %s", order_id)
    try:
        obj_id = ObjectId(order_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid order ID format")

    order = await orders_col().find_one({"_id": obj_id})
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")

    user = order.get("user")
    if not user:
        raise HTTPException(status_code=400, detail="User details missing for this order")

    phone = user.get("phone")
    if not phone:
        raise HTTPException(status_code=400, detail="Phone number not linked with user")

    otp = generate_otp(6)
    hashed = hmac_hash(otp)

    await redis.set(delivery_otp_key(order_id), hashed, ex=OTP_TTL_SECONDS)
    background_tasks.add_task(deliver_otp, phone, otp)

    logger.info("Delivery OTP stored in Redis and background task queued for order: %s", order_id)
    return {
        "message": f"Delivery OTP sent to {phone}",
        "ttl_seconds": OTP_TTL_SECONDS
    }



@app.post("/order/verify-delivery")
async def verify_order_delivery(req: VerifyOrderDeliveryRequest):
    logger.info("Verifying delivery OTP for order: %s", req.order_id)
    stored = await redis.get(delivery_otp_key(req.order_id))
    if not stored:
        raise HTTPException(status_code=400, detail="OTP not found or expired")

    if not hmac.compare_digest(hmac_hash(req.otp), stored):
        raise HTTPException(status_code=400, detail="Invalid OTP")

    try:
        obj_id = ObjectId(req.order_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid order ID format")

    order = await orders_col().find_one({"_id": obj_id})
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")

    logger.info("OTP verified. Updating order status and reducing inventory.")

    await orders_col().update_one({"_id": obj_id}, {"$set": {"status": "Delivered"}})
    await redis.delete(delivery_otp_key(req.order_id))

    # Reduce stock in product collection
    for item in order["items"]:
        await products_collection.update_one(
            {"id": item["id"]},
            {"$inc": {"quantity": -item["qty"]}}
        )
    logger.info("Order %s marked as delivered", req.order_id)
    return {
        "message": "Order delivery verified and stock updated",
        "order_id": req.order_id,
        "status": "Delivered"
    }