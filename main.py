import os, re, uuid, time, json, hmac, base64, hashlib
from datetime import datetime, timezone
from typing import Optional
import httpx
from fastapi import FastAPI, HTTPException, Depends, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
from pymongo import MongoClient, ASCENDING
from passlib.context import CryptContext

app = FastAPI(title="Reshitogram API", version="0.1.0")
MONGO_URI=os.getenv("MONGODB_URI",""); DB_NAME=os.getenv("MONGODB_DB","reshitogram")
JWT_SECRET=os.getenv("JWT_SECRET",""); GROQ_API_KEY=os.getenv("GROQ_API_KEY","")
CF_ACCOUNT=os.getenv("CLOUDFLARE_ACCOUNT_ID",""); CF_TOKEN=os.getenv("CLOUDFLARE_API_TOKEN","")
WEATHER_KEY=os.getenv("OPENWEATHER_API_KEY","")
mongo=MongoClient(MONGO_URI,serverSelectionTimeoutMS=5000) if MONGO_URI else None
db=mongo[DB_NAME] if mongo is not None else None
pwd=CryptContext(schemes=["bcrypt"],deprecated="auto"); bearer=HTTPBearer(auto_error=False)
sockets={}
def now(): return datetime.now(timezone.utc)
def need_db():
    if db is None: raise HTTPException(503,"Set MONGODB_URI in Render Environment.")
    try: mongo.admin.command("ping")
    except Exception: raise HTTPException(503,"MongoDB connection failed.")
    return db
if db is not None:
    try:
        db.users.create_index([("username_lower",ASCENDING)],unique=True)
        db.contacts.create_index([("owner_id",ASCENDING),("contact_id",ASCENDING)],unique=True)
        db.messages.create_index([("conversation_id",ASCENDING),("created_at",ASCENDING)])
    except Exception: pass

def make_token(uid):
    if not JWT_SECRET: raise HTTPException(503,"Set JWT_SECRET in Render Environment.")
    payload={"sub":uid,"exp":int(time.time())+2592000}
    raw=base64.urlsafe_b64encode(json.dumps(payload,separators=(",",":")).encode()).decode().rstrip("=")
    sig=hmac.new(JWT_SECRET.encode(),raw.encode(),hashlib.sha256).digest()
    return raw+"."+base64.urlsafe_b64encode(sig).decode().rstrip("=")
def token_uid(token):
    try:
        raw,sig=token.split(".",1); expected=hmac.new(JWT_SECRET.encode(),raw.encode(),hashlib.sha256).digest()
        supplied=base64.urlsafe_b64decode(sig+"="*(-len(sig)%4))
        if not hmac.compare_digest(expected,supplied): raise ValueError()
        data=json.loads(base64.urlsafe_b64decode(raw+"="*(-len(raw)%4)))
        if data["exp"]<int(time.time()): raise ValueError()
        return data["sub"]
    except Exception: raise HTTPException(401,"Invalid or expired session.")
def auth(c:HTTPAuthorizationCredentials=Depends(bearer)):
    need_db()
    if not c: raise HTTPException(401,"Please sign in.")
    u=db.users.find_one({"_id":token_uid(c.credentials)})
    if not u: raise HTTPException(401,"Account not found.")
    return u
def public(u):
    return {"id":u["_id"],"nickname":u.get("nickname",""),"username":u.get("username",""),"age":u.get("age"),"avatar":u.get("avatar","")}
class Register(BaseModel):
    nickname:str=Field(min_length=2,max_length=32)
    username:str=Field(min_length=3,max_length=24,pattern=r"^[A-Za-z0-9_.-]+$")
    age:int=Field(ge=13,le=120)
    password:str=Field(min_length=8,max_length=128)
class Login(BaseModel):
    username:str
    password:str
class Message(BaseModel):
    message:str=Field(min_length=1,max_length=6000)
class Weather(BaseModel):
    place:Optional[str]=None
    lat:Optional[float]=Field(default=None,ge=-90,le=90)
    lon:Optional[float]=Field(default=None,ge=-180,le=180)

@app.get("/health")
def health():
    status={"status":"ok","service":"Reshitogram","database":"not_configured"}
    if db is not None:
        try: mongo.admin.command("ping"); status["database"]="connected"
        except Exception: status["database"]="error"
    return status
@app.post("/api/auth/register")
def register(b:Register):
    need_db()
    if not JWT_SECRET: raise HTTPException(503,"Set JWT_SECRET in Render Environment.")
    username=b.username.strip()
    u={"_id":str(uuid.uuid4()),"nickname":b.nickname.strip(),"username":username,"username_lower":username.lower(),"age":b.age,"password_hash":pwd.hash(b.password),"created_at":now(),"blocked_users":[]}
    try: db.users.insert_one(u)
    except Exception: raise HTTPException(409,"Username is already taken.")
    return {"token":make_token(u["_id"]),"user":public(u)}
@app.post("/api/auth/login")
def login(b:Login):
    need_db(); u=db.users.find_one({"username_lower":b.username.strip().lower()})
    if not u or not pwd.verify(b.password,u["password_hash"]): raise HTTPException(401,"Incorrect username or password.")
    return {"token":make_token(u["_id"]),"user":public(u)}
@app.get("/api/auth/me")
def me(u=Depends(auth)): return {"user":public(u)}
@app.get("/api/users/search")
def search(q:str,u=Depends(auth)):
    q=q.strip()[:50]
    if len(q)<2:return {"users":[]}
    rx=re.escape(q)
    rows=db.users.find({"_id":{"$ne":u["_id"]},"$or":[{"username":{"$regex":rx,"$options":"i"}},{"nickname":{"$regex":rx,"$options":"i"}}]}).limit(20)
    blocked=set(u.get("blocked_users",[]))
    return {"users":[public(x) for x in rows if x["_id"] not in blocked]}
@app.get("/api/contacts")
def contacts(u=Depends(auth)):
    ids=[x["contact_id"] for x in db.contacts.find({"owner_id":u["_id"]})]
    return {"contacts":[public(x) for x in db.users.find({"_id":{"$in":ids}})]}
@app.post("/api/contacts/{target}")
def add_contact(target:str,u=Depends(auth)):
    t=db.users.find_one({"_id":target})
    if not t: raise HTTPException(404,"User not found.")
    if target==u["_id"]: raise HTTPException(400,"Cannot add yourself.")
    if target in u.get("blocked_users",[]) or u["_id"] in t.get("blocked_users",[]): raise HTTPException(403,"Contact blocked.")
    db.contacts.update_one({"owner_id":u["_id"],"contact_id":target},{"$setOnInsert":{"created_at":now()}},upsert=True)
    return {"ok":True}
@app.post("/api/users/{target}/block")
def block(target:str,u=Depends(auth)):
    db.users.update_one({"_id":u["_id"]},{"$addToSet":{"blocked_users":target}})
    db.contacts.delete_one({"owner_id":u["_id"],"contact_id":target})
    return {"ok":True}
@app.get("/api/messages/{other}")
def get_messages(other:str,u=Depends(auth)):
    t=db.users.find_one({"_id":other})
    if not t: raise HTTPException(404,"User not found.")
    if other in u.get("blocked_users",[]) or u["_id"] in t.get("blocked_users",[]): raise HTTPException(403,"Messaging unavailable.")
    cid=":".join(sorted([u["_id"],other]))
    rows=db.messages.find({"conversation_id":cid}).sort("created_at",1).limit(500)
    return {"messages":[{"id":m["_id"],"sender_id":m["sender_id"],"text":m["text"],"created_at":m["created_at"].isoformat()} for m in rows]}
@app.post("/api/ai/chat")
async def ai_chat(b:Message,u=Depends(auth)):
    if not GROQ_API_KEY: raise HTTPException(503,"Set GROQ_API_KEY in Render Environment.")
    history=list(db.ai_history.find({"user_id":u["_id"]}).sort("created_at",-1).limit(10)); history.reverse()
    msgs=[{"role":"system","content":"You are Reshitogram AI, friendly and helpful. Reply in the user's language."}]
    msgs += [{"role":x["role"],"content":x["content"]} for x in history]
    msgs.append({"role":"user","content":b.message})
    async with httpx.AsyncClient(timeout=60) as c:
        r=await c.post("https://api.groq.com/openai/v1/chat/completions",headers={"Authorization":"Bearer "+GROQ_API_KEY},json={"model":"openai/gpt-oss-120b","messages":msgs,"temperature":0.7,"max_tokens":1200})
    if r.status_code>=400: raise HTTPException(502,"Groq API error: "+r.text[:300])
    answer=r.json()["choices"][0]["message"]["content"]
    db.ai_history.insert_many([{"user_id":u["_id"],"role":"user","content":b.message,"created_at":now()},{"user_id":u["_id"],"role":"assistant","content":answer,"created_at":now()}])
    return {"reply":answer}
@app.post("/api/ai/image")
async def ai_image(b:Message,u=Depends(auth)):
    if not CF_ACCOUNT or not CF_TOKEN: raise HTTPException(503,"Set CLOUDFLARE_ACCOUNT_ID and CLOUDFLARE_API_TOKEN.")
    url=f"https://api.cloudflare.com/client/v4/accounts/{CF_ACCOUNT}/ai/run/@cf/black-forest-labs/flux-1-schnell"
    async with httpx.AsyncClient(timeout=120) as c:r=await c.post(url,headers={"Authorization":"Bearer "+CF_TOKEN},json={"prompt":b.message})
    if r.status_code>=400: raise HTTPException(502,"Cloudflare AI error: "+r.text[:300])
    typ=r.headers.get("content-type","")
    if typ.startswith("image/"): return {"image_data_url":"data:"+typ+";base64,"+base64.b64encode(r.content).decode()}
    result=r.json().get("result",{})
    if isinstance(result,dict) and result.get("image"):return {"image_data_url":"data:image/png;base64,"+result["image"]}
    raise HTTPException(502,"Unexpected Cloudflare response.")
@app.post("/api/weather")
async def weather(b:Weather,u=Depends(auth)):
    if not WEATHER_KEY: raise HTTPException(503,"Set OPENWEATHER_API_KEY in Render Environment.")
    if b.lat is not None and b.lon is not None:p={"lat":b.lat,"lon":b.lon,"appid":WEATHER_KEY,"units":"metric"}
    elif b.place and b.place.strip():p={"q":b.place.strip(),"appid":WEATHER_KEY,"units":"metric"}
    else:raise HTTPException(400,"Enter a city or both coordinates.")
    async with httpx.AsyncClient(timeout=20) as c:r=await c.get("https://api.openweathermap.org/data/2.5/weather",params=p)
    if r.status_code>=400:raise HTTPException(400,"Weather unavailable. Check place and API key.")
    d=r.json()
    return {"place":d.get("name","Coordinates"),"country":d.get("sys",{}).get("country",""),"temperature_c":d["main"]["temp"],"feels_like_c":d["main"]["feels_like"],"humidity":d["main"]["humidity"],"description":d["weather"][0]["description"],"wind_m_s":d.get("wind",{}).get("speed",0)}
@app.websocket("/ws")
async def ws_endpoint(ws:WebSocket,token:str=""):
    await ws.accept(); uid=None
    try:
        uid=token_uid(token); need_db()
        if not db.users.find_one({"_id":uid}): await ws.close(code=4401); return
        sockets.setdefault(uid,set()).add(ws)
        await ws.send_json({"type":"connected"})
        while True:
            d=await ws.receive_json()
            if d.get("type")!="message":continue
            target=str(d.get("to","")); txt=str(d.get("text","")).strip()
            if not txt or len(txt)>6000:continue
            sender=db.users.find_one({"_id":uid}); receiver=db.users.find_one({"_id":target})
            if not receiver or target in sender.get("blocked_users",[]) or uid in receiver.get("blocked_users",[]):
                await ws.send_json({"type":"error","message":"Message could not be sent."});continue
            cid=":".join(sorted([uid,target]))
            m={"_id":str(uuid.uuid4()),"conversation_id":cid,"participants":[uid,target],"sender_id":uid,"recipient_id":target,"text":txt,"created_at":now()}
            db.messages.insert_one(m); out={"type":"message","id":m["_id"],"sender_id":uid,"recipient_id":target,"text":txt,"created_at":m["created_at"].isoformat()}
            for s in list(sockets.get(target,set())):
                try:await s.send_json(out)
                except Exception:pass
            await ws.send_json(out)
    except (WebSocketDisconnect,Exception):pass
    finally:
        if uid in sockets:
            sockets[uid].discard(ws)
            if not sockets[uid]:sockets.pop(uid,None)
@app.get("/",response_class=HTMLResponse)
def home():
    with open("static/index.html",encoding="utf-8") as f:return f.read()
app.mount("/static",StaticFiles(directory="static"),name="static")
