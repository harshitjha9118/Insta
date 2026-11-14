const express=require("express");
const session=require("express-session");
const PgSession=require("connect-pg-simple")(session);
const {Pool}=require("pg");
const bcrypt=require("bcryptjs");
const helmet=require("helmet");
const rateLimit=require("express-rate-limit");
const path=require("path");
const app=express();
const pool=new Pool({connectionString:process.env.DATABASE_URL,ssl:process.env.DATABASE_URL?.includes("localhost")?false:{rejectUnauthorized:false}});
const required=["DATABASE_URL","SESSION_SECRET","ADMIN_USERNAME","ADMIN_PASSWORD"];
if(required.some(k=>!process.env[k]) || (process.env.SESSION_SECRET||"").length<32 || (process.env.ADMIN_PASSWORD||"").length<12){
 console.error("Setup incomplete: configure DATABASE_URL, SESSION_SECRET (32+ chars), ADMIN_USERNAME and ADMIN_PASSWORD (12+ chars).");process.exit(1);
}
app.set("trust proxy",1);
app.use(helmet({contentSecurityPolicy:false}));
app.use(express.json({limit:"300kb"}));
app.use(express.urlencoded({extended:false}));
app.use(session({store:new PgSession({pool,tableName:"user_sessions",createTableIfMissing:true}),secret:process.env.SESSION_SECRET,resave:false,saveUninitialized:false,cookie:{httpOnly:true,sameSite:"lax",secure:process.env.NODE_ENV==="production",maxAge:7*24*60*60*1000}}));
app.use(express.static(path.join(__dirname,"public")));
const authLimit=rateLimit({windowMs:15*60*1000,max:30,standardHeaders:true,legacyHeaders:false});
async function init(){
 await pool.query(`
 CREATE TABLE IF NOT EXISTS users(id BIGSERIAL PRIMARY KEY, username VARCHAR(30) UNIQUE NOT NULL, display_name VARCHAR(60) NOT NULL, password_hash TEXT NOT NULL, bio VARCHAR(160) DEFAULT '', created_at TIMESTAMPTZ DEFAULT NOW());
 CREATE TABLE IF NOT EXISTS posts(id BIGSERIAL PRIMARY KEY,user_id BIGINT REFERENCES users(id) ON DELETE CASCADE, caption VARCHAR(500) DEFAULT '', image_url TEXT DEFAULT '', created_at TIMESTAMPTZ DEFAULT NOW());
 CREATE TABLE IF NOT EXISTS likes(user_id BIGINT REFERENCES users(id) ON DELETE CASCADE,post_id BIGINT REFERENCES posts(id) ON DELETE CASCADE,created_at TIMESTAMPTZ DEFAULT NOW(),PRIMARY KEY(user_id,post_id));
 CREATE TABLE IF NOT EXISTS comments(id BIGSERIAL PRIMARY KEY,user_id BIGINT REFERENCES users(id) ON DELETE CASCADE,post_id BIGINT REFERENCES posts(id) ON DELETE CASCADE,body VARCHAR(300) NOT NULL,created_at TIMESTAMPTZ DEFAULT NOW());
 CREATE TABLE IF NOT EXISTS login_events(id BIGSERIAL PRIMARY KEY, username VARCHAR(30), success BOOLEAN NOT NULL, ip_hint VARCHAR(80), created_at TIMESTAMPTZ DEFAULT NOW());
 `);
}
function needAuth(req,res,next){if(!req.session.userId)return res.status(401).json({error:"Please log in"});next();}
app.post("/api/signup",authLimit,async(req,res)=>{
 try{
  let {username,displayName,password}=req.body;
  username=String(username||"").trim().toLowerCase();displayName=String(displayName||username).trim();password=String(password||"");
  if(!/^[a-z0-9_.]{3,30}$/.test(username))return res.status(400).json({error:"Username: 3–30 letters, numbers, dot or underscore."});
  if(displayName.length<1||displayName.length>60||password.length<10)return res.status(400).json({error:"Display name required; password must be at least 10 characters."});
  const hash=await bcrypt.hash(password,12);
  const r=await pool.query("INSERT INTO users(username,display_name,password_hash) VALUES($1,$2,$3) RETURNING id,username,display_name,bio,created_at",[username,displayName,hash]);
  req.session.userId=r.rows[0].id;res.json({user:r.rows[0]});
 }catch(e){res.status(e.code==="23505"?409:500).json({error:e.code==="23505"?"Username already taken":"Could not create account"});}
});
app.post("/api/login",authLimit,async(req,res)=>{
 try{
  const username=String(req.body.username||"").trim().toLowerCase(),password=String(req.body.password||"");
  const r=await pool.query("SELECT * FROM users WHERE username=$1",[username]);
  const valid=!!r.rowCount && await bcrypt.compare(password,r.rows[0].password_hash);
  await pool.query("INSERT INTO login_events(username,success,ip_hint) VALUES($1,$2,$3)",[username,valid, String(req.ip||"").slice(0,80)]);
  if(!valid)return res.status(401).json({error:"Incorrect demo username or password"});
  req.session.userId=r.rows[0].id;res.json({user:{id:r.rows[0].id,username:r.rows[0].username,display_name:r.rows[0].display_name,bio:r.rows[0].bio}});
 }catch(e){res.status(500).json({error:"Login failed"});}
});
app.post("/api/logout",(req,res)=>req.session.destroy(()=>res.json({ok:true})));
app.get("/api/me",needAuth,async(req,res)=>{const r=await pool.query("SELECT id,username,display_name,bio FROM users WHERE id=$1",[req.session.userId]);res.json({user:r.rows[0]});});
app.get("/api/feed",needAuth,async(req,res)=>{
 const r=await pool.query(`SELECT p.id,p.caption,p.image_url,p.created_at,u.username,u.display_name,
 (SELECT COUNT(*) FROM likes l WHERE l.post_id=p.id)::int AS likes,
 EXISTS(SELECT 1 FROM likes l WHERE l.post_id=p.id AND l.user_id=$1) AS liked
 FROM posts p JOIN users u ON u.id=p.user_id ORDER BY p.created_at DESC LIMIT 50`,[req.session.userId]);res.json({posts:r.rows});
});
app.post("/api/posts",needAuth,async(req,res)=>{
 const caption=String(req.body.caption||"").trim(),imageUrl=String(req.body.imageUrl||"").trim();
 if(caption.length>500||imageUrl.length>1500)return res.status(400).json({error:"Caption or image URL too long"});
 if(imageUrl&&!/^https:\/\/.+/i.test(imageUrl))return res.status(400).json({error:"Use an HTTPS image URL"});
 const r=await pool.query("INSERT INTO posts(user_id,caption,image_url) VALUES($1,$2,$3) RETURNING id,caption,image_url,created_at",[req.session.userId,caption,imageUrl]);res.json({post:r.rows[0]});
});
app.post("/api/posts/:id/like",needAuth,async(req,res)=>{
 const id=Number(req.params.id);if(!Number.isInteger(id))return res.status(400).json({error:"Invalid post"});
 const exists=await pool.query("SELECT 1 FROM likes WHERE user_id=$1 AND post_id=$2",[req.session.userId,id]);
 if(exists.rowCount)await pool.query("DELETE FROM likes WHERE user_id=$1 AND post_id=$2",[req.session.userId,id]);else await pool.query("INSERT INTO likes(user_id,post_id) VALUES($1,$2) ON CONFLICT DO NOTHING",[req.session.userId,id]);
 const c=await pool.query("SELECT COUNT(*)::int AS count FROM likes WHERE post_id=$1",[id]);res.json({liked:!exists.rowCount,likes:c.rows[0].count});
});
app.post("/api/posts/:id/comments",needAuth,async(req,res)=>{
 const body=String(req.body.body||"").trim();if(!body||body.length>300)return res.status(400).json({error:"Comment must be 1–300 characters"});
 const r=await pool.query("INSERT INTO comments(user_id,post_id,body) VALUES($1,$2,$3) RETURNING id,body,created_at",( [req.session.userId,Number(req.params.id),body] ));res.json({comment:r.rows[0]});
});
app.post("/api/admin/login",authLimit,async(req,res)=>{
 const username=String(req.body.username||"");
 const password=String(req.body.password||"");
 if(username!==process.env.ADMIN_USERNAME || password!==process.env.ADMIN_PASSWORD) return res.status(401).json({error:"Admin login failed"});
 req.session.isAdmin=true;res.json({ok:true});
});
function needAdmin(req,res,next){if(!req.session.isAdmin)return res.status(401).json({error:"Admin login required"});next();}
app.post("/api/admin/logout",needAdmin,(req,res)=>{req.session.isAdmin=false;res.json({ok:true});});
app.get("/api/admin/users",needAdmin,async(req,res)=>{
 const r=await pool.query("SELECT id,username,display_name,bio,created_at FROM users ORDER BY created_at DESC LIMIT 500");
 res.json({users:r.rows});
});
app.get("/api/admin/logins",needAdmin,async(req,res)=>{
 const r=await pool.query("SELECT id,username,success,ip_hint,created_at FROM login_events ORDER BY created_at DESC LIMIT 200");
 res.json({events:r.rows});
});
app.post("/api/admin/users/:id/reset-password",needAdmin,async(req,res)=>{
 const id=Number(req.params.id);if(!Number.isInteger(id))return res.status(400).json({error:"Invalid user"});
 const tempPassword=require("crypto").randomBytes(9).toString("base64url");
 const hash=await bcrypt.hash(tempPassword,12);
 const r=await pool.query("UPDATE users SET password_hash=$1 WHERE id=$2 RETURNING username",[hash,id]);
 if(!r.rowCount)return res.status(404).json({error:"User not found"});
 res.json({username:r.rows[0].username,temporaryPassword:tempPassword,message:"Shown once only. Copy it now and share securely with your demo user."});
});
app.get("/health",(_,res)=>res.send("ok"));
init().then(()=>{const port=process.env.PORT||3000;app.listen(port,()=>console.log("PhotoLoop running on "+port));}).catch(e=>{console.error(e);process.exit(1);});