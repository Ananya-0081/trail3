const dns = require("dns");
dns.setServers(["8.8.8.8", "1.1.1.1"]);

const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");

const app = express();
app.use(express.json());
app.use(cors());

// ✅ DB CONNECTION
mongoose.connect(process.env.MONGO_URI)
  .then(()=>console.log("DB Connected"))
  .catch(err=>console.log(err));

// ✅ USER MODEL
const User = mongoose.model("User", {
  name: { type: String, required: true },
  email: { type: String, unique: true, required: true },
  password: { type: String, required: true }
});

// ✅ EXPENSE MODEL
const Expense = mongoose.model("Expense", {
  userId: String,
  title: String,
  amount: Number,
  category: String,
  date: { type: Date, default: Date.now }
});

// ✅ AUTH MIDDLEWARE
const auth = (req,res,next)=>{
  const token = req.headers.authorization;

  if(!token) {
    return res.status(401).json({ error: "No token provided" });
  }

  try {
    const decoded = jwt.verify(token, "secret");
    req.user = decoded;
    next();
  } catch {
    return res.status(401).json({ error: "Invalid token" });
  }
};

// ✅ REGISTER
app.post("/register", async (req,res)=>{
  try {
    const {name,email,password} = req.body;

    if(!name || !email || !password){
      return res.status(400).json({ error: "All fields required" });
    }

    const exists = await User.findOne({email});
    if(exists){
      return res.status(400).json({ error: "User already exists" });
    }

    const hash = await bcrypt.hash(password,10);

    await User.create({name,email,password:hash});

    res.json({ message: "Registered successfully" });

  } catch(err){
    res.status(500).json({ error: "Server error" });
  }
});

// ✅ LOGIN
app.post("/login", async (req,res)=>{
  try {
    const {email,password} = req.body;

    const user = await User.findOne({email});
    if(!user){
      return res.status(400).json({ error: "User not found" });
    }

    const ok = await bcrypt.compare(password,user.password);
    if(!ok){
      return res.status(400).json({ error: "Wrong password" });
    }

    const token = jwt.sign({id:user._id},"secret",{ expiresIn: "1d" });

    res.json({ token });

  } catch(err){
    res.status(500).json({ error: "Server error" });
  }
});

// ✅ ADD EXPENSE
app.post("/expense", auth, async (req,res)=>{
  try {
    const {title,amount,category} = req.body;

    if(!title || !amount){
      return res.status(400).json({ error: "Title & Amount required" });
    }

    const exp = await Expense.create({
      title,
      amount,
      category,
      userId: req.user.id
    });

    res.json(exp);

  } catch(err){
    res.status(500).json({ error: "Server error" });
  }
});

// ✅ GET EXPENSES
app.get("/expenses", auth, async (req,res)=>{
  try {
    const data = await Expense.find({userId:req.user.id});
    res.json(data); // ALWAYS ARRAY
  } catch(err){
    res.status(500).json({ error: "Server error" });
  }
});

// ✅ SERVER
app.listen(5000, ()=>console.log("Server running on port 5000"));