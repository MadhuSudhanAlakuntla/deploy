const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const dotenv = require("dotenv");

dotenv.config();
const app = express();
app.use(express.json());
mongoose.connect(process.env.MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true });

const User = mongoose.model("User", {
  name: String,
  email: String,
  password: String,
  phone_number: String,
  department: String,
});

const Notice = mongoose.model("Notice", {
  title: String,
  body: String,
  category: String,
  date: { type: Date, default: Date.now() },
  user: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
});

// Authentication middleware
const authentication = (req, res, next) => {
  const token = req.header("Authorization");
  if (!token) return res.status(401).json({ msg: "Access Denied" });
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    res.status(400).json({ msg: "Invalid token" });
  }
};

// Routes
app.post("/register", async (req, res) => {
  try {
    const hashedPassword = await bcrypt.hash(req.body.password, 10);
    const user = new User({
      name: req.body.name,
      email: req.body.email,
      password: hashedPassword,
      phone_number: req.body.phone_number,
      department: req.body.department,
    });
    await user.save();
    res.status(201).json({ msg: "Registered Successfully" });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post("/login", async (req, res) => {
  try {
    const user = await User.findOne({ email: req.body.email });
    if (!user) return res.status(404).json({ msg: "User not found" });

    const validPassword = await bcrypt.compare(req.body.password, user.password);
    if (!validPassword) res.status(401).json({ msg: "Invalid password" });

    const token = jwt.sign({ _id: user._id }, process.env.JWT_SECRET);
    res.header("Authorization", token).json({ token });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post("/notices", authentication, async (req, res) => {
  try {
    const newNotice = new Notice({
      title: req.body.title,
      body: req.body.body,
      category: req.body.category,
      user: req.user._id,
    });
    await newNotice.save();
    res.status(201).json({ msg: "Notice Created Successfully" });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get("/notices", authentication, async (req, res) => {
  try {
    const filter = req.query.category ? { category: req.query.category } : {};
    const notices = await Notice.find(filter).populate("user", "name email");
    res.status(200).json(notices);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.put("/notices/:id", authentication, async (req, res) => {
  try {
    const notice = await Notice.findOne({ _id: req.params.id, user: req.user._id });
    if (!notice) return res.status(404).json({ msg: "Notice not found" });

    notice.title = req.body.title;
    notice.body = req.body.body;
    notice.category = req.body.category;
    await notice.save();
    res.status(200).json({ msg: "Notice Updated" });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete("/notices/:id", authentication, async (req, res) => {
  try {
    const notice = await Notice.findOne({ _id: req.params.id, user: req.user._id });
    if (!notice) return res.status(404).json({ msg: "Notice not found" });

    await notice.remove();
    res.status(200).json({ msg: "Notice Deleted" });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`Server Running on http://localhost:${PORT}`);
});
