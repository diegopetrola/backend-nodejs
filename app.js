const express = require("express");
const jwt = require("jsonwebtoken");
const session = require("express-session");
const path = require("path");
const mongoose = require("mongoose");

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET_KEY = process.env.SECRET_KEY;

mongoose.set("strictQuery", false);
const uri = process.env.MONGO_URL;
mongoose.connect(uri);

const User = mongoose.model("User", {
  username: String,
  email: String,
  password: String,
});
const Post = mongoose.model("Post", {
  userId: mongoose.Schema.Types.ObjectId,
  text: String,
});

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(
  session({
    secret: SECRET_KEY,
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false },
  })
);

// AuthenticateJWT Function
function authenticateJWT(req, res, next) {
  const token = req.session.token;
  if (!token) return res.status(401).json({ message: "Unauthorized" });

  try {
    // Verify token
    const decoded = jwt.verify(token, SECRET_KEY);

    // Attach user data to request
    req.user = decoded;

    // Continue to the next middleware
    next();
  } catch (error) {
    // If invalid token, return 401
    return res.status(401).json({ message: "Invalid token" });
  }
}

// RequireAuth Function code here.
function requireAuth(req, res, next) {
  const token = req.session.token; // Retrieve token from session

  if (!token) return res.redirect("/login"); // If no token, redirect to login page

  try {
    const decoded = jwt.verify(token, SECRET_KEY); // Verify the token using the secret key
    req.user = decoded; // Attach decoded user data to the request
    next(); // Pass control to the next middleware/route
  } catch (error) {
    return res.redirect("/login"); // If token is invalid, redirect to login page
  }
}

// Routing HTML code
app.get("/", (req, res) =>
  res.sendFile(path.join(__dirname, "public", "index.html"))
);

app.get("/register", (req, res) =>
  res.sendFile(path.join(__dirname, "public", "register.html"))
);

app.get("/login", (req, res) =>
  res.sendFile(path.join(__dirname, "public", "login.html"))
);

app.post("/post", authenticateJWT, async (req, res) => {
  const { text } = req.body;

  // Validate post content
  if (!text || typeof text !== "string") {
    return res
      .status(400)
      .json({ message: "Please provide valid post content" });
  }

  try {
    const newPost = new Post({ userId: req.user.userId, text });
    await newPost.save();
    res
      .status(201)
      .json({ message: "Post created successfully", post: newPost });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Internal Server Error" });
  }
});

app.get("/posts", authenticateJWT, async (req, res) => {
  try {
    // Fetch posts for the logged-in user
    const posts = await Post.find({ userId: req.user.userId });
    res.json({ posts });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Internal Server Error" });
  }
});

app.put("/posts/:postId", authenticateJWT, async (req, res) => {
  const postId = req.params.postId;
  const { text } = req.body;

  try {
    // Find and update the post, ensuring it's owned by the authenticated user
    const post = await Post.findOneAndUpdate(
      { _id: postId, userId: req.user.userId },
      { text },
      { new: true } // Return updated post
    );

    // Return error if post not found
    if (!post) return res.status(404).json({ message: "Post not found" });

    res.json({ message: "Post updated successfully", updatedPost: post });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Internal Server Error" });
  }
});

app.delete("/posts/:postId", authenticateJWT, async (req, res) => {
  const postId = req.params.postId;

  try {
    // Find and delete the post, ensuring it's owned by the authenticated user
    const post = await Post.findOneAndDelete({
      _id: postId,
      userId: req.user.userId,
    });

    // Return error if post not found
    if (!post) return res.status(404).json({ message: "Post not found" });

    res.json({ message: "Post deleted successfully", deletedPost: post });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Internal Server Error" });
  }
});

app.get("/index", requireAuth, (req, res) =>
  res.sendFile(path.join(__dirname, "public", "index.html"), {
    username: req.user.username,
  })
);

// User registration
app.post("/register", async (req, res) => {
  const { username, email, password } = req.body;

  try {
    const existingUser = await User.findOne({ $or: [{ username }, { email }] });
    if (existingUser)
      return res.status(400).json({ message: "User already exists" });

    // Create and save the new user
    const newUser = new User({ username, email, password });
    await newUser.save();

    // Generate JWT token and store in session
    const token = jwt.sign(
      { userId: newUser._id, username: newUser.username },
      SECRET_KEY,
      { expiresIn: "1h" }
    );
    req.session.token = token;

    // Respond with success message
    res.redirect(`/index?username=${newUser.username}`);
  } catch (error) {
    console.error(error);
    // Handle server errors
    res.status(500).json({ message: "Internal Server Error" });
  }
});

// User login
app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  try {
    const user = await User.findOne({ username, password });
    if (!user) return res.status(401).json({ message: "Invalid credentials" });

    // Generate JWT token and store in session
    const token = jwt.sign(
      { userId: user._id, username: user.username },
      SECRET_KEY,
      { expiresIn: "1h" }
    );
    req.session.token = token;

    // Respond with a success message
    res.redirect(`/index?username=${user.username}`);
  } catch (error) {
    console.error(error);
    // Handle server errors
    res.status(500).json({ message: "Internal Server Error" });
  }
});

app.get("/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) console.error(err); // Log any session destruction errors
    res.redirect("/login"); // Redirect to login page after logout
  });
});

app.listen(PORT, () => console.log(`Server is running on port ${PORT}`));
