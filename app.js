const express = require("express");
const cors = require("cors");
const authRoutes = require("./routes/authRoutes");  // auth routes import edilmesi

const app = express();

// Middleware
app.use(cors());
app.use(express.json()); // JSON body parser

// API Routes
app.use("/api/auth", authRoutes);  // auth routes eklenmesi

app.listen(process.env.PORT, () => {
  console.log(`🚀 Server running on port ${process.env.PORT}`);
});

