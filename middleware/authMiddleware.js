const jwt = require("jsonwebtoken");
require("dotenv").config();

// JWT doğrulama middleware'i
const protect = (req, res, next) => {
  // Token'ı header'dan al
  const token = req.header("Authorization")?.replace("Bearer ", "");

  if (!token) {
    return res.status(401).json({ message: "Token gereklidir" });
  }

  try {
    // Token'ı doğrula
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded; // Kullanıcı bilgilerini request'e ekle
    next(); // Bir sonraki middleware'e geç
  } catch (error) {
    res.status(400).json({ message: "Geçersiz token" });
  }
};

module.exports = protect;

