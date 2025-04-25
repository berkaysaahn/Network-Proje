require("dotenv").config();
const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const morgan = require("morgan");

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware'ler
app.use(express.json()); // JSON isteklerini anlamak için
app.use(cors()); // CORS yapılandırması
app.use(helmet()); // Güvenlik için HTTP başlıkları
app.use(morgan("dev")); // HTTP logları

app.get("/", (req, res) => {
  res.send("Kimlik doğrulama API'si çalışıyor!");
});

app.listen(PORT, () => {
  console.log(`🚀 Sunucu ${PORT} portunda çalışıyor...`);
});

