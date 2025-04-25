const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { createUser, findUserByEmail } = require("../models/userModel");
require("dotenv").config();

const router = express.Router();

// Kayıt (register) endpoint'i
router.post("/register", async (req, res) => {
  const { name, email, password } = req.body;

  try {
    // E-posta kontrolü
    const existingUser = await findUserByEmail(email);
    if (existingUser) {
      return res.status(400).json({ message: "E-posta zaten kayıtlı!" });
    }

    // Şifreyi hash'le
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Yeni kullanıcıyı veritabanına ekle
    const newUser = await createUser(name, email, hashedPassword);

    // Kullanıcıyı kaydettikten sonra JWT oluştur
    const token = jwt.sign({ userId: newUser.id }, process.env.JWT_SECRET, {
      expiresIn: "1h",
    });

    res.status(201).json({ message: "Kayıt başarılı!", token });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Bir hata oluştu!", error: error.message });
  }
});

// Giriş (login) endpoint'i
router.post("/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    // Kullanıcıyı e-posta ile bul
    const user = await findUserByEmail(email);
    if (!user) {
      return res.status(400).json({ message: "Geçersiz e-posta veya şifre" });
    }

    // Şifreyi doğrula
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: "Geçersiz e-posta veya şifre" });
    }

    // JWT oluştur
    const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, {
      expiresIn: "1h",
    });

    res.status(200).json({ message: "Giriş başarılı!", token });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Bir hata oluştu!", error: error.message });
  }
});

module.exports = router;

