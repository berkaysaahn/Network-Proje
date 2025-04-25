### İlk Aşama
- İlk aşamada backend kısmını yapılandırıyoruz.
	- Backend: Node.js (Express)
	- Veritabanı: PostgreSQL
	- Kimlik Doğrulama: JWT (JSON Web Token)
	- Şifreleme: bcrypt    
	- Güvenli İletişim: HTTPS (SSL/TLS)
- İzlenecek Yol Şöyle:
	- Node.js ve Express kurulumunu yapacağız.
	- PostgreSQL/MySQL bağlantısını yapılandıracağız.
	- Kullanıcı modeli oluşturup UUID ile benzersiz kimlik atayacağız.
	- Şifreleme için bcrypt ve kimlik doğrulama için JWT kullanacağız.
	- Kimlik doğrulama için kayıt, giriş ve token doğrulama endpoint’leri oluşturacağız.
	- SSL/TLS ile güvenli veri iletimini sağlayacağız.
- Yapılacaklar 
	- Google Authenticator ile iki faktörlü doğrulama yap. speakeasy, qrcode kütühanelerini kullan.
#### Hadi Başlayalım :)))
##### İlk Adımda Gerekli Paketlerin Kurulumunu ve Proje Başlatma
```bash
# Yeni bir proje oluştur
mkdir auth-system && cd auth-system
npm init -y

# Gerekli bağımlılıkları yükle
npm install express pg bcryptjs jsonwebtoken dotenv uuid cors helmet morgan

# Geliştirme için ek bağımlılıklar
npm install --save-dev nodemon
```
- Kullanılan Paketler ve Açıklamaları Şöyle:
	1. <u><i>express:</i></u> HTTP Sunucuları oluşturmak için kullanılır. URL yönlendirme, HTTP istek ve yanıtları yönetme, middleware kullanımı gibi özelliklere sahiptir.
	2. <u><i>pg (PostgreSQL):</i></u> Postgre ile etkileşim için gerekli olan Node.js istemci paketidir. SQL sorguları göndermenize, veritabanı bağlantıları oluşturmanıza ve sonuçları almanıza olanak tanır.
	3. <u><i>bcrypt (Blowfish Crypt):</i></u> Şifreleri güvenli bir şekilde hash'lemek ve doğrulamak için kullanılan bir JavaScript kütüphanesidir. Kullanıcı şifrelerini veritabanında saklamak için hash fonksiyonu uygular. Aynı zamanda şifre doğrulaması yapmak için de kullanılır. `bcrypt`'in saf JavaScript sürümüdür, bu nedenle Node.js ile uyumludur.
	4. <u><i>jsonwebtoken (JWT):</i></u> JWT, bir kullanıcının kimliğini doğrulamak için sunucu ile istemci arasında güvenli bir şekilde veri iletmek için yaygın olarak kullanılır. Genellikle kullanıcı giriş yaptıktan sonra token oluşturulur ve her istekle birlikte bu token sunucuya gönderilir.
	5. <u><i>dotenv:</i></u> `dotenv`, uygulamanızın ortam değişkenlerini `.env` dosyasından yüklemenize yarayan bir kütüphanedir. Ortam değişkenleri, hassas bilgilerin (API anahtarları, veritabanı bağlantı bilgileri vb.) doğrudan kodda yer almasını engeller ve uygulamanın yapılandırılmasını kolaylaştırır.
	6. <u><i>uuid (Universally Unique Identifier):</i></u> UUID'ler, her bir kaydın benzersiz bir şekilde tanımlanması için yaygın olarak kullanılır. Veritabanlarında anahtarlar veya diğer benzersiz tanımlayıcılar oluşturmak için kullanılır.
	7. <u><i>cors (Cross-Origin Resource Sharing):</i></u> Farklı domainlerden gelen web isteklerini kontrol etmenizi sağlayan bir Node.js [[middleware]]'dir. Web uygulamaları, bir kaynağın başka bir kaynaktan gelen istekleri kabul edip etmemesini belirleyen güvenlik politikalarını uygular. Bu paket, CORS başlıklarını ayarlayarak uygulamanızın kaynak paylaşımını yönetir.
	8. <u><i>helmet:</i></u> Express uygulamanıza güvenlik eklemek için kullanılan bir middleware'dir. HTTP başlıklarını ayarlayarak, uygulamanızı çeşitli yaygın web güvenlik açıklarına karşı korur. Örneğin, XSS (Cross-Site Scripting) ve clickjacking gibi saldırılara karşı koruma sağlar.
	9. <u><i>morgan:</i></u> HTTP isteklerinin günlüklerini tutmak için kullanılan bir middleware'dir. Web uygulamanızda yapılan her isteği konsola yazdırarak, hata ayıklama ve izleme yapmanıza olanak tanır. Özellikle geliştirme sırasında veya canlı ortamda, hangi isteklerin yapıldığını görmek için kullanışlıdır.
##### İkinci Adım Express Sunucusunu Kurma
- Şimdi projeyi oluşturduğumuz yere gidelim ve `server.js` dosyasını oluşturalım.
```js
require("dotenv").config(); // dotenv kütüphanesi ile .env dosyasındaki ortam değişkenlerini yükler.
const express = require("express"); // express ile web sunucusu oluşturur.
const cors = require("cors"); // CORS (Cross-Origin Resource Sharing) için middleware ekler.
const helmet = require("helmet"); //helmet ile güvenlik başlıkları ekler.
const morgan = require("morgan"); //morgan ile http isteklerini loglar.

const app = express(); //Express uygulamasını başlatır ve `app` değişkenine atar. Bu, web sunucusunun temel yapı taşıdır.
const PORT = process.env.PORT || 5000; //Eğer `.env` dosyasındaki veya ortam değişkenlerinden (`process.env`) bir `PORT` değeri belirlenmişse, bu değeri alır. Bu, genellikle uygulamanın çalışacağı port numarasını dışarıdan yapılandırmak için kullanılır (örneğin, bir bulut servis sağlayıcısı bu şekilde portu ayarlayabilir). Tanımlanmadıysa 5000 kullanır.

// Middleware'ler
app.use(express.json()); // JSON isteklerini anlamak için
app.use(cors()); // CORS yapılandırması
app.use(helmet()); // Güvenlik için HTTP başlıkları
app.use(morgan("dev")); // HTTP logları

app.get("/", (req, res) => {
  res.send("Kimlik doğrulama API'si çalışıyor!");
}); //Ana dizine gelen GET isteği, "Kimlik doğrulama API'si çalışıyor!" mesajını döner. Bu, sunucunun doğru şekilde çalıştığını kontrol etmek için basit bir yanıt olarak kullanılır.

app.listen(PORT, () => {
  console.log(`🚀 Sunucu ${PORT} portunda çalışıyor...`); 
}); //Sunucu belirtilen portta (varsayılan olarak `5000`) çalıştırılmaya başlanır.
```
- Sunucuyu Çalıştırmak İçin: `node server.js`
- Eğer Otomatik Olarak Yeniden Başlatma İstenirse: `npx nodemon server.js`
##### Üçüncü Adım PostgreSQL Kurulumu ve Yapılandırılması
- İlk önce sisteme postgre kuruyoruz.
- Daha sonra postgre için yeni veri klasörü oluşturuyoruz.
```bash
sudo rm -rf /var/lib/postgres/data
sudo mkdir -p /var/lib/postgres/data
sudo chown -R postgres:postgres /var/lib/postgres
```
- Yeni Veri Tabanı Başlatma:
```bash
sudo -u postgres initdb --locale=C.UTF-8 --encoding=UTF8 -D /var/lib/postgres/data
#sudo -u postgres Bu komut, postgres kullanıcısı olarak çalıştırılması gerektiği için, postgres kullanıcısının izinleriyle işlem yapılmasını sağlar. PostgreSQL, genellikle postgres adıyla ayrı bir sistem kullanıcısı ile çalışır.

#initdb: Bu, PostgreSQL veritabanı sunucusunun ilk kurulumunu yapmak için kullanılan bir komuttur. Veritabanı klasör yapısını oluşturur ve ilk veritabanını başlatmak için gerekli dosyaları oluşturur.

#--locale=C.UTF-8: Bu, PostgreSQL veritabanı sunucusunun dil ve karakter seti ayarlarını belirtir. C.UTF-8 karakter kümesi, dil ve bölgesel ayarların doğru şekilde işlenmesini sağlar.

#--encoding=UTF8: Bu, veritabanının karakter kodlamasını UTF-8 olarak ayarlar. UTF-8, geniş bir karakter yelpazesini desteklediği için çoğu uygulama ve veritabanı için yaygın olarak tercih edilen bir kodlamadır.

#-D /var/lib/postgres/data: Bu, veritabanı verilerinin depolanacağı dizini belirtir. PostgreSQL veritabanı, bu dizinde veri dosyalarını tutar. Bu örnekte, /var/lib/postgres/data dizini seçilmiştir.
```
- Servisi yeniden başlatma:
```bash
sudo systemctl restart postgresql
```
- Postgre terminal'e giriş:
```bash
sudo -u postgres psql
#sudo -u postgres: Bu, postgres kullanıcısı olarak komutu çalıştırmanızı sağlar. PostgreSQL, genellikle postgres adlı ayrı bir sistem kullanıcısı ile çalışır. Bu komut, postgres kullanıcısının izinleriyle işlem yapmanızı sağlar.

#psql: Bu, PostgreSQL'in komut satırı arayüzüdür. psql komutu, PostgreSQL veritabanına bağlanmanızı ve SQL sorguları çalıştırmanızı sağlar. Bu komut, veritabanı üzerinde işlem yapabileceğiniz bir terminal oturumu başlatır.
```
- Alttaki kod'u psql'e ekliyoruz:
```postgresql
-- Yeni bir veritabanı oluştur
CREATE DATABASE authdb;

-- Yeni bir kullanıcı oluştur ve güvenli bir şifre belirle
CREATE USER authuser WITH ENCRYPTED PASSWORD 'Şifren';

-- Kullanıcıya veritabanında tüm yetkileri ver
GRANT ALL PRIVILEGES ON DATABASE authdb TO authuser;
```
- Şifreyi değiştirmek için:
```postgresql
ALTER USER authuser WITH ENCRYPTED PASSWORD 'Yeni Şifre';
```
- Şimdi proje dosyamıza girerek `.env` dosyası oluşturuyoruz ve şu kodları ekliyoruz.
```bash
PORT=5000
DB_USER=authuser
DB_HOST=localhost
DB_NAME=authdb
DP_PASSWORD=Proje
DB_PORT=5432 
#supersecretkey: Bu, JWT token'larını imzalamak için kullanılan gizli bir anahtardır. Uygulama, bu anahtarı kullanarak JWT'yi oluşturur ve doğrular. Anahtarın güvenli olması çok önemlidir çünkü başkalarının erişimi durumunda token'lar sahte olarak üretilebilir.
JWT_SECRET=supersecretkey 
# PostgreSQL'in varsayılan bağlantı portudur. Yani, bu satır PostgreSQL veritabanına bağlanırken kullanılan portu belirtir. Bu port üzerinde PostgreSQL'e bağlanabilirsiniz.
```
- Önemli NOT!!! .env dosyası, gizli bilgiler içerdiği için versiyon kontrolüne dahil edilmemelidir. Bu dosyanın .gitignore dosyasına ekli olduğundan emin olmak gerekir.
- Şimdi db.js dosyasını proje klasörümüzün içerisinde oluşturuyoruz ve içerisine aşağıdaki kodları ekliyoruz. Bu [[Node.js]] uygulaması için PostgreSQL veritabanına bağlantıyı sağlayan bir betiktir.
```js
const { Pool } = require("pg"); //Bu satır, PostgreSQL için Node.js istemcisi olan pg paketini içeri aktarır. Pool, veritabanı bağlantı havuzunu oluşturmak için kullanılan bir sınıftır.
require("dotenv").config();
//Bu satır, .env dosyasındaki ortam değişkenlerini yükler.
//dotenv paketi, yapılandırma ayarlarını (örneğin, veritabanı kullanıcı adı, şifre, vs.) güvenli bir şekilde depolamak için kullanılır. Ortam değişkenleri, genellikle uygulamanın çevresel yapılandırmasını içerir.

const pool = new Pool({
user: process.env.DB_USER,
host: process.env.DB_HOST,
database: process.env.DB_NAME,
password: process.env.DB_PASSWORD,
port: process.env.DB_PORT,
});
//Burada, Pool sınıfını kullanarak bir veritabanı bağlantı havuzu oluşturuluyor. Bu havuz, veritabanına birden fazla bağlantı sağlamak için kullanılır ve veritabanına yapılan sorguların daha verimli bir şekilde işlenmesine yardımcı olur.

pool.connect()
.then(() => console.log("✅ PostgreSQL'e başarıyla bağlandı"))
.catch(err => console.error("❌ PostgreSQL bağlantı hatası", err));
//Bu satır, veritabanına bağlantı kurmayı dener. Eğer bağlantı başarılı olursa, `.then()` bloğunda `"✅ PostgreSQL'e başarıyla bağlandı"` mesajı yazdırılır.

module.exports = pool;
//Bu satır, pool nesnesini başka dosyalarla paylaşmak için dışa aktarır. Böylece, başka bir dosyada bu pool nesnesini kullanarak veritabanı işlemleri yapılabilir.
```
- NOT: `db.js`, veritabanı bağlantısı ve sorguları için merkezi bir yapı sağlar.
- `node db.js` yazarak test edebiliriz.
##### Dördüncü Adım
- Şimdi kullanıcı kayıt (register) ve giriş (login) işlemlerini yazacağız. Şifreleri bcrypt ile güvenli hale getireceğiz. JWT ile kimlik doğrulama yapacağız buradan devam edelim.
- `auth-system/routes/authRoutes.js` dosyasını oluştur ve şu kodu ekle:
```js
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

```
- `auth-system/app.js` dosyasını şu şekilde güncelle:
```js
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
```
- `/models/userModel.js` dosyasını oluştur ve şu içeriği ekle:
```js
const pool = require("../db");

// Kullanıcıyı e-posta ile bul
const findUserByEmail = async (email) => {
  const query = `SELECT * FROM users WHERE email = $1`;
  const { rows } = await pool.query(query, [email]);
  return rows[0];
};

// Yeni kullanıcı oluştur
const createUser = async (name, email, hashedPassword) => {
  const query = `INSERT INTO users (name, email, password) VALUES ($1, $2, $3) RETURNING *`;
  const values = [name, email, hashedPassword];
  const { rows } = await pool.query(query, values);
  return rows[0];
};

module.exports = { createUser, findUserByEmail };
```
- Şimdi ana proje dosyasında terminale `node app.js` yazarak test edelim.
##### Beşinci Adım
- Şimdi `JWT` ile korunan endpoint'ler (middleware kullanarak) ekleyebiliriz.
- Ayrıca, kullanıcı doğrulama ve token geçerliliğini kontrol etme gibi işlemleri eklememiz gerekebilir.


#### Aradaki Hatalar ve Düzeltmeleri
- Postman ile post işlemi yapınca aldığım hata: Burada users tablosuna erişim izni verilmedğini söylüyor.
```bash
error: permission denied for table users
    at /home/theghost/auth-system/node_modules/pg-pool/index.js:45:11
    at process.processTicksAndRejections (node:internal/process/task_queues:105:5)
    at async findUserByEmail (/home/theghost/auth-system/models/userModel.js:6:20)
    at async /home/theghost/auth-system/routes/authRoutes.js:15:26 {
  length: 93,
  severity: 'ERROR',
  code: '42501',
  detail: undefined,
  hint: undefined,
  position: undefined,
  internalPosition: undefined,
  internalQuery: undefined,
  where: undefined,
  schema: undefined,
  table: undefined,
  column: undefined,
  dataType: undefined,
  constraint: undefined,
  file: 'aclchk.c',
  line: '2843',
  routine: 'aclcheck_error'
}
```
- Çözüm:
- İlk önce psql ile terminale giriyoruz: `sudo psql -U postgres`
```postgresql
\c authdb --Kullanılan veri tabanını bağlıyoruz. Eğer db bilinmiyorsa \l ile bakılır.
GRANT ALL PRIVILEGES ON TABLE users TO your_user; --Kullanıcıya izin verme. your_user kısmını bilmiyorsan: \du çalıştır bu bize user ları listeler.
\q --Çıkış için.
```
- Postman ile alınan ikinci hata: Burada sequence users_id_seq izninin olmadığı söyleniyor.
```bash
error: permission denied for sequence users_id_seq
    at /home/theghost/auth-system/node_modules/pg-pool/index.js:45:11
    at process.processTicksAndRejections (node:internal/process/task_queues:105:5)
    at async createUser (/home/theghost/auth-system/models/userModel.js:14:20)
    at async /home/theghost/auth-system/routes/authRoutes.js:25:21 {
  length: 106,
  severity: 'ERROR',
  code: '42501',
  detail: undefined,
  hint: undefined,
  position: undefined,
  internalPosition: undefined,
  internalQuery: undefined,
  where: undefined,
  schema: undefined,
  table: undefined,
  column: undefined,
  dataType: undefined,
  constraint: undefined,
  file: 'sequence.c',
  line: '652',
  routine: 'nextval_internal'
}
```
- Çözüm:
- İlk önce psql ile terminale giriyoruz: `sudo psql -U postgres`
```postgresql
\c authdb
GRANT USAGE, SELECT ON SEQUENCE users_id_seq TO your_user;
\q
```

#### SQL İçerisinde Bulunan Tabloyu Görme
```bash
psql -U postgres
```
```postgresql
\c authdb
\dt --Tabloları listelemek için.
SELECT * FROM users; --users tablosundaki tüm verileri listeler.
\d users --Tablonun yapısını görmek için.
SELECT * FROM users WHERE email = 'jane@example.com'; --Veri sorgulama için
\q
```