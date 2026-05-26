// ==========================================================
//  Secure IoT Control System (Arduino Nano 33 IoT)
// ==========================================================
// Purpose:
// - Secure remote control of IoT device via TCP + JSON
// - Authentication using ECDSA (micro-ecc)
// - Message integrity via SHA-256 hashing
//
// Key Features:
// - WiFi TCP server (port 6668)
// - JSON command protocol
// - SHA-256 hash verification
// - ECDSA signature validation
// - Trusted client authentication
// - Secure LED control interface
// ==========================================================

#include <WiFiNINA.h>
#include <ArduinoJson.h>

// ----------------------------------------------------------
// 🔧 Micro-ecc library (ECDSA support)
// ----------------------------------------------------------
extern "C" {
  #include "uECC.h"
}

// ==========================================================
//  SHA-256 IMPLEMENTATION (embedded lightweight version)
// ==========================================================
//
// Used for:
// - Hashing incoming JSON messages
// - Ensuring message integrity before signature verification
//
// NOTE: No external crypto libraries used (fully embedded)
// ==========================================================

typedef struct {
  uint32_t state[8];
  uint64_t bitlen;
  uint32_t datalen;
  uint8_t data[64];
} SHA256_CTX;

// ----------------------------------------------------------
// SHA-256 bitwise operations macros
// ----------------------------------------------------------
#define ROTRIGHT(a,b) (((a) >> (b)) | ((a) << (32-(b))))
#define CH(x,y,z)    (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z)   (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x)       (ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22))
#define EP1(x)       (ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25))
#define SIG0(x)      (ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ ((x) >> 3))
#define SIG1(x)      (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10))

// ----------------------------------------------------------
// SHA-256 constants (FIPS standard)
// ----------------------------------------------------------
static const uint32_t kSHA[64] = {
  0x428a2f98ul,0x71374491ul,0xb5c0fbcful,0xe9b5dba5ul,0x3956c25bul,0x59f111f1ul,0x923f82a4ul,0xab1c5ed5ul,
  0xd807aa98ul,0x12835b01ul,0x243185beul,0x550c7dc3ul,0x72be5d74ul,0x80deb1feul,0x9bdc06a7ul,0xc19bf174ul,
  0xe49b69c1ul,0xefbe4786ul,0x0fc19dc6ul,0x240ca1ccul,0x2de92c6ful,0x4a7484aaul,0x5cb0a9dcul,0x76f988daul,
  0x983e5152ul,0xa831c66dul,0xb00327c8ul,0xbf597fc7ul,0xc6e00bf3ul,0xd5a79147ul,0x06ca6351ul,0x14292967ul,
  0x27b70a85ul,0x2e1b2138ul,0x4d2c6dfcul,0x53380d13ul,0x650a7354ul,0x766a0abbul,0x81c2c92eul,0x92722c85ul,
  0xa2bfe8a1ul,0xa81a664bul,0xc24b8b70ul,0xc76c51a3ul,0xd192e819ul,0xd6990624ul,0xf40e3585ul,0x106aa070ul,
  0x19a4c116ul,0x1e376c08ul,0x2748774cul,0x34b0bcb5ul,0x391c0cb3ul,0x4ed8aa4aul,0x5b9cca4ful,0x682e6ff3ul,
  0x748f82eeul,0x78a5636ful,0x84c87814ul,0x8cc70208ul,0x90befffaul,0xa4506cebul,0xbef9a3f7ul,0xc67178f2ul
};

// ==========================================================
// SHA-256 CORE TRANSFORM FUNCTION
// ==========================================================
// Processes 512-bit blocks and updates internal state
// ==========================================================

void sha256_transform(SHA256_CTX *ctx, const uint8_t data[]) {
  uint32_t a,b,c,d,e,f,g,h,i,j,t1,t2,m[64];

  for (i = 0, j = 0; i < 16; ++i, j += 4) {
    m[i] = ((uint32_t)data[j] << 24) |
           ((uint32_t)data[j+1] << 16) |
           ((uint32_t)data[j+2] << 8) |
           ((uint32_t)data[j+3]);
  }

  for (; i < 64; ++i) {
    m[i] = SIG1(m[i-2]) + m[i-7] + SIG0(m[i-15]) + m[i-16];
  }

  a = ctx->state[0];
  b = ctx->state[1];
  c = ctx->state[2];
  d = ctx->state[3];
  e = ctx->state[4];
  f = ctx->state[5];
  g = ctx->state[6];
  h = ctx->state[7];

  for (i = 0; i < 64; ++i) {
    t1 = h + EP1(e) + CH(e,f,g) + kSHA[i] + m[i];
    t2 = EP0(a) + MAJ(a,b,c);

    h = g; g = f; f = e; e = d + t1;
    d = c; c = b; b = a; a = t1 + t2;
  }

  ctx->state[0] += a;
  ctx->state[1] += b;
  ctx->state[2] += c;
  ctx->state[3] += d;
  ctx->state[4] += e;
  ctx->state[5] += f;
  ctx->state[6] += g;
  ctx->state[7] += h;
}

// ==========================================================
// SHA-256 INITIALIZATION
// ==========================================================

void sha256_init(SHA256_CTX *ctx) {
  ctx->datalen = 0;
  ctx->bitlen = 0;

  ctx->state[0] = 0x6a09e667ul;
  ctx->state[1] = 0xbb67ae85ul;
  ctx->state[2] = 0x3c6ef372ul;
  ctx->state[3] = 0xa54ff53aul;
  ctx->state[4] = 0x510e527ful;
  ctx->state[5] = 0x9b05688cul;
  ctx->state[6] = 0x1f83d9abul;
  ctx->state[7] = 0x5be0cd19ul;
}

// ==========================================================
// SHA-256 UPDATE (streaming input processing)
// ==========================================================

void sha256_update(SHA256_CTX *ctx, const uint8_t data[], size_t len) {
  for (size_t i = 0; i < len; ++i) {
    ctx->data[ctx->datalen++] = data[i];

    if (ctx->datalen == 64) {
      sha256_transform(ctx, ctx->data);
      ctx->bitlen += 512;
      ctx->datalen = 0;
    }
  }
}

// ==========================================================
// SHA-256 FINALIZATION (produces 32-byte hash)
// ==========================================================

void sha256_final(SHA256_CTX *ctx, uint8_t hash[]) {
  uint32_t i = ctx->datalen;

  if (ctx->datalen < 56) {
    ctx->data[i++] = 0x80;
    while (i < 56) ctx->data[i++] = 0x00;
  } else {
    ctx->data[i++] = 0x80;
    while (i < 64) ctx->data[i++] = 0x00;
    sha256_transform(ctx, ctx->data);
    memset(ctx->data, 0, 56);
  }

  ctx->bitlen += (uint64_t)ctx->datalen * 8;

  ctx->data[63] = ctx->bitlen & 0xFF;
  ctx->data[62] = (ctx->bitlen >> 8) & 0xFF;
  ctx->data[61] = (ctx->bitlen >> 16) & 0xFF;
  ctx->data[60] = (ctx->bitlen >> 24) & 0xFF;
  ctx->data[59] = (ctx->bitlen >> 32) & 0xFF;
  ctx->data[58] = (ctx->bitlen >> 40) & 0xFF;
  ctx->data[57] = (ctx->bitlen >> 48) & 0xFF;
  ctx->data[56] = (ctx->bitlen >> 56) & 0xFF;

  sha256_transform(ctx, ctx->data);

  for (i = 0; i < 4; ++i) {
    hash[i]      = (ctx->state[0] >> (24 - i * 8)) & 0xFF;
    hash[i + 4]  = (ctx->state[1] >> (24 - i * 8)) & 0xFF;
    hash[i + 8]  = (ctx->state[2] >> (24 - i * 8)) & 0xFF;
    hash[i + 12] = (ctx->state[3] >> (24 - i * 8)) & 0xFF;
    hash[i + 16] = (ctx->state[4] >> (24 - i * 8)) & 0xFF;
    hash[i + 20] = (ctx->state[5] >> (24 - i * 8)) & 0xFF;
    hash[i + 24] = (ctx->state[6] >> (24 - i * 8)) & 0xFF;
    hash[i + 28] = (ctx->state[7] >> (24 - i * 8)) & 0xFF;
  }
}

// ==========================================================
//  Helper: HEX ↔ BYTE CONVERSION
// ==========================================================

// Converts binary data to HEX string
String toHex(const uint8_t* data, size_t len) {
  const char* hex = "0123456789ABCDEF";
  String s;

  for (size_t i = 0; i < len; i++) {
    s += hex[data[i] >> 4];
    s += hex[data[i] & 0xF];
  }

  return s;
}

// Converts HEX string back to bytes (used for signatures)
bool hexToBytes(const char* hex, uint8_t* out, size_t outLen) {
  for (size_t i = 0; i < outLen; i++) {
    char hi = hex[2*i];
    char lo = hex[2*i+1];

    auto val = [](char c)->int {
      if (c >= '0' && c <= '9') return c - '0';
      if (c >= 'A' && c <= 'F') return c - 'A' + 10;
      if (c >= 'a' && c <= 'f') return c - 'a' + 10;
      return -1;
    };

    int hi_v = val(hi);
    int lo_v = val(lo);
    if (hi_v < 0 || lo_v < 0) return false;

    out[i] = (hi_v << 4) | lo_v;
  }

  return true;
}

// ==========================================================
//  ECDSA + RNG SUPPORT (micro-ecc dependency)
// ==========================================================

// RNG required by micro-ecc (Arduino pseudo-random source)
int rng_function(uint8_t *dest, unsigned size) {
  while (size) {
    uint32_t r = ((uint32_t)random() << 17)
               ^ ((uint32_t)random() << 2)
               ^ random();

    unsigned chunk = size < sizeof(r) ? size : sizeof(r);
    memcpy(dest, &r, chunk);

    dest += chunk;
    size -= chunk;
  }
  return 1;
}

// ==========================================================
//  NETWORK CONFIGURATION
// ==========================================================

char ssid[] = "WiFi";
char pass[] = "HT8d6";
WiFiServer server(6668);

// ==========================================================
//  CRYPTO KEYS (DEVICE + CLIENT)
// ==========================================================

static uint8_t privateKey[32];
static uint8_t publicKey[64];
bool keysReady = false;

// Trusted client public key (ECDSA verification anchor)
static const uint8_t clientPubKey[64] = {
  0x29, 0x99, 0xd8, 0xca, 0xf8, 0x2a, 0x97, 0xfd,
  0x6c, 0x14, 0x68, 0xe3, 0xbf, 0xba, 0x8c, 0x66,
  0x14, 0xac, 0xc6, 0xaa, 0xff, 0x15, 0x2f, 0xa1,
  0x27, 0xe1, 0x47, 0x95, 0xf2, 0xf7, 0x17, 0xf7,
  0x45, 0xf4, 0x70, 0x19, 0x1c, 0x73, 0x0f, 0x70,
  0x5a, 0xbc, 0x62, 0x27, 0x47, 0xe6, 0x2d, 0xde,
  0x12, 0x04, 0x78, 0x2a, 0xc9, 0x72, 0x83, 0xee,
  0x4b, 0x48, 0x05, 0xdd, 0xd3, 0x85, 0xbc, 0x06
};

// ==========================================================
//  KEY GENERATION
// ==========================================================

void generateKeyIfNeeded() {
  if (!keysReady) {
    const struct uECC_Curve_t *curve = uECC_secp256r1();

    if (!uECC_make_key(publicKey, privateKey, curve)) {
      Serial.println("Error generating ECDSA keypair!");
      return;
    }

    Serial.println("ECDSA keypair generated successfully.");
    keysReady = true;
  }
}

// ==========================================================
//  SETUP (BOOT SEQUENCE)
// ==========================================================

void setup() {
  Serial.begin(9600);
  while (!Serial);

  randomSeed(analogRead(A0));
  uECC_set_rng(&rng_function);

  pinMode(LED_BUILTIN, OUTPUT);

  Serial.print("Connecting to WiFi: ");
  Serial.println(ssid);

  while (WiFi.begin(ssid, pass) != WL_CONNECTED) {
    Serial.println("Connecting...");
    delay(1000);
  }

  Serial.print("Connected. IP: ");
  Serial.println(WiFi.localIP());

  server.begin();
  generateKeyIfNeeded();
}

// ==========================================================
//  MAIN LOOP (TCP SERVER HANDLER)
// ==========================================================

void loop() {
  WiFiClient c = server.available();
  if (!c) return;

  Serial.println("--- client connected ---");

  String in = "";
  unsigned long start = millis();

  while (c.connected() && millis() - start < 2000) {
    if (c.available()) {
      char ch = c.read();
      start = millis();
      if (ch == '\n') break;
      in += ch;
    }
  }

  in.trim();
  Serial.print("Received: ");
  Serial.println(in);

  if (in.length() == 0) {
    c.stop();
    return;
  }

  StaticJsonDocument<1024> doc;
  DeserializationError err = deserializeJson(doc, in);

  if (err) {
    c.println("{\"response\":\"json_error\"}");
    c.stop();
    return;
  }

  const char* cmd = doc["command"];
  const char* sigHex = doc["signature"];

  if (!cmd || !sigHex) {
    c.println("{\"response\":\"missing_command_or_signature\"}");
    c.stop();
    return;
  }

  String sigStr = String(sigHex);
  sigStr.trim();
  doc.remove("signature");

  String js;
  serializeJson(doc, js);

  SHA256_CTX ctx;
  sha256_init(&ctx);
  sha256_update(&ctx, (const uint8_t*)js.c_str(), js.length());

  uint8_t hash[32];
  sha256_final(&ctx, hash);

  uint8_t sigBytes[64];

  if (!hexToBytes(sigStr.c_str(), sigBytes, 64)) {
    c.println("{\"response\":\"invalid_signature_format\"}");
    c.stop();
    return;
  }

  const struct uECC_Curve_t *curve = uECC_secp256r1();

  bool ok = uECC_verify(clientPubKey, hash, sizeof(hash), sigBytes, curve);

  if (!ok) {
    c.println("{\"response\":\"invalid_signature\"}");
    c.stop();
    return;
  }

  Serial.println("Signature verified. Executing command.");

  if (strcmp(cmd, "led_on") == 0) {
    digitalWrite(LED_BUILTIN, HIGH);
    c.println("{\"response\":\"led_on\"}");
  }
  else if (strcmp(cmd, "led_off") == 0) {
    digitalWrite(LED_BUILTIN, LOW);
    c.println("{\"response\":\"led_off\"}");
  }
  else if (strcmp(cmd, "status") == 0) {
    bool s = digitalRead(LED_BUILTIN);
    c.print("{\"response\":\"status\",\"led\":\"");
    c.print(s ? "on" : "off");
    c.println("\"}");
  }
  else if (strcmp(cmd, "get_pubkey") == 0) {
    String pubHex = toHex(publicKey, 64);
    c.print("{\"response\":\"arduino_pubkey\",\"pubkey\":\"");
    c.print(pubHex);
    c.println("\"}");
  }
  else {
    c.println("{\"response\":\"unknown_command\"}");
  }

  c.flush();
  delay(10);
  c.stop();

  Serial.println("--- client disconnected ---");
}