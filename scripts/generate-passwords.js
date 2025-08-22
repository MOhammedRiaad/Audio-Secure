// scripts/generate-passwords.js
// Script to generate hashed passwords for users
const bcrypt = require("bcrypt");
const crypto = require("crypto");

async function generatePassword(plainPassword) {
  const saltRounds = 10;
  const hashedPassword = await bcrypt.hash(plainPassword, saltRounds);
  return hashedPassword;
}

async function generateCredentials() {
  console.log("🔐 Secure Audio Streaming - Password Generator");
  console.log("=".repeat(50));

  const passwords = [
    { username: "admin", password: "SecureAudio2025" },
    { username: "user1", password: "UserPass123" },
    { username: "user2", password: "MediaAccess456" },
    { username: "guest", password: "TempGuest789" },
  ];

  console.log("\n📝 Generated User Credentials:");
  console.log("-".repeat(30));

  for (const { username, password } of passwords) {
    const hashedPassword = await generatePassword(password);
    console.log(`Username: ${username}`);
    console.log(`Plain Password: ${password}`);
    console.log(`Hashed Password: ${hashedPassword}`);
    console.log("-".repeat(30));
  }

  console.log("\n🔑 JWT Secret (copy to your .env file):");
  console.log(`JWT_SECRET=${crypto.randomBytes(64).toString("hex")}`);

  console.log("\n🔐 Encryption Key (copy to your .env file):");
  console.log(`ENCRYPTION_KEY=${crypto.randomBytes(32).toString("hex")}`);

  console.log("\n⚠️  Security Notes:");
  console.log("1. Change default passwords immediately");
  console.log("2. Store JWT_SECRET and ENCRYPTION_KEY in .env file");
  console.log("3. Never commit .env file to version control");
  console.log("4. Use strong, unique passwords for production");
  console.log("5. Consider using a proper user database");
}

// Custom password generation
async function generateCustomPassword() {
  const readline = require("readline");
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });

  rl.question("Enter username: ", (username) => {
    rl.question("Enter password: ", async (password) => {
      const hashedPassword = await generatePassword(password);

      console.log("\n✅ Generated Credentials:");
      console.log(`Username: ${username}`);
      console.log(`Hashed Password: ${hashedPassword}`);
      console.log("\nAdd this to your USERS object in server.js:");
      console.log(`'${username}': '${hashedPassword}',`);

      rl.close();
    });
  });
}

// Check command line arguments
const args = process.argv.slice(2);
if (args.includes("--custom")) {
  generateCustomPassword();
} else {
  generateCredentials();
}

module.exports = { generatePassword };
