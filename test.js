const bcrypt = require("bcryptjs");
const hashed = bcrypt.hashSync("password123", 10);
console.log(hashed);
