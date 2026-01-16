// utils/mail.js
const nodemailer = require("nodemailer");

const transporter = nodemailer.createTransport({
  host: "smtp.gmail.com",
  port: 587,
  secure: false, // TLS is not used on port 587
  auth: {
    user: "safesphere.cf@gmail.com", // your Gmail
    pass: "agzgzywmujfuksbg",       // 16-char Gmail App Password, no spaces
  },
});

const sendOtpEmail = async (to, otp) => {
  await transporter.sendMail({
    from: `"CalVant" <safesphere.cf@gmail.com>`,
    to,
    subject: "Your OTP for Password Reset",
    text: `Your OTP for password reset is: ${otp}. It is valid for 10 minutes.`,
  });
};

module.exports = { sendOtpEmail };
