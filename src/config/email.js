const nodemailer = require('nodemailer');
require('dotenv').config();

// Account where App Password was generated is 'guradfile@gmail.com'
let smtpUser = (process.env.SMTP_USER || 'guradfile@gmail.com').trim();
if (smtpUser.toLowerCase() === 'guardfile@gmail.com') {
  // Automatically correct common typo so Vercel env vars don't cause BadCredentials
  smtpUser = 'guradfile@gmail.com';
}
const smtpPass = (process.env.SMTP_PASS || 'kheiqwkvrwbnmwcm').replace(/\s+/g, '');

const transporter = nodemailer.createTransport({
  service: 'gmail',
  host: 'smtp.gmail.com',
  port: 465,
  secure: true,
  auth: {
    user: smtpUser,
    pass: smtpPass,
  },
  connectionTimeout: 10000,
  greetingTimeout: 10000,
  socketTimeout: 15000,
  tls: {
    rejectUnauthorized: false,
  },
});

module.exports = { transporter, smtpUser };
