const nodemailer = require('nodemailer');
require('dotenv').config();

// Create reusable transporter
const transporter = nodemailer.createTransport({
  service: 'gmail',
  host: process.env.SMTP_HOST || 'smtp.gmail.com',
  port: parseInt(process.env.SMTP_PORT || '587', 10),
  secure: false, // true for 465, false for other ports
  auth: {
    user: process.env.SMTP_USER || 'guardfile@gmail.com',
    pass: (process.env.SMTP_PASS || 'khei qwkv rwbn mwcm').replace(/\s+/g, ''),
  },
  tls: {
    rejectUnauthorized: false,
  },
});

module.exports = { transporter };
