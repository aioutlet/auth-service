import nodemailer from 'nodemailer';

let transporter;

if (process.env.EMAIL_PROVIDER === 'smtp') {
  transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: process.env.SMTP_PORT,
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS,
    },
  });
} else {
  throw new Error(`Unsupported EMAIL_PROVIDER: ${process.env.EMAIL_PROVIDER}`);
}

export function sendMail({ to, subject, text, html }) {
  return transporter.sendMail({ from: process.env.EMAIL_FROM, to, subject, text, html });
}
