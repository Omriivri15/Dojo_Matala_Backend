const nodemailer = require('nodemailer');

// Create transporter with proper configuration
const createTransporter = () => {
  // Check if SMTP is properly configured
  const hasSMTPConfig = process.env.SMTP_HOST && 
                        process.env.SMTP_USER && 
                        process.env.SMTP_PASS && 
                        process.env.SMTP_PASS !== 'your-app-password-here';

  if (!hasSMTPConfig) {
    return null; // Will use console logging instead
  }

  return nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: parseInt(process.env.SMTP_PORT || '587'),
    secure: process.env.SMTP_PORT === '465', // true for 465, false for other ports
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS
    },
    tls: {
      rejectUnauthorized: false // Allow self-signed certificates
    }
  });
};

const sendOTPEmail = async (email, otp) => {
  const transporter = createTransporter();

  // If no SMTP config, log to console
  if (!transporter) {
    console.log('\n========================================');
    console.log('📧 OTP EMAIL (Development Mode - No SMTP Config)');
    console.log('========================================');
    console.log(`To: ${email}`);
    console.log(`OTP Code: ${otp}`);
    console.log('========================================\n');
    return true;
  }

  try {
    // Verify transporter connection
    await transporter.verify();
    console.log('✅ SMTP server is ready to send emails');

    const mailOptions = {
      from: process.env.EMAIL_FROM || process.env.SMTP_USER,
      to: email,
      subject: 'Your OTP for Sign Up - DOJO IS GREAT',
      text: `Your OTP code is: ${otp}. This code will expire in 10 minutes.`,
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
          <h2 style="color: #667eea; text-align: center;">DOJO IS GREAT</h2>
          <p style="font-size: 16px;">Your OTP code for signup is:</p>
          <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; text-align: center; font-size: 36px; font-weight: bold; color: white; letter-spacing: 8px; margin: 20px 0; border-radius: 10px;">
            ${otp}
          </div>
          <p style="color: #666;">This code will expire in 10 minutes.</p>
          <p style="color: #999; font-size: 12px; margin-top: 30px;">If you didn't request this code, please ignore this email.</p>
        </div>
      `
    };

    const info = await transporter.sendMail(mailOptions);
    console.log(`✅ OTP email sent successfully to ${email}`);
    console.log(`   Message ID: ${info.messageId}`);
    return true;
  } catch (error) {
    console.error('❌ Error sending email:', error.message);
    console.error('   Full error:', error);
    
    // Log OTP to console as fallback
    console.log('\n========================================');
    console.log('⚠️  Email sending failed, but here is the OTP:');
    console.log('========================================');
    console.log(`To: ${email}`);
    console.log(`OTP Code: ${otp}`);
    console.log('========================================\n');
    
    // In development, allow signup to continue
    if (process.env.NODE_ENV !== 'production') {
      return true;
    }
    
    throw error;
  }
};

module.exports = { sendOTPEmail };

