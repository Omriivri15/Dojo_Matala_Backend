# Deploying Backend to Heroku

## Prerequisites
- Heroku account
- Heroku CLI installed
- MongoDB Atlas account (or MongoDB database)

## Steps

1. **Login to Heroku:**
   ```bash
   heroku login
   ```

2. **Create Heroku app:**
   ```bash
   heroku create your-app-name-backend
   ```

3. **Set environment variables:**
   ```bash
   heroku config:set MONGODB_URI=your-mongodb-connection-string
   heroku config:set JWT_SECRET=your-jwt-secret
   heroku config:set JWT_REFRESH_SECRET=your-refresh-token-secret
   heroku config:set SMTP_HOST=smtp.gmail.com
   heroku config:set SMTP_PORT=587
   heroku config:set SMTP_USER=your-email@gmail.com
   heroku config:set SMTP_PASS=your-app-password
   heroku config:set EMAIL_FROM=your-email@gmail.com
   ```

4. **Deploy:**
   ```bash
   git push heroku main
   ```

5. **Check logs:**
   ```bash
   heroku logs --tail
   ```

## Your backend URL will be:
`https://your-app-name-backend.herokuapp.com`

