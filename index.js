const express = require('express');
const bcrypt = require('bcrypt');

const bodyParser = require('body-parser');
const app = express();
const { user } = require('./models');
const ejs = require('ejs');
const winston = require('winston');

const logger = winston.createLogger({
    level: 'info',
    format: winston.format.json(),
    defaultMeta: { service: 'user-service' },
    transports: [
      //
      // - Write all logs with importance level of `error` or less to `error.log`
      // - Write all logs with importance level of `info` or less to `combined.log`
      //
      new winston.transports.File({ filename: 'error.log', level: 'error' }),
      new winston.transports.File({ filename: 'combined.log' }),
    ],
  });
  
  //
  // If we're not in production then log to the `console` with the format:
  // `${info.level}: ${info.message} JSON.stringify({ ...rest }) `
  //
  if (process.env.NODE_ENV !== 'production') {
    logger.add(new winston.transports.Console({
      format: winston.format.simple(),
    }));
  }
  
  
  
app.all('*', (req, res, next) => {
      logger.log({
          level: 'info',
          method: req.method,
          url: req.url,
          body: req.body,
          params: req.params,
          timestamp: new Date().toLocaleString()
      });
      next();
  })

app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({ extended: false }));
app.use(express.json());
app.use(express.static(__dirname + '/public'));
const path = require('path');



app.get('/', (req, res) => {
  res.render('register', { error: '' });
});

app.post('/register', async (req, res) => {
  const { yourName, email, password, reenterpassword } = req.body;
    // Check if the name contains a URL
    const urlRegex = /[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)?/gi;;
    if (yourName == urlRegex) {
      return res.render('register', { error: 'Name cannot contain a URL' });
    }


  // Check if passwords match
  if (password !== reenterpassword) {
    // Passwords don't match, render the 'register' view with the error message
    return res.render('register', { error: 'Passwords must match' });
  }
  

  // Password Checks (uncomment and complete these as needed)
  if (password.length < 6) {
      return res.render('register', { error: 'Password must be at least 6 characters' });
  }

  if (!/[a-zA-Z]/.test(password) || !/\d/.test(password)) {
      return res.render('register', { error: 'Password must contain at least one letter and one number' });
  }



  if (!/[a-zA-Z]/.test(yourName) || /\d/.test(yourName)) {
  return res.render('register', { error: 'Name must not contain any numbers' });
}

  

try {
  const saltRounds = 10; // Specify the number of salt rounds
  const hashedPassword = await bcrypt.hash(password, saltRounds);

  await user.create({
    yourName: yourName,
    email: email,
    password: hashedPassword, // Store the hashed password in the database
    reenterpassword: reenterpassword,
  });

    // If successful, you can redirect the user to a success page
    res.redirect('/login.html');
    // res.redirect('/success'); // Replace with your actual success route
  } catch (error) {
    // Handle database or other errors here
    console.error(error);
    // Render an error message on the registration page
    return res.render('register', { error: 'An error occurred during registration' });
  }

  // Logging and rendering 'register' view after successful registration or error handling
  console.log({
    yourName: yourName,
    email: email,
    password: password,
    reenterpassword: reenterpassword,
  });

  // ... Any other code you need to execute after database interaction
  // res.render('register') or any other response logic
});

app.listen(3001, () => {
  console.log('Server is running on port 3001');
});
