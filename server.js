//MODULES
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const router = require('./Routes/routes')
const jwt = require('jsonwebtoken');
const passport = require('passport');
const LocalStrategy = require('passport-local');

const JwtStrategy = require('passport-jwt').Strategy;
const { ExtractJwt } = require('passport-jwt');
const secret = 'secret';
// const session = require('express-session');
// const cors = require('cors')

//DATABASE CONNECTION
const User = require("./Users/User");

mongoose.connect("mongodb://localhost/Auth")
.then(connected => {
    console.log('connected to db')
}).catch(err => {
    console.log('error connecting to db')
})

//SERVER
const server = express();

// server.use(cors())


//SERVER FUNCTIONS/MIDDLEWARE
// function validate(password, passwordDB) {
//     bcrypt.compare(password, passwordDB, function(err, res) {
//         console.log(res)
//     })
// }

// function seperateObject(info) {
//     let usernameVal = Object.values(info, [0]);
//     usernameVal = usernameVal[0]
//     let obj = {
//         username: usernameVal.toString()
//     }
//     return obj;
// }

// function restrictedCheck(req, res) {
//     if(req.session && req.session.username) {
//         res.send("You may pass")
//     } else {
//         res.send("YOU SHALL NOT PASS");
//     }
// }

// server.use(express.json())

// server.use('/', router )



//SERVER HANDLERS

// server.get('/', (req, res) => {
//     if (req.session && req.session.username) {
//         User.find().then(users => {
//             res.status(200).json(users)
//         })
//     //   res.send(`welcome back ${req.session.username}`);
//     } else {
//       res.send('YOU SHALL NOT PASS');
//     }
//   });
  

// server.post('/register', (req, res) => {
//     const user = new User(req.body);

//     user.save().then(user => {
//         res.send(user)
//     }).catch(err => {
//         res.status(400).json({
//             error: "There was an error registering as a new user"
//         })
//     })
// })

// server.post('/login', (req, res, next) => {
//     const login = req.body;
//     // console.log(login)
    
//     User.findOne(seperateObject(login)).then(user => {
//         // console.log(login.password)
//         // console.log(user.password)

//         user.isPasswordValid(login.password).then(valid => {
//             if(valid) {
//                 req.session.username = user.username
//                 res.send("Login successful")
//             } else {
//                 res.send("Login failed")
//             }
//         })
//     }).catch(err => {
//         res.status(400).json({
//             error: "Could not find that username"
//         })
//     })
// })

// server.get("/logout", (req, res) => {
//     if(req.session) {
//         req.session.destroy(function(err) {
//             if(err) {
//                 res.send('Error')
//             } else {
//                 res.send("Logged out, goodbye(:")
//             }
//         })
//     }
// })

// server.get("/api/restricted", (req, res) => {
//     res.send("RESTRICTED SERVER RUNNING")
// })


const localStrategy = new LocalStrategy(function(username, password, done) {
  User.findOne({ username })
    .then(user => {
      if (!user) {
        done(null, false);
      } else {
        user
          .validatePassword(password)
          .then(isValid => {
            if (isValid) {
              const { _id, username } = user;
              return done(null, { _id, username }); // this ends in req.user
            } else {
              return done(null, false);
            }
          })
          .catch(err => {
            return done(err);
          });
      }
    })
    .catch(err => done(err));
});

const jwtOptions = {
  jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
  secretOrKey: secret,
};

const jwtStrategy = new JwtStrategy(jwtOptions, function(payload, done) {
  // here the token was decoded successfully
  User.findById(payload.sub)
    .then(user => {
      if (user) {
        done(null, user); // this is req.user
      } else {
        done(null, false);
      }
    })
    .catch(err => {
      done(err);
    });
});

// passport global middleware
passport.use(localStrategy);
passport.use(jwtStrategy);

// passport local middleware
const passportOptions = { session: false };
const authenticate = passport.authenticate('local', passportOptions);
const protected = passport.authenticate('jwt', passportOptions);

// helpers
function makeToken(user) {
  const timestamp = new Date().getTime();
  const payload = {
    sub: user._id,
    iat: timestamp,
    username: user.username,
  };
  const options = {
    expiresIn: '24h',
  };

  return jwt.sign(payload, secret, options);
}

// routes
server.get('/', function(req, res) {
    res.send({ api: 'up and running' });
  });

  server.post('/register', function(req, res) {
    User.create(req.body) // new User + user.save
      .then(user => {
        const token = makeToken(user);
        res.status(201).json({ user, token });
      })
      .catch(err => res.status(500).json(err));
  });

  server.post('/login', authenticate, (req, res) => {
    // if we're here the user logged in correctly
    res.status(200).json({ token: makeToken(req.user), user: req.user });
  });

  server.get('/users', protected, (req, res) => {
    User.find()
      .select('username')
      .then(users => {
        res.json(users);
      })
      .catch(err => {
        res.status(500).json(err);
      });
  });
server.listen(5000, () => console.log('API RUNNING ON PORT 5000'));

