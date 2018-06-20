var express = require('express');
var router = express.Router();
var multer = require('multer');
var passport = require('passport');
var LocalStrategy = require('passport-local').Strategy;

var User = require('../models/users');

/* GET users listing. */

var storage = multer.diskStorage({

  destination: (req, file, cb) => {
    cb(null, './uploads');
  },

  filename: (req, file, cb) => {
    cb(null, Date.now() + '.jpg');
  }
});

var upload = multer({ storage: storage });

router.get('/', (req, res) => {
  res.send('responded');
});

router.get('/profile/:username', function(req, res, next) {
  
  const { username } = req.params;

  User.getUserByUsername(username, function(err, user) {

    console.log(user);

    res.json(user);
  });
});

router.get('/register', function(req, res, next) {
  res.render('register', {
    title: 'Register'
  });
});

router.get('/login', function(req, res, next) {
  res.render('login', {
    title: 'Login'
  });
});

router.post('/login', passport.authenticate('local', {failureRedirect: '/users/login', failureFlash: 'invalid username or password'}), function(req, res) {
    
  req.flash('success', 'You are now logged in');

  res.redirect('/');
});

passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.getUserById(id, function(err, user) {
    done(err, user);
  });
});

passport.use(new LocalStrategy(function(username, password, done) {

  User.getUserByUsername(username, function(err, user) {
    if(err) throw err;

    if(!user) {
      return done(null, false, {message: 'Unknown User'});
    }

    User.comparePassword(password, user.password, function(err, isMatch) {
      if(err) return done(err);

      if(isMatch) {
        return done(null, user);
      } else {
        return done(null, false, {message: 'Invalid Password'});
      }
    });
  });
}));

router.post('/register', upload.single('profileImage'), function(req, res, next) {
  
  const { name, email, password, username, password2 } = req.body;

  var profileImage;

  if(req.file) {
    console.log("Uploading File.....");
    console.log(req.file.filename);
    profileImage = req.file.filename;
  } else {
    console.log("No File Uploaded");
    var profileImage = 'noimage.jpg'
  }

  req.checkBody('name', 'Name field is required').notEmpty();
  req.checkBody('email', 'Email field is required').notEmpty();
  req.checkBody('email', 'Email Must be valid email').isEmail();
  req.checkBody('username', 'Username field is required').notEmpty();
  req.checkBody('password', 'Password field is required').notEmpty();
  req.checkBody('password2', 'Passwords do not match').equals(password);

  var errors = req.validationErrors();

  if(errors) {
    res.render('register', {
      errors
    });
  } else {
      var newUser = new User({ name, email, username, password, profileImage });

      User.createUser(newUser, function(err, user) {

        if(err) throw err;

      });

      req.flash('success', 'You are now registered and can login');

      res.location('/');
      res.redirect('/');
  }

});

router.get('/logout', function(req, res) {
  req.logout();
  req.flash('success', 'You are now logged out');
  res.redirect('/users/login');
});

module.exports = router;
