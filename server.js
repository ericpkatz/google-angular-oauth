var Sequelize = require('sequelize');
var db = new Sequelize(process.env.DATABASE_URL);

var User = db.define('user', {
  name: Sequelize.STRING, 
  password: Sequelize.STRING,
  token: Sequelize.STRING
});

if(process.env.SYNC){
  db.sync({ force: true })
    .then(function(){
      return Promise.all([
          User.create({ name: 'moe', password: 'foo'}),
          User.create({ name: 'larry', password: 'bar' })
      ]);
    })
    .catch(function(err){
      console.log(err);
    });
}

var express = require('express');
var swig = require('swig');
swig.setDefaults({ cache: false });
var path = require('path');
var app = express();
app.use(require('express-session')( { secret: process.env.SECRET }));
app.use(express.static(path.join(__dirname, 'node_modules')));
app.use('/browser', express.static(path.join(__dirname, 'browser')));
app.use(require('body-parser').json());
app.use(require('method-override')('_method'));

var passport = require('passport');
var GoogleStrategy = require('passport-google-oauth').OAuth2Strategy;

app.use(passport.initialize());
app.use(passport.session());



app.engine('html', swig.renderFile);
app.set('view engine', 'html');

app.use(function(req, res, next){
  if(!req.session.userId)
    return next();
  User.findById(req.session.userId)
    .then(function(user){
      res.locals.user = user;
      next();
    })
    .catch(next);

});

app.get('/', function(req, res, next){
  res.render('index');
});

app.get('/login', function(req, res, next){
  res.render('login');
});

//if running locally you can have a file with your 'secrets'
//if you are deployed- set environmental variables
var config = process.env; 
if(process.env.NODE_ENV === 'development'){
  config = require('./config.json');
}
  //strategy consists of things google needs to know, plus a callback when we successfully get a token which identifies the user
  passport.use(new GoogleStrategy({
    clientID: config.CLIENT,
    clientSecret: config.SECRET,
    callbackURL: config.URL 
  }, 
  function (token, refreshToken, profile, done) { 
    //this will be called after we get a token from google 
    //google has looked at our applications secret token and the token they have sent our user and exchanged it for a token we can use
    //now it will be our job to find or create a user with googles information
    if(!profile.emails.length)//i need an email
      return done('no emails found', null);
    User.findOne({ where: {token: token} })
      .then(function(user){
        if(user)
          return user;
        return User.create({
          name: profile.emails[0].value, 
          token: token}
        );
      })
      .then(function(user){
        done(null, user); 
      });
  }));

//passport serialization methods
passport.serializeUser(function(user, done){
  //passport asks us how we want to store our user in session
  //we are only storing the id
  done(null, user.id);
});

passport.deserializeUser(function(userId, done){
  //passport will send us the data we stored in session for our user and it is up to us to use it to 'recreate our user'
  User.findById(userId)
    .then(function(user){
      done(null, user);
    });
});


//passport will take care of authentication
app.get('/login/google', passport.authenticate('google', {
	scope: 'email'
}));

//here is our callback - passport will exchange token from google with a token which we can use.
app.get('/auth/google/callback', passport.authenticate('google', {
	successRedirect: '/',
	failureRedirect: '/'
}));



function restrict(req, res, next){
  if(res.locals.user)
    return next();
  res.sendStatus(401);
}

app.get('/restricted', restrict, function(req, res, next){
  res.render('restricted');
});

app.get('/api/sessions', function(req, res, next){
  if(res.locals.user || req.user)
    return res.send(res.locals.user || req.user);
  res.sendStatus(401);
});

app.post('/api/sessions', function(req, res, next){
  console.log(req.body);
  User.findOne({ where: { name: req.body.name, password: req.body.password}})
    .then(function(user){
      if(user){
        req.session.userId = user.id;
        return res.send(user);
      }
      else {
        return res.sendStatus(401);
      }
    })
    .catch(next);
});

app.delete('/api/sessions', function(req, res, next){
  req.session.destroy();
  res.sendStatus(200);
});

var port = process.env.PORT || 3000;
app.listen(port, function(){
  console.log('listening on port ' + port);
});

