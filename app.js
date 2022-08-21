require('dotenv').config()
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportMongoose = require("passport-local-mongoose");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const findOrCreate = require("mongoose-findorcreate");
const multer = require("multer");

const app = express();

app.use(bodyParser.urlencoded({extended: true}));
app.use(express.static("public"));
app.set("view engine", "ejs");

//Using session package and setting it some initial configuration
//Inside documentation for session
app.use(session({
  secret: "Bleh bleh secret.",  //This is the secret used to sign the session ID cookie
  resave: false,
  saveUninitialized: false
}));

//Initialising passport package and telling passport to use and manage our sessions
//Inside documentation for passport
app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/snapsDB");

const userSchema = new mongoose.Schema({
  email: String,
  username: String,
  password: String,
  googleId: String,
  secret: String,
  image: String
});

//The plugin is used to hash and salt passwords and save the data to mongoDB
//Inside documentation for passport-local-mongoose
userSchema.plugin(passportMongoose);
userSchema.plugin(findOrCreate);
const User = mongoose.model("User", userSchema);

//Strategy to authenticate users using thier username and password
//Inside documentation for passport-local-mongoose
passport.use(User.createStrategy());

//Stores user identification in cookie
//Inside documentation for passport-local-mongoose
// passport.serializeUser(User.serializeUser()); ----> Used for Local authentication

passport.serializeUser(function(user,done){
  done(null,user.id);
});

//Destroys the cookie to discover the identification and authenticate the user
//Inside documentation for passport-local-mongoose
// passport.deserializeUser(User.deserializeUser()); ----> Used for Local authentication

passport.deserializeUser(function(id, done){
  User.findById(id, function(err,user){
    done(err,user);
  });
});

//The google strategy to login our user
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },

  //A callback function where google sends back a access token and profile
  function(accessToken, refreshToken, profile, cb) {
    //We use their google id to find the user or create them
    //The findOrCreate function actually does not exist but people have maded it, hence you can npm install it mongoose-findorcreate
    console.log(profile);
    console.log("------------------------------------------------------------");
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

//Disk Storage for images
const Storage = multer.diskStorage({
  destination: "./public/uploads",
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9)
    cb(null, file.originalname + '-' + uniqueSuffix)
  }
})

// Middleware to Specifying the above storage as multer storage
const upload = multer({
  storage: Storage,
}).single("mypic");

app.get("/", function(req,res){
  res.render("home")
});

//Inside here we will initiate our authentication with google
//The scope tells we want users profile which includes thier email and user id
app.get("/auth/google",
  passport.authenticate("google", {scope: ["profile"]})
);

//Here we authenticate the user through google and save their session in a cookie
app.get("/auth/google/secrets",
  passport.authenticate("google", { failureRedirect: "/login" }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect("/secrets");
  });

app.get("/login", function(req,res){
  res.render("login");
});

app.get("/register", function(req,res){
  res.render("register");
});

app.get("/secrets", function(req,res){

  User.find({"image": {$ne:null}}, function(err, found){
    if(!err){
      res.render("secrets", {allSecretUser: found});
    }
  });

  //Here we check if user is authenticated, here we rely on passport, passport-local, passportMongoose, session
  // if(req.isAuthenticated()){
  //   res.render("secrets");
  // }
  // else{
  //   res.redirect("/login");
  // }
});

app.get("/submit", function(req,res){

  if(req.isAuthenticated()){
    res.render("submit");
  }
  else{
    res.redirect("/login");
  }
});

app.get("/logout", function(req,res){

  req.logout(function(err){
    if(err){console.log(err);}
  });

  res.redirect("/");
});

app.post("/submit", upload, function(req,res){
  const submittedPic =  req.file.filename;
  console.log(submittedPic);
  console.log(req.user.id)

  User.findById(req.user.id, function(err,foundDoc){
    if(err){
      console.log(err);
    }
    else{
      if(req.file){
        foundDoc.image = submittedPic;
        foundDoc.save(function(){
        res.redirect("/secrets");
      });
      }
      else{
        res.redirect("/secrets");
      }
    }
  });
});

app.post("/register", function(req,res){
  //Register function comes from the passport-local-mongoose package
  //Inside documentation for passport-local-mongoose
  //Package passport-local-mongoose itself adds username hash and salt to the DB
  User.register({username: req.body.username}, req.body.password, function(err, user){
    if(err){
      console.log(err);
      res.redirect("/register");
    }
    else{
      // The callback function only triggered if authentication was succesful
      //Authenticating user and setting up login session for them

      passport.authenticate("local")(req, res, function(){
        res.redirect("/secrets");
      });
    }
  });
});

app.post("/login", function(req,res){

  const user = new User({
    username: req.body.username,
    password: req.body.password
  });

  //We use passport to login the user and authenticate them
  req.login(user, function(err){
    if(err){
      console.log(err);
      res.redirect("/login");
    }
    else{
      passport.authenticate("local")(req, res, function(){
        res.redirect("/secrets");
      });
    }
  })


});

app.listen(3000, function(){
  console.log("Server up and running");
});






// Using bcrypt Authentication 

// const bcrypt = require("bcrypt");
// const salt = 10;


// bcrypt.hash(req.body.password, salt, function(err, hash) {
//
//   const newUser = new User({
//     email: req.body.username,
//     password: hash
//   });
//
//   newUser.save(function(err){
//     if(!err){
//       res.render("secrets");
//     }
//     else{
//       console.log(err);
//     }
//   });
//
// });


// const usr = req.body.username;
// const pass = req.body.password;
//
// User.findOne({email: usr}, function(err,found){
//   if(err){
//     console.log(err);
//   }
//   else if(found){
//     bcrypt.compare(pass, found.password, function(err, result) {
//       if(result === true){
//         res.render("secrets");
//       }
//     });
//   }
// });
