// jshint esversion:6
require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth2').Strategy;
const findOrCreate = require("mongoose-findorcreate");

const app = express();

app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(session({
    secret: 'Our little secret',
    resave: false,
    saveUninitialized: true,
    cookie: { maxAge: 1000 * 60 * 60 * 24 } // 1 day
}));

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect(process.env.MONGODB_URL);

const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    secret: String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser((user, cb) => {
    cb(null, user.id); // Store just the user ID in session
});

passport.deserializeUser(async (id, cb) => {
    try {
        const user = await User.findById(id);
        cb(null, user); // Retrieve the user object
    } catch (error) {
        cb(error);
    }
});

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: process.env.CALLBACK_URL,
    passReqToCallback: true
}, (request, accessToken, refreshToken, profile, done) => {
    User.findOrCreate({ googleId: profile.id }, (err, user) => {
        return done(err, user);
    });
}));

app.get("/", (req, res) => {
    res.render("home");
});

app.get("/auth/google", passport.authenticate("google", { scope: ["profile"] }));

app.get("/auth/google/secrets",
    passport.authenticate("google", {
        successRedirect: "/secrets",
        failureRedirect: "/login"
    })
);

app.get("/login", (req, res) => {
    res.render("login");
});

app.get("/register", (req, res) => {
    res.render("register");
});

app.get("/logout", (req, res) => {
    req.logout((err) => {
        if (err) {
            console.error(err);
            return res.status(500).send("Error logging out user.");
        }
        res.redirect("/");
    });
});

app.get("/secrets", async (req, res) => {
    try {
      const foundUsers = await User.find({ "secret": { $ne: null } });
      res.render("secrets", { usersWithSecrets: foundUsers || [] });
    } catch (err) {
      res.send('Error finding secrets');
    }
  });

app.get("/submit", (req, res) => {
    if (req.isAuthenticated()) {
        res.render("submit");
    } else {
        res.redirect("/login");
    }
});

app.post("/submit", async (req, res) => {
    try {
        const submittedSecret = req.body.secret;
        const foundUser = await User.findById(req.user.id);

        if (foundUser) {
            foundUser.secret = submittedSecret;

            const saveUser = await foundUser.save();
            if (saveUser) {
                return res.redirect("/secrets");
            }
        }
        res.status(400).send("Unable to save secret.");
    } catch (error) {
        console.error("Error submitting user secret:", error);
        res.status(500).send("Error submitting user secret.");
    }
});


app.post("/register", async (req, res) => {
    try {
        const registerUser = await User.register({ username: req.body.username }, req.body.password);
        req.logIn(registerUser, (err) => {
            if (err) {
                return res.status(500).send("Error logging in after registration.");
            }
            res.redirect("/secrets");
        });
    } catch (err) {
        console.error(err);
        res.status(500).send("Error registering user.");
    }
});

app.post("/login", (req, res, next) => {
    passport.authenticate("local", (err, user, info) => {
        if (err) {
            return next(err);
        }
        if (!user) {
            return res.status(401).send("Invalid email or password.");
        }
        
        req.logIn(user, (err) => {
            if (err) {
                return next(err);
            }
            return res.redirect("/secrets");
        });
    })(req, res, next);
});

app.listen(process.env.PORT, () => {
    console.log("Server is running on port 3000");
});
