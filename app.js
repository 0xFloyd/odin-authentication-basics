/////// app.js

const dotenv = require('dotenv')
require('dotenv').config()
const express = require("express");
var Router = require('router')
const path = require("path");
const session = require("express-session");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const mongoose = require("mongoose");
const Schema = mongoose.Schema;
const bcrypt = require("bcryptjs");

const result = dotenv.config()

if (result.error) {
    throw result.error
}

const mongoDb = process.env.DB_HOST;
mongoose.connect(mongoDb, { useNewUrlParser: true });
const db = mongoose.connection;
db.on("error", console.error.bind(console, "mongo connection error"));

const User = mongoose.model(
    "User",
    new Schema({
        username: { type: String, required: true },
        password: { type: String, required: true }
    })
);
User.validPassword = function(password) {
    return bcrypt.compareSync(password, this.password);
};

// this is what passport.autheticate() uses to authenticate by communicating with database 
passport.use(new LocalStrategy(
    function (username, password, done) {
        User.findOne({ username: username }, function (err, user) {
            if (err) { return done(err); }
            if (!user) {
                return done(null, false, { message: 'Incorrect username.' });
            }
            bcrypt.compare(password, user.password, (err, res) => {
                if (res) {
                    // passwords match! log user in
                    return done(null, user)
                } else {
                    // passwords do not match!
                    return done(null, false, { msg: "Incorrect password" })
                }
            })
            return done(null, user);
        });
    }
));

// create cookie 
passport.serializeUser(function (user, done) {
    done(null, user.id);
});

passport.deserializeUser(function (id, done) {
    User.findById(id, function (err, user) {
        done(err, user);
    });
});

var router = Router()
const app = express();
app.set("views", __dirname);
app.set("view engine", "ejs");

app.use(session({ secret: "cats", resave: false, saveUninitialized: true }));
app.use(passport.initialize());
app.use(passport.session());
app.use(express.urlencoded({ extended: false }));


//cuistom middleware. this can be used in future applications, so instead of having to pass username in every view, you can just access this varaible 
router.use(function(req, res, next) {
  res.locals.currentUser = req.user;
  next();
});



app.get("/", (req, res) => {
    res.render("index", { user: req.user });
});

app.get("/sign-up", (req, res) => res.render("sign-up-form"));

app.post("/sign-up", (req, res, next) => {
    bcrypt.hash(req.body.password, 10, (err, hashedPassword) => {
        if (err) return next(err);
        const user = new User({
            username: req.body.username,
            password: hashedPassword
        }).save(err => {
            if (err) return next(err);
        res.redirect("/");
        });
    })
});

// passport autheticate does the functions coded above 
app.post(
    "/log-in",
    passport.authenticate("local", {
        successRedirect: "/",
        failureRedirect: "/"
    })
);

// logiut route. req.logout is part of the passport middleware 
app.get("/log-out", (req, res) => {
    req.logout();
    res.redirect("/");
});

app.listen(3000, () => console.log(`app listening on port 3000!`));
