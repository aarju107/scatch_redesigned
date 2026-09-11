const userModel = require("../models/user-model");
const bcrypt = require("bcrypt");
const { generateToken } = require("../utils/generateToken");

module.exports.registerUser = async (req, res) => {
    try {
        let { fullname, email, password } = req.body;

        if (!fullname || !email || !password) {
            req.flash("error", "All fields are required");
            return res.redirect("/");
        }

        let user = await userModel.findOne({ email: email });
        if (user) {
            req.flash("error", "User already exists, please login");
            return res.redirect("/");
        }

        let salt = await bcrypt.genSalt(10);
        let hash = await bcrypt.hash(password, salt);

        let newUser = await userModel.create({
            fullname,
            email,
            password: hash,
        });

        let token = generateToken(newUser);
        res.cookie("token", token);
        res.redirect("/shop");
    } catch (error) {
        console.log("Register Error:", error);
        req.flash("error", "Something went wrong while creating your account");
        res.redirect("/");
    }
};

module.exports.loginUser = async function (req, res) {
    try {
        let { email, password } = req.body;

        let user = await userModel.findOne({ email: email });
        if (!user) {
            req.flash("error", "Email or Password is incorrect");
            return res.redirect("/");
        }

        let result = await bcrypt.compare(password, user.password);
        if (!result) {
            req.flash("error", "Email or Password is incorrect");
            return res.redirect("/");
        }

        let token = generateToken(user);
        res.cookie("token", token);
        res.redirect("/shop");
    } catch (error) {
        console.log("Login Error:", error);
        req.flash("error", "Something went wrong while logging in");
        res.redirect("/");
    }
};

module.exports.logoutUser = function (req, res) {
    res.cookie("token", "");
    res.redirect("/");
};
