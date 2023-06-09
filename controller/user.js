const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const emailJs = require("@emailjs/nodejs");

const User = require("../model/user");

async function sendEmail(templateParams, templateId) {
    const serviceId = "service_93kbnlyfhgh";
    const response = await emailJs.send(serviceId, templateId, templateParams, {
        publicKey: process.env.EMAILJS_PUBLIC_KEY,
        privateKey: process.env.EMAILJS_PRIVATE_KEY
    })
    return response;
}

function generateRandomNumber() {
    var minm = 100000;
    var maxm = 999999;
    return Number(Math.floor(Math
        .random() * (maxm - minm + 1)) + minm);
}

exports.createUser = async (req, res, next) => {
    let firstName = req.body.firstName;
    let lastName = req.body.lastName;
    let email = req.body.email;
    let unhashedPassword = req.body.password;
    const otp = generateRandomNumber()

    try {
        const pastUser = await User.findOne({ email });
        if (pastUser && pastUser.isActivated === true) {
            const error = new Error("User with this email already exists");
            error.status = 403
            throw error
        }

        let newUser;
        let hashedPassword = await bcrypt.hash(unhashedPassword, 10);
        if (pastUser) {
            await User.updateOne({ _id: pastUser._id }, {
                firstName,
                lastName,
                email,
                password: hashedPassword,
                otp
            })
        }
        else {
            newUser = new User({
                firstName,
                lastName,
                email,
                password: hashedPassword,
                otp
            })
            await newUser.save()
        }

        const response = await sendEmail({ name: firstName, email, otp }, "template_addvp4m")
        if (response.status !== 200) {
            const error = new Error(response.text)
            error.status = response.status
            throw error
        }


        res.status(201).json({
            message: "User created Successfully"
        })
    } catch (error) {
        next(error);
    }
}

exports.getUser = async (req, res, next) => {
    let email = req.body.email;
    let password = req.body.password
    try {
        let userData = await User.findOne({ email });
        if (!userData) {
            const error = new Error("No user found with this Email Address")
            error.status = 404;
            throw error;
        }

        let isCorrectPassword = await bcrypt.compare(password, userData.password);
        if (!isCorrectPassword) {
            const error = new Error("Wrong Password");
            error.status = 401;
            throw error
        }

        const token = jwt.sign(
            {
                userEmail: email,
                userId: userData._id
            },
            process.env.JWT_SECRET_KEY,
            { expiresIn: "1h" }
        )
        res.status(200).json({
            message: "Logged in Successfully",
            token
        })

    } catch (error) {
        next(error);
    }
}

exports.resendOtp = async (req, res, next) => {
    const email = req.body.email;
    const name = req.body.name;
    const otp = generateRandomNumber()

    try {
        const response = await sendEmail({ name, email, otp }, "template_addvp4m")
        if (response.status !== 200) {
            const error = new Error(response.text)
            error.status = response.status;
            throw error
        }

        await User.updateOne({ email }, { $set: { otp } })
        res.status(200).json({
            message: "OTP sent Successfully"
        })

    } catch (error) {
        next(error)
    }
}


exports.checkOtp = async (req, res, next) => {
    const email = req.body.email
    const otp = Number(req.body.otp)
    try {
        const userData = await User.findOne({ email });
        if (userData.otp !== otp) {
            const error = new Error("Wrong OTP");
            error.status = 400
            throw error
        }
        userData.otp = null;
        userData.isActivated = true;

        await User.findByIdAndUpdate({ _id: userData._id }, { ...userData });
        res.status(200).json({
            message: "Email Verified Successfully"
        })

    } catch (error) {
        next(error);
    }
}

exports.checkUserToken = (req, res, next) => {
    res.status(200).json({ message: "User Authenticated" });
}

exports.sendResetPasswordMail = async (req, res, next) => {
    let email = req.body.email;
    try {
        let userData = await User.findOne({ email });
        if (!userData) {
            const error = new Error("No user found with this Email Address")
            error.status = 404;
            throw error;
        }

        let resetID = generateRandomNumber()

        let resetLink = `http://localhost:5173/reset-password/${String(userData._id)}-${resetID}`
        userData.isResetPasswordEnabled = true;
        userData.resetId = resetID;
        await User.findOneAndUpdate({ email }, { ...userData })
        const response = await sendEmail({ email, resetLink, name: userData.firstName }, "template_qc3nqkf")
        if (response.status !== 200) {
            const error = new Error(response.text)
            error.status = response.status;
            throw error
        }
        res.status(200).json({ message: "reset link sent" })


    } catch (error) {
        next(error);
    }
}

exports.resetPassword = async (req, res, next) => {
    if (req.body.userId.includes("-")) {
        let _id = req.body.userId.split("-")[0];
        let password = req.body.password;

        try {
            const userData = await User.findOne({ _id })
            let hashedPassword = await bcrypt.hash(password, 10);
            userData.password = hashedPassword
            userData.isResetPasswordEnabled = false;
            userData.resetId = null;
            await User.findOneAndUpdate({ _id }, { ...userData })
            res.status(200).json({ message: "Password Changed Successfully" })

        } catch (error) {
            next(error);
        }
    }
}

exports.checkUrlValidity = async (req, res, next) => {
    if (req.body.userId.includes("-")) {
        let _id = req.body.userId.split("-")[0];
        let resetId = req.body.userId.split("-")[1];

        try {
            const userData = await User.findOne({ _id })
            if (!(userData.isResetPasswordEnabled) || userData.resetID === resetId) {
                const error = new Error("Link Expired")
                error.status = 498;
                throw error;
            }
            res.status(200).json({ message: "link hasn't expired" })

        } catch (error) {
            next(error);
        }
    }
}


