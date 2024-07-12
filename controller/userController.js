const bcrypt = require('bcrypt')
const userRegisterModel = require('../model/userRegisterModel')
const sendMail = require('../helper/mailer')
const { validationResult } = require('express-validator')
const randomString = require('randomstring')
const updatePassword_data = require('../model/updatePasswordModel')
const jwt = require('jsonwebtoken')

const userRegister = async (req, res) => {
    try {
        const errors = validationResult(req)
        if (!errors.isEmpty()) {
            return res.status(400).json({
                success: false,
                signUp_error_array_msg: errors.array()
            })
        }

        const { name, mobile_number, gmail_address, password } = req.body
        const bcrypt_pasword = await bcrypt.hash(password, 10)
        const fullUrl = req.protocol + '://' + req.get('host');
        const isExists = await userRegisterModel.findOne({ gmail_address })
        if (isExists) {
            return res.status(400).json({
                success: false,
                signUp_error_already_message: 'User Already Exists'
            })
        }

        const userData = {
            name,
            mobile_number,
            gmail_address,
            password: bcrypt_pasword
        }

        const user_data = new userRegisterModel(userData)
        const userModel_data = await user_data.save()

        const msg = `<p>Hello ${userModel_data.name} Welcome To Earning Planer, Click <a href="${fullUrl}/varify?id=${userModel_data._id}"> here </a> To Verify Your Email id</p>`
        sendMail(userModel_data.gmail_address, 'Verify Email', msg)

        res.status(200).json({
            success: true,
            signUp_success_msg: 'Register successfully!',
            user: userModel_data
        })
    } catch (error) {
        res.status(400).json({
            success: false,
            msg: error.message
        })
    }
}

const userVerify = async (req, res) => {
    try {
        const id = req.query.id
        user = await userRegisterModel.findOne({ _id: id })
        if (user) {
            if (user.is_verified === 1) {
                return res.render('404', { title: 'Already Verified', h1: 'User Already Verified' })
            }
            await userRegisterModel.findByIdAndUpdate({ _id: id }, { is_verified: 1 }, { new: true })
            return res.render('verification_success', { title: 'Verified Success', h1: 'Congratulations User Verified' })
        }
    } catch (error) {
        return res.render('404', { title: 'Invalid', h1: '😔 Sorry Invalid User' })
    }
}

const userVerify_link = async (req, res) => {
    try {
        const { gmail_address } = req.body
        const fullUrl = req.protocol + '://' + req.get('host');

        const isExists = await userRegisterModel.findOne({ gmail_address })
        if (!isExists) {
            return res.status(400).json({
                success: false,
                user_verify_link_gmail_notExist_msg: 'Gmail id not found Please Check'
            })
        }

        if (isExists.is_verified === 1) {
            return res.status(400).json({
                success: false,
                user_verify_link_gmailAlready_verified_msg: 'Gmail Already Verified'
            })
        }

        const msg = `<p>Hello ${isExists.name} Welcome To Earning Planer, Click <a href="${fullUrl}/varify?id=${isExists._id}"> here </a> To Verify Your Email id</p>`
        sendMail(isExists.gmail_address, 'Verify Email', msg)

        res.status(200).json({
            success: true,
            msg: 'Verification Link Sended Successfully! Please Check',
        })
    } catch (error) {

    }
}

const userCheckGmail_signUp_data = async (req, res) => {
    let { gmail } = req.body
    const data = await userRegisterModel.findOne({ gmail_address: gmail })
    res.json(data)
}

const userForgotPassword_dataBase_post = async (req, res) => {
    try {
        const { gmailID_state } = req.body
        const isExists = await userRegisterModel.findOne({ gmail_address: gmailID_state })
        const fullUrl = req.protocol + '://' + req.get('host');
        if (!isExists) {
            return res.status(400).json({
                success: false,
                forgotPassword_error_notExist_message: 'Sorry User not Found Please Check Your Email'
            })
        }
        let token = randomString.generate()
        let obj = {
            user_id: isExists._id,
            token
        }
        let insert = new updatePassword_data(obj)
        let data = await insert.save()

        const msg = `<p>Hello ${isExists.name} Welcome To Earning Planer, Click <a href="${fullUrl}/UpdatePassword/${data.token}"> here </a> To Reset Your Password</p>`
        sendMail(isExists.gmail_address, 'Reset/update Password', msg)

        return res.status(200).json({
            success: true,
            forgotPassword_success_msg: 'reset email sended successfully!',
            user: data
        })

    } catch (error) {
        return res.status(400).json({
            success: false,
            msg: error.message
        })
    }
}

const userUpdatePassword_Form_get = async (req, res) => {
    const id = req.params.id
    const isExists = await updatePassword_data.findOne({ token: id })
    if (!isExists) {
        return res.status(404).json({
            success: false,
            updatePassword: 'Sorry 404 Page not Found'
        })
    }
    return res.status(200).json({
        success: true,
        msg: 'Data matched'
    })

}

const userUpdatePassword_Form_post = async (req, res) => {
    try {
        const errors = validationResult(req)
        if (!errors.isEmpty()) {
            return res.status(400).json({
                success: false,
                msg: errors.array()[0].msg
            })
        }
        const id = req.params.id
        const isExists = await updatePassword_data.findOne({ token: id })
        const Obj_Id = isExists.user_id
        const password = req.body.password
        const bcrypted_password = await bcrypt.hash(password, 10)

        await userRegisterModel.findOneAndUpdate({ _id: Obj_Id }, { password: bcrypted_password }, { new: true })
        await updatePassword_data.deleteMany({ user_id: Obj_Id })

        return res.status(200).json({
            success: true,
            msg: 'Password Reseted SuccessFully!'
        })
    } catch (error) {
        return res.status(400).json({
            success: false,
            msg: 'Bad Request 400'
        })
    }
}

let jwt_accessToken = (user) => {
    return jwt.sign({ jwtUser: user }, process.env.JWT_ACCESS_KEY, { expiresIn: '0.5m' })
}

const userLogin = async (req, res) => {
    try {
        const errors = validationResult(req)
        if (!errors.isEmpty()) {
            return res.status(400).json({
                success: false,
                login_error_array_msg: errors.array()
            })
        }
        let { gmail_id, password } = req.body

        const isExists = await userRegisterModel.findOne({ gmail_address: gmail_id })
        if (!isExists) {
            return res.status(400).json({
                success: false,
                login_invalid_gmailPassword_message: 'Invalid Gmail or Password'
            })
        }

        let passwordMatched = await bcrypt.compare(password, isExists.password)

        if (!passwordMatched) {
            return res.status(400).json({
                success: false,
                login_invalid_password_message: 'Password not Matched'
            })
        }
        let jwt_token = jwt_accessToken(isExists)

        return res.status(200).json({
            success: true,
            jwtToken_msg: jwt_token
        })

    } catch (error) {
        return res.status(400).json({
            success: false,
            msg: error.message
        })
    }
}

const userHome_dataBase_get = async (req, res) => {
    try {
        userData = req.user
        return res.status(200).json({
            success: true,
            userData
        })
    } catch (error) {
        return res.status(404).json({
            success: false,
            msg: 'not found'
        })
    }
}

module.exports = {
    userRegister,
    userVerify,
    userVerify_link,
    userCheckGmail_signUp_data,
    userForgotPassword_dataBase_post,
    userUpdatePassword_Form_post,
    userUpdatePassword_Form_get,
    userLogin,
    userHome_dataBase_get
}