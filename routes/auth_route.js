const express = require('express')
const route = express()
const userController = require('../controller/userController')
const validator = require('../helper/validator')

route.post('/varify_otp', validator.otpValidator, userController.userVerify_otp)
route.post('/verify_resend_otp', userController.userVerify_resend_otp)
route.post('/checkGmail_signUp_data', userController.userCheckGmail_signUp_data)
route.post('/updatePassword_Form/:id', validator.passwordValidator, userController.userUpdatePassword_Form_post)
route.get('/updatePassword_Form_get/:id', userController.userUpdatePassword_Form_get)

module.exports = route