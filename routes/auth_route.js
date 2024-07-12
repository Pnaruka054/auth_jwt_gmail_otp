const express = require('express')
const route = express()
const userController = require('../controller/userController')
const validator = require('../helper/validator')

route.get('/varify', userController.userVerify)
route.post('/verify_link', userController.userVerify_link)
route.post('/checkGmail_signUp_data', userController.userCheckGmail_signUp_data)
route.post('/updatePassword_Form/:id', validator.passwordValidator, userController.userUpdatePassword_Form_post)
route.get('/updatePassword_Form_get/:id', userController.userUpdatePassword_Form_get)

module.exports = route