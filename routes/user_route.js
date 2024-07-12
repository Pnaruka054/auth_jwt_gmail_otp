const express = require('express')
const route = express()
const userController = require('../controller/userController')
const validator = require('../helper/validator')
const middleware = require('../middlewares/middleware')

route.use('/home_dataBase_get', middleware.middleware_userLogin_check)
route.post('/register', validator.registerValidator, userController.userRegister)
route.post('/forgotPassword_dataBase_post', userController.userForgotPassword_dataBase_post)
route.post('/login', validator.loginValidator, userController.userLogin)
route.get('/home_dataBase_get', userController.userHome_dataBase_get)

module.exports = route