const { check } = require("express-validator");

const registerValidator = [
    check('mobile_number', 'Mobile number must be 10 digits').isLength({
        max: 10,
        min: 10
    }),
    check('gmail_address', 'Please enter valid gmail address').isEmail().normalizeEmail({
        gmail_lowercase: true,
        gmail_remove_dots: true,
    }),
    check('password', 'Password must contain min 8 character(min[1 number, 1 speciel character, 1 word]').isStrongPassword({
        minLength: 8,
        minUppercase: 1,
        minSymbols: 1,
        minNumbers: 1
    })
]

const passwordValidator = [
    check('password', 'Password must contain min 8 character(min[1 number, 1 speciel character, 1 word]').isStrongPassword({
        minLength: 8,
        minUppercase: 1,
        minSymbols: 1,
        minNumbers: 1
    })
]

const loginValidator = [
    check('gmail_id', 'Please enter valid gmail address').isEmail().normalizeEmail({
        gmail_lowercase: true,
        gmail_remove_dots: true,
    })
]

module.exports = {
    registerValidator,
    passwordValidator,
    loginValidator
}