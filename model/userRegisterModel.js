const mongoose = require('mongoose')

const userSchema = new mongoose.Schema({
    name: { type: String, require: true },
    mobile_number: { type: Number, require: true },
    gmail_address: { type: String, require: true },
    password: { type: String, require: true },
    is_verified: { type: Number, default: 0 },
    balance: { type: Number, default: 0 }
})

const user_Register_data = mongoose.model('user', userSchema)

module.exports = user_Register_data