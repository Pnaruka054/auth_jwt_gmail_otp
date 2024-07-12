const mongoose = require('mongoose')

const OTP_Schema = new mongoose.Schema({
    user_id: { type: String, require: true },
    gmail: { type: String, require: true },
    otp: { type: Number, require: true }
})

const otp_data = mongoose.model('otp_Data', OTP_Schema)

module.exports = otp_data