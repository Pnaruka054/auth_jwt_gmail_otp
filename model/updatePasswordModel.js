const mongoose = require('mongoose')

const updatePasswordSchema = new mongoose.Schema({
    user_id: { type: String, require: true },
    token: { type: String, require: true }
})

const updatePassword_data = mongoose.model('updatePassword', updatePasswordSchema)

module.exports = updatePassword_data