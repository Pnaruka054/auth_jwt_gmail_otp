require('dotenv').config()
const nodemailer = require('nodemailer')

const transpoter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: process.env.SMTP_PORT,
    secure: false,
    requireTLS: true,
    auth: {
        user: process.env.SMTP_EMAIL,
        pass: process.env.SMTP_PASSWORD
    }
})

const sendMail = async (to, subject, html) => {
    try {
        const mailOptions = {
            from: process.env.SMTP_EMAIL,
            to,
            subject,
            html
        }

        await transpoter.sendMail(mailOptions, (error, info) => {
            if (error) {
                return console.log(error)
            }
            console.log('Mail Send', info.messageId)
        })
    } catch (error) {
        console.log(error)
    }
}

module.exports = sendMail