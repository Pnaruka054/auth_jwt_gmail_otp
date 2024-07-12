const jwt = require('jsonwebtoken')

const middleware_userLogin_check = async (req, res, next) => {
    try {
        let jwtToken = req.query.jwtToken
        if (!jwtToken) {
            return res.status(400).json({
                success: false,
                msg: 'user not found'
            })
        }

        let jwtToken_result = jwt.verify(jwtToken, process.env.JWT_ACCESS_KEY).jwtUser
        req.user = jwtToken_result
        next()
    } catch (error) {
        return res.status(400).json({
            success: false,
            jwtToken_message: error.message
        })
    }
}

module.exports = {
    middleware_userLogin_check
}