require('dotenv').config()
const express = require('express')
const app = express()
const mongoose = require('mongoose')
const userRouter = require('./routes/user_route')
const authRouter = require('./routes/auth_route')
const cors = require('cors')
const PORT = process.env.PORT

app.use(express.json())
app.use(cors())
app.use(express.static(path.resolve(__dirname, 'public')));
app.get('/', (req, res) => {
    res.sendFile(path.resolve(__dirname, 'public', 'index.html'))
});
app.get('/Verify', (req, res) => {
    res.sendFile(path.resolve(__dirname, 'public', 'index.html'))
});
app.get('/signUp', (req, res) => {
    res.sendFile(path.resolve(__dirname, 'public', 'index.html'))
});
app.get('/forgot-password', (req, res) => {
    res.sendFile(path.resolve(__dirname, 'public', 'index.html'))
});
app.get('/Home', (req, res) => {
    res.sendFile(path.resolve(__dirname, 'public', 'index.html'))
});
app.get('/UpdatePassword/:id', (req, res) => {
    res.sendFile(path.resolve(__dirname, 'public', 'index.html'))
});

async function modelCalled() {
    await mongoose.connect(process.env.DATABASE_URL)
    console.log('database connected successfully')
}

modelCalled()

app.use('/api', userRouter)
app.use('/', authRouter)

app.set('view engine', 'ejs')
app.set('views', './views')

app.listen(PORT, () => {
    console.log('server started on port -' + PORT)
})