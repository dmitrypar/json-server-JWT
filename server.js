const express = require('express')
const fs = require('fs')
const bodyParser = require('body-parser')
const jsonServer = require('json-server')
const jwt = require('jsonwebtoken')


const server = jsonServer.create()
const router = jsonServer.router('./database.json')
const userdb = JSON.parse(fs.readFileSync('./users.json', 'UTF-8'))

server.use(bodyParser.urlencoded({extended: true}))
server.use(bodyParser.json())
server.use(jsonServer.defaults());
server.use('/static', express.static('public'))

const SECRET_KEY = '123456789'

const expiresIn = '11111h'

// Create a token from a payload
function createToken(payload){
    return jwt.sign(payload, SECRET_KEY, {expiresIn})
}

// Verify the token
function verifyToken(token){
    return  jwt.verify(token, SECRET_KEY, (err, decode) => decode !== undefined ?  decode : err)
}

// Check if the user exists in database
function isAuthenticated({email, password}){
    return userdb.users.findIndex(user => user.email === email && user.password === password) !== -1
}

// Register New User
server.post('/auth/register', (req, res) => {
    console.log("register endpoint called; request body:");
    console.log(req.body);
    const {email, password} = req.body;

    if(isAuthenticated({email, password}) === true  ) {
        const status = 401;
        const message = 'Email and Password already exist';
        res.status(status).json({status, message});
        return
    } else if ((email||password) === '') {
        const status = 401;
        const message = 'Please write some letter into each field';
        res.status(status).json({status, message});
        console.log('Please write some letter into each field')
        return
    }

    fs.readFile("./users.json", (err, data) => {
        if (err) {
            const status = 401
            const message = err
            res.status(status).json({status, message})
            return
        };

        // Get current users data
        var data = JSON.parse(data.toString());

        // Get the id of last user
        var last_item_id = data.users[data.users.length-1].id;

        //Add new user
        data.users.push({id: last_item_id + 1, email: email, password: password}); //add some data
        var writeData = fs.writeFile("./users.json", JSON.stringify(data), (err, result) => {  // WRITE
            if (err) {
                const status = 401
                const message = err
                res.status(status).json({status, message})
                return
            }
        });
    });


// Create token for new user
    const access_token = createToken({email, password})
    function isAuthenticatedId({email})
    {return userdb.users.findIndex(user => user.email === email) + 1};
    const authenticatedId = isAuthenticatedId({email})
    console.log("Access Token:", access_token);
    res.status(200).json({access_token, email})
    console.log("id ", authenticatedId);
    console.log("email:", email);
})





// Get last User
server.get(
    '/auth/user', (req, res) => {
    console.log("register endpoint called; request body:");
    console.log(req.body);
    const {email, password} = req.body;

    if(isAuthenticated({email, password}) === '') {
        const status = 401;
        const message = 'Email or Password should be more that one symbol';
        res.status(status).json({status, message});
        return
    }

    fs.readFile("./users.json", (err, data) => {
        if (err) {
            const status = 401
            const message = err
            res.status(status).json({status, message})
            return
        };

        // Get current users data
        var data = JSON.parse(data.toString());

        // Get the id of last user
        var last_item_id = data.users[data.users.length-1].id

        // Get data of last user
        var last_user_data = data.users[data.users.length-1]

        res.status(200).json({last_user_data})
        console.log("last_user_data:", last_user_data);
    });


});





// Login to one of the users from ./users.json
server.post('/auth/login', (req, res) => {
    console.log("login endpoint called; request body:");
    console.log(req.body);
    const {email, password} = req.body;
    if (isAuthenticated({email, password}) === false) {
        const status = 401
        const message = 'Incorrect email or password'
        res.status(status).json({status, message})
        return
    }
    const access_token = createToken({email, password})

    // Find  userId exists in database if email pass
    function isAuthenticatedId({email})
    {return userdb.users.findIndex(user => user.email === email) + 1};
    const authenticatedId = isAuthenticatedId({email})
    console.log("id :", authenticatedId);

    console.log("Access Token:", access_token);
    console.log("email:", email);
    res.status(200).json({access_token, email, authenticatedId})




});



server.use(/^(?!\/auth).*$/,  (req, res, next) => {
    if (req.headers.authorization === undefined || req.headers.authorization.split(' ')[0] !== 'Bearer') {
        const status = 401
        const reqheaders = req.headers.authorization
        const message = 'Error in authorization format'
        res.status(status).json({status, message, reqheaders})
        console.log(status, message, req.headers.authorization)
        return
    }
    try {
        let verifyTokenResult;
        verifyTokenResult = verifyToken(req.headers.authorization.split(' ')[1]);

        if (verifyTokenResult instanceof Error) {
            const status = 401
            const message = 'Access token not provided'
            res.status(status).json({status, message})
            return
        }
        next()
    } catch (err) {
        const status = 401
        const message = 'Error access_token is revoked'
        res.status(status).json({status, message})
    }
});



server.use(router)

server.listen(3000, () => {
    console.log('Run Auth API Server')
})