// Import package
var mongodb = require('mongodb');
var ObjectID = mongodb.ObjectID;
var crypto = require('crypto');
var express = require('express');
var bodyParser = require('body-parser');
var nodemailer = require('nodemailer');
var jwt = require('jsonwebtoken');
var ObjectId = require('mongodb').ObjectID;
var path = require('path');

require("dotenv").config();

const IP_ADRESS = '3.135.240.60'
//const IP_ADDRESS = '192.168.14.183'
const EMAIL_SECRET = 'asdf1093KMnzxcvnkljvasdu09123nlasdasdf';

const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.user,
        pass: process.env.pass,
    },
    tls: {
        rejectUnauthorized: false
    }
});

//PASSWORD UTILS
//CREATE FUNCTION TO RANDOM SALT
var getRandomString = function (length) {
    return crypto.randomBytes(Math.ceil(length / 2))
        .toString('hex') /* convert to hexa format */
        .slice(0, length);
};

var sha512 = function (password, salt) {
    var hash = crypto.createHmac('sha512', salt);
    hash.update(password);
    var value = hash.digest('hex');
    return {
        salt: salt,
        passwordHash: value
    };
};

function saltHashPassword(userPassword) {
    var salt = getRandomString(16); // create 16 random character
    var passwordData = sha512(userPassword, salt);
    return passwordData;
}

function checkHashPassword(userPassword, salt) {
    var passwordData = sha512(userPassword, salt);
    return passwordData;
}

function sendMail(email, subject, html) {
    console.log('Test 5');
    console.log('username: '+ process.env.user + 'password: ' + process.env.pass);
    transporter.sendMail({
        from: 'buddynsoulmonitor@gmail.com',
        to: email,
        subject: subject,
        html: html
    });
}

//Create Express Service
var app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({extended: true}));
app.use(express.static(__dirname + "/public"));

//Create MongoDB Client
var MongoClient = mongodb.MongoClient;

//Connection URL
var url = 'mongodb://localhost:27017' //27017 is default port

MongoClient.connect(url, {useNewUrlParser: true}, function (err, client) {
    if (err)
        console.log('Unable to connect to the mongoDB server.Error', err);
    else {

        //Register
        app.post('/register', (request, response, next) => {
            var post_data = request.body;

            var plaint_password = post_data.password;
            var hash_data = saltHashPassword(plaint_password);

            var password = hash_data.passwordHash; // Save password hash
            var salt = hash_data.salt;

            var name = post_data.name;
            var email = post_data.email;

            var registration_date = Date.now()

            var insertJson = {
                'email': email,
                'password': password,
                'salt': salt,
                'name': name,
                'registration_date': registration_date,
                'confirmed': false
            };
            var db = client.db('buddy&soulmonitor');

            console.log('Test');

            //Check exists email
            db.collection('user')
                .find({'email': email}).count(function (err, number) {
                if (number != 0) {
                    response.json('Email already exists');
                    console.log('Email already exists');
                } else {
                    console.log('Test2');
                    //Insert data
                    db.collection('user')
                        .insertOne(insertJson, function (error, res) {
                            if (error) {
                                response.status(400).json('Error occurs during registration');
                                console.log(error);
                            } else {
                                //send confirmation mail
                                // async email
                                console.log('Test3');
                                jwt.sign(
                                    {
                                        userId: res.insertedId,
                                        //userId: user._id,
                                        //email: email,
                                    },
                                    EMAIL_SECRET,
                                    {
                                        expiresIn: '1d',
                                    },
                                    (err, emailToken) => {
                                        if (err) {
                                            console.log(err);
                                            response.json(err);
                                        }
                                        else {
                                            console.log('Test4');
                                            //const url = `http://localhost:3000/confirmation/${emailToken}`;
                                            const url = `http://${IP_ADDRESS}:3000/confirmation/${emailToken}`;

                                            var subject = 'Confirm you registration to Buddy&Soul Monitor';
                                            var html = `Hi ${name},
                                                    <br>
                                                    Please click on the <a href="${url}">link</a> to confirm your email.
                                                    <br>
                                                    <br>
                                                    Buddy&Soul Monitor`;

                                            //sendMail(email, subject, html);

                                            console.log('Test6');

                                            response.status(200).json('Please check your email and follow the ' +
                                                'link to complete the registration');
                                            console.log('Confirmation mail have been sent');
                                        }
                                    },
                                );
                            }
                        })
                }
            })
        });

        //Login
        app.post('/login', async (request, response, next) => {
            var post_data = request.body;

            var email = post_data.email;
            var userPassword = post_data.password;

            var db = client.db('buddy&soulmonitor');

            //Check exists email
            db.collection('user')
                .find({'email': email}).count(function (err, number) {
                if (number == 0) {
                    response.status(404).json('Your account doesn\'t exist');
                    console.log('Your account doesn\'t exist');
                } else {
                    //Insert data
                    db.collection('user')
                        .findOne({'email': email}, function (err, user) {
                            if (user.confirmed == false) {
                                response.json('Please confirm your email');
                                console.log('Please confirm your email');
                            } else {
                                var salt = user.salt; // Get salt from user
                                var hashed_password = checkHashPassword(userPassword, salt).passwordHash; // Get password from user
                                var encrypted_password = user.password;

                                if (hashed_password == encrypted_password) {

                                    // async email
                                    jwt.sign(
                                        {
                                            //userId: user._id,
                                            email: email,
                                        },
                                        EMAIL_SECRET,
                                        (err, refreshToken) => {
                                            //response.json('Login success');
                                            response.json(refreshToken);
                                            console.log('Login success');
                                        },
                                    );

                                } else {
                                    response.status(401).json('Wrong password');
                                    console.log('Wrong password');
                                }
                            }
                        })
                }
            })
        });

        //Email confirmation
        app.get('/confirmation/:token', (request, response, next) => {

            try {
                const decoded = jwt.verify(request.params.token, EMAIL_SECRET);
                var userId = decoded.userId

                var db = client.db('buddy&soulmonitor');

                db.collection('user')
                    .findOne({'_id': ObjectId(userId)}, function (err, user) {
                        if (err) {
                            console.log(err);
                            response.json('Error in confirmation mail');
                        } else {
                            if (user.confirmed) {
                                console.log('Mail has been already confirmed');
                                response.json('Mail has been already confirmed');
                            } else {
                                db.collection('user')
                                    .updateOne({'_id': ObjectId(userId)}, //filter
                                        {$set: {'confirmed': true}}
                                    ).then(() => {
                                    db.collection('monitor')
                                        .insertOne({'email': user.email}, function (error, res) {
                                            if (err) {
                                                console.log(err)
                                                response.json("Error new user in monitor")
                                            }
                                        })
                                    console.log("Db updated");
                                })
                                    .catch((err) => {
                                        console.log(err);
                                    })

                                console.log('Mail confirmed');
                                response.json('Mail confirmed');
                            }

                        }
                    })


            } catch (e) {
                console.log(e);
                response.json('error');
            }

            //return res.redirect('http://localhost:3001/login');
        });

        //Send the Reset password (the user enters his mail and receives a reset link)
        app.post('/sendresetmail', (request, response, next) => {
            var post_data = request.body;

            var email = post_data.email;

            var db = client.db('buddy&soulmonitor');

            //Check exists email
            db.collection('user')
                .find({'email': email}).count(function (err, number) {
                if (number != 0) {

                    //check reset field (if true not send again)

                    //send reset password mail
                    db.collection('user').findOne({'email': email}, function (err, user) {
                        if (err) {
                            console.log(err)
                            response.json(err);
                        } else {
                            console.log('userId resetPassword: ' + user._id);
                            // async email
                            jwt.sign(
                                {
                                    userId: user._id,
                                    //email: email,
                                },
                                EMAIL_SECRET,
                                {
                                    expiresIn: '1d',
                                },
                                (err, emailToken) => {
                                    //const url = `http://localhost:3000/confirmation/${emailToken}`;
                                    //const url = `http://192.168.14.183:3000/confirmation/${emailToken}`;
                                    const url = `http://${IP_ADDRESS}:3000/enterpassword/${emailToken}`;

                                    var subject = 'Password Reset Buddy&Soul Monitor';
                                    var html = 'You are receiving this because you (or someone else) have requested' +
                                        ' the reset of the password for your account.\n\n' +
                                        ' Please click on the following link, or paste this' +
                                        ' into your browser to complete the process:\n\n' +
                                        url;

                                    var html = `Hi ${user.name}, 
                                                <br>
                                                Please click on the <a href="${url}">link</a> to reset your password.
                                                <br> 
                                                <br>
                                                Buddy&Soul Monitor`;

                                    sendMail(email, subject, html);

                                    response.json('Reset mail have been sent');
                                    console.log('Reset mail have been sent');
                                },
                            );
                        }
                    })
                }
                // var msg = 'If a matching account was found an email was sent to '
                //     + email + ' to allow you to reset your password.'
                // console.log(msg)
                // response.json(msg);
            })
        });

        //Redirect to Reset password page (the user click on the reset link and is been redirecting
        // to the reset html restet page)
        app.get('/enterpassword/:token', (request, response, next) => {

            try {
                const decoded = jwt.verify(request.params.token, EMAIL_SECRET);
                var userId = decoded.userId

                //response.sendFile('/resetPassword.html');
                response.sendFile(path.join(__dirname + '/resetPassword.html'));

            } catch (e) {
                console.log(e);
                response.json('error');
            }
        });

        //Change password (the user enters a new password and the password is updated in the db)
        app.post('/enterpassword/:token', (request, response, next) => {

            try {
                const decoded = jwt.verify(request.params.token, EMAIL_SECRET);
                var userId = decoded.userId

                var db = client.db('buddy&soulmonitor');

                db.collection('user')
                    .findOne({'_id': ObjectId(userId)}, function (err, user) {
                        if (err) {
                            console.log('An error occurred when resetting password');
                            response.json('An error occurred when resetting password');
                        } else {

                            var post_data = request.body;
                            var new_password = post_data.password;

                            var hash_data = saltHashPassword(new_password);

                            new_password = hash_data.passwordHash; // Save password hash
                            var salt = hash_data.salt;

                            db.collection('user')
                                .updateOne({'_id': ObjectId(userId)}, //filter
                                    {
                                        $set:
                                            {
                                                'password': new_password,
                                                'salt': salt
                                            }
                                    }).then(() => {
                                console.log("Password has been changed");
                                response.json({
                                    //status: 'success',
                                    message: 'Success! Your password has been changed.'
                                });
                            })
                                .catch((err) => {
                                    console.log(err);
                                    response.json('An error occurred during resetting password');
                                })
                        }
                    })


            } catch (e) {
                console.log(e);
                response.json('error');
            }
        });

        //Change password (the user enters a new password and the password is updated in the db)
        app.post('/senddata/:token', (request, response, next) => {

            try {
                const decoded = jwt.verify(request.params.token, EMAIL_SECRET);
                var email = decoded.email

                var post_data = request.body;
                var data = post_data.data;

                var db = client.db('buddy&soulmonitor');

                //db.collection('user')
                db.collection('monitor')
                    .findOne({'email': email}, function (err, user) {
                        if (err) {
                            console.log(err)
                        } else {
                            db.collection('monitor').updateOne(
                                {email: email},
                                {
                                    $push: {
                                        data: JSON.parse(data)
                                    }
                                }
                            ).then(() => {
                                console.log('Added in monitor dB');
                                response.json('Good');
                            })
                                .catch(() => {
                                    console.log("Error")
                                    response.json('Error');
                                })
                        }
                    })


            } catch (e) {
                console.log(e);
                response.json('error');
            }
        });


        //Start Web Server
        app.listen(3000, () => {
            console.log('Connected to MongoDB Server, WebService running on port 3000');
        })
    }
})