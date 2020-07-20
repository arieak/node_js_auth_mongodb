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
const fs = require('fs');
require("dotenv").config();

const IP_ADDRESS = process.env.ip_address;
const EMAIL_SECRET = process.env.email_secret;

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

async function sendMail(email, subject, html, response) {
    let info = await transporter.sendMail({
        from: '"Buddy&Soul Monitor" <buddynsoulmonitor@gmail.com>',
        to: email,
        subject: subject,
        html: html
    });
    console.log(info);
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

            var email = post_data.email;
            var plaint_password = post_data.password;

            if (email === undefined || plaint_password === undefined) {
                console.log('Body parameter is null');
                response.status(400).json('Body parameter is null');
            }

            var hash_data = saltHashPassword(plaint_password);
            var name = post_data.name;
            var password = hash_data.passwordHash; // Save password hash
            var salt = hash_data.salt;
            var registration_date = Date.now()

            var insertJson = {
                'email': email,
                'password': password,
                'salt': salt,
                'name': name,
                'registration_date': registration_date,
                'reset_password': false,
                'confirmed': false,
                'admin': false
            };
            var db = client.db('buddy&soulmonitor');

            //Check exists email
            db.collection('user')
                .find({'email': email}).count(function (err, number) {
                if (number != 0) {
                    response.status(409).json('Email already exists');
                    console.log('Email already exists');
                } else {
                    //Insert data
                    db.collection('user')
                        .insertOne(insertJson, function (error, res) {
                            if (error) {
                                response.status(400).json('Error occurs during registration');
                                console.log(error);
                            } else {
                                //send confirmation mail
                                // async email
                                jwt.sign(
                                    {
                                        userId: res.insertedId,
                                        //userId: user._id,
                                        //email: email,
                                    },
                                    EMAIL_SECRET,
                                    {
                                        expiresIn: '2h',
                                    },
                                    async (err, emailToken) => {
                                        if (err) {
                                            console.log(err);
                                            response.json(err);
                                        } else {
                                            //const url = `http://localhost:3000/confirmation/${emailToken}`;
                                            const url = `http://${IP_ADDRESS}/confirmation/${emailToken}`;

                                            var subject = 'Confirm you registration to Buddy&Soul Monitor';
                                            var html = `Hi ${name},
                                                    <br>
                                                    <br>
                                                    Please click on the <a href="${url}">link</a> to confirm your registration.
                                                    <br>
                                                    The link will expire after 2 hours.
                                                    <br>
                                                    <br>
                                                    Buddy&Soul Monitor`;

                                            await sendMail(email, subject, html, response);

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
                                            var json_to_send = {
                                                'refreshToken': refreshToken,
                                                'name': user.name,
                                                'registration_date': user.registration_date,
                                                'admin': user.admin,
                                            }
                                            response.json(json_to_send);
                                            //response.json(refreshToken);
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
                                response.sendFile(path.join(__dirname + '/alreadyConfirmationMessage.html'));
                                //response.json('Mail has been already confirmed');
                            } else {
                                db.collection('user')
                                    .updateOne({'_id': ObjectId(userId)}, //filter
                                        {$set: {'confirmed': true}}
                                    ).then(() => {
                                    db.collection('monitor')
                                        .insertOne({'email': user.email}, async function (error, res) {
                                            if (err) {
                                                console.log(err)
                                                response.json("Error new user in monitor")
                                            }

                                            var subject = 'Welcome to Buddy&Soul Monitor';
                                            var html = `Hi ${user.name},
                                                    <br> <br> Your account has been activated.<br><br>
                                                    Buddy&Soul Monitor`;

                                            await sendMail(user.email, subject, html, response);
                                            //redirect to html page
                                            response.sendFile(path.join(__dirname + '/confirmationMessage.html'));
                                        })
                                    console.log("Db updated");
                                })
                                    .catch((err) => {
                                        console.log(err);
                                        response.json('Error');
                                    })

                                console.log('Mail confirmed');
                                //response.json('Mail confirmed');
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
                                    expiresIn: '2h',
                                },
                                async (err, emailToken) => {
                                    //const url = `http://localhost:3000/confirmation/${emailToken}`;
                                    //const url = `http://192.168.14.183:3000/confirmation/${emailToken}`;
                                    const url = `http://${IP_ADDRESS}/enterpassword/${emailToken}`;

                                    var subject = 'Password Reset Buddy&Soul Monitor';

                                    var html = `Hi ${user.name}, 
                                                <br>
                                                <br>
                                                Please click on the <a href="${url}">link</a> to reset your password.
                                                <br>
                                                The link will expire after 2 hours. 
                                                <br>
                                                <br>
                                                Buddy&Soul Monitor`;

                                    await sendMail(email, subject, html);

                                    db.collection('user')
                                        .updateOne({'_id': ObjectId(user._id)}, //filter
                                            {
                                                $set:
                                                    {'reset_password': true}
                                            }).then(() => {
                                        console.log("Password has been changed");
                                        response.json({
                                            status: 'success',
                                            message: 'Success! Your password has been changed.'
                                        });
                                    })
                                        .catch((err) => {
                                            console.log(err);
                                            response.json('An error occurred during resetting password');
                                        })
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

                var db = client.db('buddy&soulmonitor');

                // Check resetPassword value
                db.collection('user')
                    .findOne({'_id': ObjectID(userId)}, function (err, user) {
                        if (user.reset_password == false) {
                            response.sendFile(path.join(__dirname + '/alreadyResetPassword.html'));
                        } else {
                            response.sendFile(path.join(__dirname + '/resetPassword.html'));
                        }
                    })
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
                                                'salt': salt,
                                                'reset_password': false,
                                            }
                                    }).then(() => {
                                console.log("Password has been changed");
                                response.json({
                                    status: 'success',
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

        //Send data from the app to the server
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

        //Send list of all confirmed users
        app.post('/listusers/:token', (request, response, next) => {

            try {
                const decoded = jwt.verify(request.params.token, EMAIL_SECRET);
                var adminEmail = decoded.email

                var db = client.db('buddy&soulmonitor');

                //Check exists email
                db.collection('user')
                    .findOne({'email': adminEmail}, function (err, user) {
                            if (err) {
                                console.log('Error');
                                response.json("Error");
                            }
                            if (!user.admin) {
                                console.log('Not allowed');
                                response.json("Not allowed");
                            } else {
                                var post_data = request.body;
                                var status = post_data.status;

                                if(status == 'true') {
                                    status = true;
                                }
                                else {
                                    status = false;
                                }

                                db.collection('user')
                                    .find({'confirmed': status}, {})
                                    .collation({ locale: "en" })
                                    .sort({name: 1})
                                    .toArray(function (err, result) {
                                    var data = [];
                                    result.forEach(user => {
                                        var json_user = {
                                            'email': user.email,
                                            'name': user.name,
                                            'registration_date': user.registration_date,
                                            'admin': user.admin
                                        };
                                        data.push(json_user);
                                    });
                                    console.log('List of users have been send');
                                    response.json(data);
                                });
                            }
                        }
                    )

            } catch (e) {
                console.log(e);
                response.json('error');
            }

        });

        //Send data of specific user between two different dates
        app.post('/databetweentwodates/:token', (request, response, next) => {

            try {
                const decoded = jwt.verify(request.params.token, EMAIL_SECRET);
                var adminEmail = decoded.email

                var db = client.db('buddy&soulmonitor');

                //Check exists email
                db.collection('user')
                    .findOne({'email': adminEmail}, function (err, user) {
                        if (err) {
                            console.log('Error');
                            response.json("Error");
                        }
                        if (!user.admin) {
                            console.log('Not allowed');
                            response.json("Not allowed");
                        } else {
                            var post_data = request.body;
                            var email = post_data.email;
                            var start = post_data.start;
                            var end = post_data.end;

                            db.collection('monitor')
                                .find({'email': email}, {}).toArray(function (err, result) {
                                if (err) {
                                    console.log(err);
                                    response.json('error');
                                } else if (result.length === 0) {
                                    console.log("User's email doesn't exist");
                                    response.json("User's email doesn't exist")
                                } else {
                                    var data = [];
                                    //if (result[0].data === undefined) {
                                    if (typeof (result[0]["data"]) === "undefined") {
                                        console.log("Still no data");
                                        response.json('Still no data');
                                    } else {
                                        if (start == -1 && end == -1) {
                                            //data = adaptToJson(result[0].data);
                                            data = result[0].data;
                                            console.log('List of users have been send');
                                            response.json(data);
                                        }
                                            // } else if (start < result[0].data[0].timestamps) {
                                            //     console.log('No data between these dates');
                                            //     response.json("No data between these dates");
                                        // }
                                        else {
                                            (result[0].data).forEach(periodic_data => {
                                                if (periodic_data.timestamps >= start && periodic_data.timestamps <= end) {
                                                    data.push(periodic_data);
                                                }
                                            });
                                            if (data.length != 0) {
                                                console.log('Data of user have been send');
                                                response.json(data);
                                            } else {
                                                console.log('No data between these dates');
                                                response.json("No data between these dates");
                                            }
                                        }
                                    }
                                }
                            });
                        }
                    });


            } catch (e) {
                console.log(e);
                response.json('error');
            }

        });

        //Send all the user data
        app.post('/backupuserdata/:token', (request, response, next) => {

            try {
                const decoded = jwt.verify(request.params.token, EMAIL_SECRET);
                var email = decoded.email

                var db = client.db('buddy&soulmonitor');

                //Check exists email
                db.collection('user')
                    .findOne({'email': email}, function (err, user) {
                        if (err) {
                            console.log('Error');
                            response.json("Error");
                        }
                        else {
                            db.collection('monitor')
                                .find({'email': email}, {}).toArray(function (err, result) {
                                if (err) {
                                    console.log(err);
                                    response.json('error');
                                } else if (result.length === 0) {
                                    console.log("User's email doesn't exist");
                                    response.json("User's email doesn't exist")
                                } else {
                                    if (typeof (result[0]["data"]) === "undefined") {
                                        console.log("Still no data");
                                        response.json('Still no data');
                                    }
                                    else {
                                        var data = result[0].data;
                                        console.log('Back up of user have been send');
                                        response.json(data);
                                    }
                                }
                            });
                        }
                    });

            } catch (e) {
                console.log(e);
                response.json('error');
            }

        });

        //Change user to be an Admin
        app.post('/updatepermission/:token', (request, response, next) => {

            try {
                const decoded = jwt.verify(request.params.token, EMAIL_SECRET);
                var adminEmail = decoded.email

                var post_data = request.body;
                var newAdminEmail = post_data.email;
                var allow = post_data.allow

                // convert 'allow' variable to boolean type
                if(allow == 'true') {
                    allow = true;
                }
                else {
                    allow = false;
                }

                var db = client.db('buddy&soulmonitor');

                db.collection('user')
                    .findOne({'email': adminEmail}, function (err, user) {
                        if (err) {
                            console.log(err);
                            response.status(401).json('Error when finding admin mail in the db');
                        } else {
                            if (!user.admin) {
                                console.log('Not allowed');
                                response.status(401).json("Not allowed");
                            } else {
                                db.collection('user')
                                    .updateOne({'email': newAdminEmail}, //filter
                                        {$set: {'admin': allow}}
                                    ).then(() => {
                                    console.log("User's permission have been updated");
                                    response.json("User's permission have been updated");
                                })
                                    .catch((err) => {
                                        console.log("Error when updating users's permission");
                                        response.json("Error when updating user's permission");
                                    })
                            }
                        }
                    })

            } catch (e) {
                console.log(e);
                response.json('error');
            }
        });

        //Delete user from admin board
        app.post('/deleteuser/:token', (request, response, next) => {

            try {
                const decoded = jwt.verify(request.params.token, EMAIL_SECRET);
                var adminEmail = decoded.email

                var post_data = request.body;
                var userToRemove = post_data.email;

                var db = client.db('buddy&soulmonitor');

                db.collection('user')
                    .findOne({'email': adminEmail}, function (err, userToCheck) {
                        if (err) {
                            console.log(err);
                            response.json('Error when finding admin mail in the db');
                        } else {
                            if (!userToCheck.admin) {
                                console.log('Not allowed');
                                response.json("Not allowed");
                            }
                            else {
                                // get user status
                                db.collection('user')
                                    .findOne({'email': userToRemove}, function (err, user) {
                                        var userStatus = user.confirmed;

                                        // delete the user from the 'user' collection
                                        db.collection('user')
                                            .deleteOne({'email': userToRemove}, function (err, res) {
                                                if (err) {
                                                    console.log("Failed to remove user");
                                                    response.json("Failed to remove user");
                                                } else {
                                                    if (res.deletedCount === 0) {
                                                        console.log("User email not found");
                                                        response.json("User email not found");
                                                    }
                                                }
                                            })

                                        if (userStatus) {
                                            // delete the user from the 'monitor' collection
                                            db.collection('monitor')
                                                .deleteOne({'email': userToRemove}, function (err, res) {
                                                    if (err) {
                                                        console.log("Failed to remove user");
                                                        response.json("Failed to remove user");
                                                    }
                                                    else {
                                                        if (res.deletedCount === 0) {
                                                            console.log("User email not found");
                                                            response.json("User email not found");
                                                        }
                                                    }
                                                })
                                        }

                                    });

                                console.log("User has been removed");
                                response.json("User has been removed");
                            }
                        }
                    })

            } catch (e) {
                console.log(e);
                response.json('error');
            }
        });

        //User delete his account
        app.get('/deleteaccount/:token', (request, response, next) => {

            try {
                const decoded = jwt.verify(request.params.token, EMAIL_SECRET);
                var userEmail = decoded.email

                var db = client.db('buddy&soulmonitor');

                db.collection('user')
                    .findOne({'email': userEmail}, function (err, user) {
                        if (err) {
                            console.log(err);
                            response.json('Error when finding user mail in the db');
                        }
                        else {
                            var userStatus = user.confirmed;

                            // delete the user from the 'user' collection
                            db.collection('user')
                                .deleteOne({'email': userEmail}, function (err, res) {
                                    if (err) {
                                        console.log("Failed to remove user");
                                        response.json("Failed to remove user");
                                    } else {
                                        if (res.deletedCount === 0) {
                                            console.log("User email not found");
                                            response.json("User email not found");
                                        }
                                    }
                                })

                            if (userStatus) {
                                // delete the user from the 'monitor' collection
                                db.collection('monitor')
                                    .deleteOne({'email': userEmail}, function (err, res) {
                                        if (err) {
                                            console.log("Failed to remove user");
                                            response.json("Failed to remove user");
                                        }
                                        else {
                                            if (res.deletedCount === 0) {
                                                console.log("User email not found");
                                                response.json("User email not found");
                                            }
                                        }
                                    })
                            }
                            console.log("User has been removed");
                            response.json("User has been removed");
                        }
                    });
            } catch (e) {
                console.log(e);
                response.json('error');
            }
        });

        //Update user email
        app.post('/sendverificationcode/:token', (request, response, next) => {

            try {
                const decoded = jwt.verify(request.params.token, EMAIL_SECRET);
                var userEmail = decoded.email

                var post_data = request.body;
                var newEmail = post_data.newEmail;

                var db = client.db('buddy&soulmonitor');

                // first we check if the new email is available
                db.collection('user')
                    .find({'email': newEmail}).count(function (err, number) {
                    if (number != 0) {
                        response.status(409).json('Email already exists');
                        console.log('Email already exists');
                    } else {
                        db.collection('user')
                            .findOne({'email': userEmail}, function (err, user) {
                                if (err) {
                                    console.log(err);
                                    response.json('Error when finding user mail in the db');
                                } else {
                                    var userName = user.name;
                                    var verificationCode = getRandomString(4); // create 4 random character

                                    db.collection('user')
                                        .updateOne({'email': userEmail}, //filter
                                            {
                                                $set: {
                                                    'verification_code': verificationCode,
                                                    'new_email': newEmail
                                                }
                                            }
                                        ).then(async () => {
                                        var subject = 'Verification code';
                                        var html = `Hi ${userName},
                                                    <br>
                                                    <br>
                                                    Your verification code is: ${verificationCode}
                                                    <br>
                                                    <br>
                                                    Buddy&Soul Monitor`;

                                        await sendMail(newEmail, subject, html);

                                        response.status(200).json('Verification code have been sent');
                                        console.log('Verification code have been sent');
                                    });
                                }
                            });
                    }
                });
            } catch (e) {
                console.log(e);
                response.json('error');
            }
        });

        //Update user email
        app.post('/updateemail/:token', (request, response, next) => {

            try {
                const decoded = jwt.verify(request.params.token, EMAIL_SECRET);
                var userEmail = decoded.email

                var post_data = request.body;
                var verificationCode = post_data.verificationCode;

                var db = client.db('buddy&soulmonitor');

                db.collection('user')
                    .findOne({'email': userEmail}, function (err, user) {
                        if (err) {
                            console.log(err);
                            response.json('Error when finding user mail in the db');
                        }
                        else {
                            if (user.verification_code === undefined || user.new_email === undefined) {
                                console.log('Field does not exist');
                                response.status(400).json('Field does not exist');
                            }
                            else {
                                if(user.verification_code === verificationCode) {
                                    // update user email and unset new fields, also send the new refresh token

                                    var newEmail = user.new_email;

                                    db.collection('user')
                                        .updateOne({'email': userEmail}, //filter
                                            {
                                                $set: {'email': newEmail},
                                                $unset: {'verification_code': 1,
                                                    'new_email': 1}
                                            }
                                        ).then(async () => {
                                        var subject = 'Email update';
                                        var html = `Hi ${user.name},
                                                    <br>
                                                    <br>
                                                    Your email have been updated successfully.
                                                    <br>
                                                    <br>
                                                    Buddy&Soul Monitor`;

                                        await sendMail(newEmail, subject, html);

                                        jwt.sign(
                                            {
                                                email: newEmail,
                                            },
                                            EMAIL_SECRET,
                                            (err, refreshToken) => {
                                                var refreshTokenToSend = {
                                                    'refreshToken': refreshToken,
                                                }
                                                response.status(200).json(refreshTokenToSend);
                                                console.log('Email have been updated');
                                            },
                                        );
                                    });
                                }
                                else {
                                    // verification code is wrong
                                    db.collection('user')
                                        .updateOne({'email': userEmail}, //filter
                                            {
                                                $unset: {'verification_code': 1,
                                                    'new_email': 1}
                                            }
                                        ).then(() => {
                                        response.status(400).json('Confirmation code is not correct');
                                        console.log('Confirmation code is not correct');
                                    });
                                }
                            }
                        }
                    });
            } catch (e) {
                console.log(e);
                response.json('error');
            }
        });

        //Contact us message request
        app.post('/contactus/:token', (request, response, next) => {

            try {
                const decoded = jwt.verify(request.params.token, EMAIL_SECRET);
                var email = decoded.email

                var post_data = request.body;
                var message = post_data.message;

                message = JSON.parse(message);
                var timestamps = message.timestamps;
                var userEmail = message.email;
                var userSubject = message.subject;
                var message_body = message.message;

                var db = client.db('buddy&soulmonitor');

                db.collection('user')
                    .find({'confirmed': true}, {}).toArray(function (err, result) {
                    if (result.length > 0) {
                        var mailList = [];
                        result.forEach(user => {
                            mailList.push(user.email);
                        });

                        var subject = 'Contact us notification';

                        var html = `Hi admin, 
                                                <br>
                                                <br>
                                                You received a new message from an user.
                                                <br>
                                                <br>
                                                Date: ${timestamps} <br>
                                                User: ${userEmail} <br>
                                                Subject: ${userSubject} <br>
                                                Message: ${message_body}
                                                <br>
                                                <br>
                                                Buddy&Soul Monitor`;

                        sendMail(mailList, subject, html);

                        response.json('Contact us message have been sent');
                        console.log('Contact us message have been sent');
                    }
                });


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