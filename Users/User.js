const mongoose = require("mongoose");
const bcrypt = require('bcrypt');

const UserSchema = new mongoose.Schema({
    username: {
        type: String,
        required: true,
        unique: true,
    },
    password: {
        type: String,
        required: true
    }
})


UserSchema.pre('save', function(next) {
    bcrypt.hash(this.password, 15, (err, hash) => {
        if(err) {
            return next(err);
        } else {
            this.password = hash;
            return next()
        }
    })
})

UserSchema.methods.validatePassword = function(passwordGuess) {
    return bcrypt.compare(passwordGuess, this.password);
  };

module.exports = mongoose.model("User", UserSchema)