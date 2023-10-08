import mongoose from 'mongoose';

const messagesCollection = 'message';

const messageSchema = new mongoose.Schema({

    user:  {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'users'
    },

    message: {
        type: String,
        require: true,
    }

})

messageSchema.pre('find', function(){
    this.populate('user');
})

export const messageModel = mongoose.model(messagesCollection, messageSchema);