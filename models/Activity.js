import mongoose from 'mongoose';

const ActivitySchema = new mongoose.Schema({
    user_id: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    timestamp: {
        type: Date,
        default: Date.now,
        required: true
    },
    action: {
        type: String,
        required: true,
        enum: ['login', 'upload', 'download', 'delete', 'report_issue'] // Define possible actions
    },
    description: {
        type: String,
        required: true
    },
    file_name: String, // Optional, for file-related activities
    file_size: Number, // Optional, for upload/delete
    // Add other relevant fields for specific activities if needed
});

const Activity = mongoose.model('Activity', ActivitySchema);
export default Activity;