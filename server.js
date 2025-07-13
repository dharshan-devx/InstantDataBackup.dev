// server.js
import { fileURLToPath } from 'url';
import { dirname } from 'path';
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
import 'dotenv/config'; // This should always be at the very top to load .env variables
import express from 'express';
import connectDB from './config/db.js';
import User from './models/User.js'; // Ensure this path is correct
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import auth from './middleware/auth.js'; // NOTE: Commented out. We will use the custom authMiddleware defined below for consistency with new features.
import multer from 'multer';
import path from 'path';
import fsp from 'fs/promises'; // For promise-based file system operations
import fs from 'fs';          // For synchronous file system operations (e.g., existsSync)
import crypto from 'crypto';  // For cryptographic operations like generating tokens
import archiver from 'archiver';
import { Block, Blockchain } from './lib/blockchain.js'; // Ensure this is only imported once at the top
import BlockchainState from './models/BlockchainState.js'; // Import your BlockchainState model
import cors from 'cors';
import helmet from 'helmet';
import { check, validationResult } from 'express-validator';
import rateLimit from 'express-rate-limit';
import mime from 'mime-types'; // <--- ADDED THIS IMPORT for MIME type detection
import { v4 as uuidv4 } from 'uuid'; // For unique serial numbers
import Activity from './models/Activity.js'; // Adjust path as needed, add .js extension
import Issue from './models/Issue.js';     // Adjust path as needed, add .js extension
import sendEmail from './utils/emailSender.js'; // <--- ADDED THIS IMPORT

const app = express();
const port = 3000;
import File from './models/File.js';
// import { decrypt } from './utils/encryptionUtil.js';
// const fs = require('fs');
// const fsp = fs.promises; // Use fs.promises for async file operations
// const path = require('path');
// const crypto = require('crypto');
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY;
if (!ENCRYPTION_KEY) {
    console.error("CRITICAL ERROR: ENCRYPTION_KEY is not set in environment variables. Please set it in your .env file or server environment.");
    process.exit(1);
}
const IV_LENGTH = 16;

// --- JWT Configuration ---
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
    console.error("CRITICAL ERROR: JWT_SECRET is not set in environment variables. Please set it in your .env file or server environment.");
    process.exit(1);
}

// Declare instantDataBackupChain globally so it can be accessed by routes
let instantDataBackupChain;

// --- Initialize and Load Blockchain from Database ---
async function initializeBlockchain() {
    try {
        let blockchainState = await BlockchainState.findOne({});

        if (!blockchainState) {
            instantDataBackupChain = new Blockchain();
            blockchainState = new BlockchainState({
                chain: instantDataBackupChain.chain.map(block => ({
                    index: block.index,
                    timestamp: block.timestamp,
                    data: block.data,
                    previousHash: block.previousHash,
                    hasher: block.hasher,
                    nonce: block.nonce
                })),
                difficulty: instantDataBackupChain.difficulty
            });
            await blockchainState.save();
            console.log("No existing blockchain found in DB. Created new Genesis Block and saved to DB.");
        } else {
            instantDataBackupChain = new Blockchain(blockchainState.chain, blockchainState.difficulty);
            console.log(`Blockchain loaded with ${instantDataBackupChain.chain.length} blocks from DB.`);
        }

        if (!instantDataBackupChain.isChainValid()) {
            console.error("Warning: Loaded blockchain is not valid! Potential data corruption or tampering detected.");
            // OPTIONAL: Implement recovery or alert mechanism here
        }

    } catch (error) {
        console.error("Critical Error: Failed to initialize or load blockchain from database:", error);
        process.exit(1);
    }
}

// --- Connect to MongoDB ---
connectDB();

// --- Middleware ---
app.use(express.json());

// --- Strict CORS Configuration ---
app.use(cors({
    origin: 'https://3000-firebase-instant-data-backup-1748249505922.cluster-nzwlpk54dvagsxetkvxzbvslyi.cloudworkstations.dev',
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    credentials: true
}));

// --- Security Headers with Helmet ---
app.use(helmet());

// --- Rate Limiting Configuration ---
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    message: { message: 'Too many authentication attempts from this IP, please try again after 15 minutes' },
    standardHeaders: true,
    legacyHeaders: false,
});

const apiLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    max: 500,
    message: { message: 'Too many requests from this IP, please try again after an hour.' },
    standardHeaders: true,
    legacyHeaders: false,
});
// --- End Rate Limiting Configuration ---

// --- Multer Configuration for File Uploads ---
const storage = multer.diskStorage({
    destination: function(req, file, cb) {
        fs.mkdirSync('uploads/', { recursive: true });
        cb(null, 'uploads/');
    },
    filename: function(req, file, cb) {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
    }
});

const upload = multer({
    storage: storage,
    limits: { fileSize: 100000000 }, // 100 MB limit
    fileFilter: function(req, file, cb) {
        checkFileType(file, cb);
    }
});

function checkFileType(file, cb) {
    const allowedMimeTypes = /jpeg|jpg|png|gif|pdf|doc|docx|txt|zip|rar|mp4|mov|avi|mp3|wav|json|xml|csv/;
    const extname = allowedMimeTypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = allowedMimeTypes.test(file.mimetype) || file.mimetype.startsWith('text/') || file.mimetype.startsWith('application/');

    if (mimetype && extname) {
        return cb(null, true);
    } else {
        cb('Error: Files of this type are not supported! Allowed: images, pdf, documents, text, archives, common video/audio.');
    }
}
// --- End Multer Configuration ---

// --- Encryption/Decryption Helper Functions ---
function encrypt(buffer) {
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY, 'hex'), iv);
    let encrypted = cipher.update(buffer);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return iv.toString('hex') + ':' + encrypted.toString('hex');
}

function decrypt(encryptedText) {
    const textParts = encryptedText.split(':');
    const iv = Buffer.from(textParts.shift(), 'hex');
    const encryptedData = Buffer.from(textParts.join(':'), 'hex');
    const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY, 'hex'), iv);
    let decrypted = decipher.update(encryptedData);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted;
}
// --- End Encryption/Decryption Helper Functions ---

// --- Custom Authentication Middleware ---
// This middleware is designed to extract userId, username, and serialNumber from the JWT
// It's recommended to move this to `./middleware/auth.js` for better organization.
const authMiddleware = (req, res, next) => {
    // Get token from header
    const authHeader = req.header('Authorization'); // Changed from 'x-auth-token'

    // Check if not token or not in Bearer format
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        console.log("DEBUG AUTH: No Bearer token found in Authorization header.");
        return res.status(401).json({ message: 'No token, authorization denied' });
    }

    const token = authHeader.split(' ')[1]; // Extract the token part

    try {
        // Verify token
        // Ensure JWT_SECRET is accessible here, e.g., via process.env.JWT_SECRET
        const decoded = jwt.verify(token, process.env.JWT_SECRET); 
        
        console.log("DEBUG AUTH: Token decoded successfully.");
        console.log("DEBUG AUTH: Decoded payload:", decoded); // Log the entire decoded payload
        
        // Ensure that decoded.user contains the necessary properties
        if (!decoded.user) {
            console.error("DEBUG AUTH ERROR: Decoded token missing 'user' property.");
            return res.status(401).json({ message: 'Token invalid: User data missing.' });
        }
        
        req.user = decoded.user; // This is where req.user is populated
        
        console.log("DEBUG AUTH: req.user populated:", req.user); // Log req.user after population
        
        next(); // Proceed to the next middleware/route handler
    } catch (err) {
        console.error("DEBUG AUTH ERROR: Token verification failed:", err.message);
        res.status(401).json({ message: 'Token is not valid' });
    }
};

// --- End Custom Authentication Middleware ---


// Serve static files from the 'frontend' directory
app.use(express.static(path.join(__dirname, 'frontend')));

// --- API Routes ---

// --- Consolidated User Registration Endpoint (/api/register) ---
// This route now includes username, serial_number, total_storage_used, last_login logic.
app.post(
    '/api/register',
    authLimiter, // Apply rate limiting to registration attempts
    [
        check('username', 'Username is required').not().isEmpty(),
        check('email', 'Please include a valid email').isEmail(),
        check('password', 'Password must be 6 or more characters').isLength({ min: 6 }),
    ],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ message: errors.array()[0].msg });
        }

        const { username, email, password } = req.body;

        try {
            console.log('Register - received email:', email); // Debug log
            console.log('Register - received username:', username); // Debug log

            let user = await User.findOne({ email });
            if (user) {
                return res.status(400).json({ message: 'User already exists' });
            }

            const serialNumber = uuidv4(); // Generate a unique serial number

            // Password hashing is handled by the pre-save hook in your User model
            user = new User({
                username,
                email,
                password: password, // The pre-save hook will hash this
                serial_number: serialNumber,
                total_storage_used: 0,
                last_login: new Date()
            });

            await user.save(); // This will trigger the pre('save') hook in User.js to hash the password
            console.log('Register - User saved successfully to DB.');

            const payload = {
                user: {
                    id: user.id, // MongoDB _id
                    userId: user._id, // Alias for consistency with some frontend usage if needed
                    username: user.username,
                    serialNumber: user.serial_number,
                },
            };

            jwt.sign(
                payload,
                JWT_SECRET,
                { expiresIn: '1h' },
                (err, token) => {
                    if (err) {
                        console.error('JWT Sign Error:', err);
                        throw err;
                    }
                    res.status(201).json({ message: 'User registered successfully', token, username: user.username });
                }
            );
        } catch (err) {
            console.error('Registration Error:', err.message);
            res.status(500).send('Server error during registration');
        }
    }
);

// --- Consolidated User Login Endpoint (/api/login) ---
// This route now includes last_login update and activity logging.
app.post(
    '/api/login',
    authLimiter, // Apply rate limiting to login attempts
    [
        // Allow either email or username to be present for validation
        // We'll check if at least one is provided in the route handler itself.
        // It's generally good practice to have some validation for username if it's required.
        // For simplicity, we'll keep the direct check in the route for now.
        check('password', 'Password is required').exists(),
    ],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ message: errors.array()[0].msg });
        }

        // Destructure both username and email from req.body
        const { username, email, password } = req.body; // MODIFICATION: Added 'username' here

        try {
            console.log('Login - received username:', username, 'email:', email); // MODIFICATION: Log both

            let user;
            // Determine how to find the user: by email or by username
            if (email && email.length > 0) { // Check if email is provided and not empty
                user = await User.findOne({ email });
                console.log('Login - Attempting to find user by email:', email);
            } else if (username && username.length > 0) { // Check if username is provided and not empty
                user = await User.findOne({ username });
                console.log('Login - Attempting to find user by username:', username);
            } else {
                // If neither email nor username is provided
                return res.status(400).json({ message: 'Please enter your email or username.' });
            }

            if (!user) {
                console.log('Login - User not found for provided credentials.');
                return res.status(400).json({ message: 'Invalid credentials' });
            }

            const isMatch = await bcrypt.compare(password, user.password);
            console.log('Login - bcrypt.compare result (true/false):', isMatch);
            if (!isMatch) {
                return res.status(400).json({ message: 'Invalid credentials' });
            }

            // Update last_login on successful login
            user.last_login = new Date();
            await user.save();

            // Log the login activity
            const loginActivity = new Activity({
                user_id: user._id,
                timestamp: new Date(),
                action: 'login',
                // Use user.username for description, fallback to user.email if username is null/undefined
                description: `User ${user.username || user.email} logged in.`,
            });
            await loginActivity.save();

            const payload = {
                user: {
                    id: user.id, // MongoDB _id (string representation)
                    userId: user._id, // MongoDB _id (ObjectId type, or string if Mongoose getter is used)
                    username: user.username,
                    email: user.email,
                    encryptionKey: user.encryptionKey // Attach user's specific encryption key to payload
                },
            };

            jwt.sign(
                payload,
                JWT_SECRET, // Ensure JWT_SECRET is correctly defined/imported in server.js
                { expiresIn: '1h' },
                (err, token) => {
                    if (err) {
                        console.error('JWT Sign Error:', err);
                        return res.status(500).json({ message: 'Token generation failed.' }); // MODIFICATION: Added return for clarity
                    }
                    // MODIFICATION: Sent username back in the response for frontend convenience
                    res.json({ message: 'Logged in successfully', token, username: user.username });
                }
            );
        } catch (err) {
            console.error('Login Error:', err.message);
            res.status(500).send('Server error during login');
        }
    }
);

// --- NEW: Forgot Password Request Endpoint ---
app.post(
    '/api/forgotpassword',
    apiLimiter, // Rate limit this endpoint to prevent abuse
    [
        check('email', 'Please include a valid email').isEmail(),
    ],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ message: errors.array()[0].msg });
        }

        const { email } = req.body;

        try {
            const user = await User.findOne({ email });
            if (!user) {
                // Return a generic success message to avoid email enumeration
                return res.status(200).json({ message: 'If a user with that email exists, a password reset link has been sent.' });
            }

            // Generate a reset token and hash it for storage
            const rawResetToken = crypto.randomBytes(32).toString('hex'); // The token to send in email
            const hashedResetToken = await bcrypt.hash(rawResetToken, 10); // Hash for database storage

            user.resetPasswordToken = hashedResetToken; // Store the HASHED token
            user.resetPasswordExpire = Date.now() + 3600000; // Token valid for 1 hour
            await user.save();

            // Create the reset URL (IMPORTANT: Use your frontend URL here!)
            const resetUrl = `https://3000-firebase-instant-data-backup-1748249505922.cluster-nzwlpk54dvagsxetkvxzbvslyi.cloudworkstations.dev/resetpassword/${rawResetToken}`; // Send the RAW token

            const emailContent = `
                <p>You are receiving this because you (or someone else) have requested the reset of the password for your account.</p>
                <p>Please click on the following link, or paste this into your browser to complete the process within one hour of receiving it:</p>
                <p><a href="${resetUrl}">${resetUrl}</a></p>
                <p>If you did not request this, please ignore this email and your password will remain unchanged.</p>
            `;

            const emailResult = await sendEmail(user.email, 'Password Reset Request', emailContent);

            if (emailResult.success) {
                res.status(200).json({ message: 'Password reset link sent successfully.' });
            } else {
                console.error('Error sending reset email:', emailResult.error);
                res.status(500).json({ message: 'Error sending password reset email.' });
            }

        } catch (err) {
            console.error('Forgot Password Error:', err.message);
            res.status(500).send('Server error during password reset request.');
        }
    }
);

// --- NEW: Reset Password Endpoint ---
app.post(
    '/api/resetpassword/:token',
    apiLimiter, // Rate limit this endpoint
    [
        check('password', 'Password must be 6 or more characters').isLength({ min: 6 }),
    ],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ message: errors.array()[0].msg });
        }

        const { token } = req.params; // The raw token from the URL
        const { password } = req.body; // The new password

        try {
            // Find users with a valid (non-expired) reset token
            const users = await User.find({
                resetPasswordExpire: { $gt: Date.now() } // Token must not be expired
            });

            let user = null;
            // Iterate through valid tokens and compare hashed values
            for (const u of users) {
                if (u.resetPasswordToken && await bcrypt.compare(token, u.resetPasswordToken)) {
                    user = u;
                    break;
                }
            }

            if (!user) {
                return res.status(400).json({ message: 'Invalid or expired password reset token.' });
            }

            // Update user's password (pre-save hook will handle hashing)
            user.password = password; // Assign plaintext new password

            // Clear reset token fields
            user.resetPasswordToken = undefined;
            user.resetPasswordExpire = undefined;

            await user.save(); // This will trigger the pre('save') hook to hash the new password

            res.status(200).json({ message: 'Password has been reset successfully.' });

        } catch (err) {
            console.error('Reset Password Error:', err.message);
            res.status(500).send('Server error during password reset.');
        }
    }
);


// --- API for User Feedback/Bug Report ---
app.post('/api/report-issue', authMiddleware, async (req, res) => {
    const { subject, description } = req.body;
    const userId = req.user.userId;
    const username = req.user.username;
    const serialNumber = req.user.serialNumber;

    if (!subject || !description) {
        return res.status(400).json({ message: 'Subject and description are required.' });
    }

    try {
        const newIssue = new Issue({
            user_id: userId,
            username: username,
            serial_number: serialNumber,
            subject: subject,
            description: description,
            status: 'new',
            reported_at: new Date()
        });

        await newIssue.save();
        res.status(201).json({ message: 'Issue reported successfully!' });
    } catch (error) {
        console.error('Error reporting issue:', error);
        res.status(500).json({ message: 'Failed to report issue.' });
    }
});

// File Upload, Encryption, Local Storage, and Blockchain Integration
app.post('/api/upload', authMiddleware, apiLimiter, upload.array('file'), async (req, res) => {
    try {
        // Multer handles temporary file storage; req.files contains an array of file objects
        if (!req.files || req.files.length === 0) {
            return res.status(400).json({ message: 'No files uploaded.' });
        }

        // --- START USER_ID VALIDATION ---
        if (!req.user || (req.user.userId === undefined && req.user.id === undefined)) {
            console.error("Authentication Error: req.user or user ID (userId/id) is missing in /api/upload.");
            return res.status(401).json({ message: 'Unauthorized: User information missing from token.' });
        }
        const userId = req.user.userId || req.user.id; // Use userId, fallback to id
        if (!userId) {
            console.error("CRITICAL ERROR: userId variable is undefined despite token validation in /api/upload.");
            return res.status(500).json({ message: 'Server configuration error: User ID could not be determined.' });
        }
        console.log("DEBUG: Uploading for userId:", userId);
        // --- END USER_ID VALIDATION ---

        const encryptedDir = 'encrypted_files'; // Ensure this directory exists relative to your server.js
        await fsp.mkdir(encryptedDir, { recursive: true });

        const uploadedFilesResponse = [];
        let totalUploadedSize = 0;

        for (const file of req.files) { // Loop through each uploaded file
            const originalFilePath = file.path; // Temporary path where multer saved the file
            const originalFileName = file.originalname;

            try {
                const fileBuffer = await fsp.readFile(originalFilePath);

                // IMPORTANT: Your 'encrypt' function.
                // Ensure it's correctly defined and handles the encryption.
                // If it needs a user's encryption key, you MUST fetch the user first
                // to get their key (e.g., `const user = await User.findById(userId); const userEncryptionKey = user.encryptionKey;`).
                // For now, I'm using `encrypt(fileBuffer)` as you provided, assuming it works globally or has access to what it needs.
                const encryptedContentHex = encrypt(fileBuffer);

                const encryptedFileNameOnDisk = `${crypto.randomBytes(16).toString('hex')}.enc`;
                const encryptedFilePath = path.join(encryptedDir, encryptedFileNameOnDisk);
                await fsp.writeFile(encryptedFilePath, encryptedContentHex);

                const encryptedFileHash = crypto.createHash('sha256').update(encryptedContentHex).digest('hex');

                await fsp.unlink(originalFilePath); // Delete the temporary file created by multer

                const fileMetadata = {
                    originalName: originalFileName,
                    mimeType: file.mimetype,
                    encryptedFileName: encryptedFileNameOnDisk,
                    // encryptedFilePath: encryptedFilePath, // Uncomment if your File model includes this
                    fileSize: file.size,
                    encryptedFileHash: encryptedFileHash,
                    uploadDate: new Date().toISOString(),
                    userId: userId
                };

                // Add metadata to MongoDB File model
                // This `File` refers to the Mongoose model you just created and imported.
                const newFileRecord = new File(fileMetadata);
                await newFileRecord.save();

                // Add file upload activity to the blockchain
                const latestBlock = instantDataBackupChain.getLatestBlock();
                const newBlock = new Block(
                    instantDataBackupChain.chain.length, // index
                    Date.now(), // timestamp
                    { // Data payload for the blockchain block
                        type: 'file_upload',
                        userId: userId,
                        originalName: fileMetadata.originalName,
                        encryptedFileName: fileMetadata.encryptedFileName,
                        fileSize: fileMetadata.fileSize,
                        mimeType: fileMetadata.mimeType,
                        encryptedFileHash: fileMetadata.encryptedFileHash
                    },
                    latestBlock.hasher // previousHash
                );
                instantDataBackupChain.addBlock(newBlock);
                console.log(`Block mined: ${newBlock.hasher}`);
                console.log(`New block added to the blockchain: ${newBlock.hasher}`);

                // Add to total size for user storage update
                totalUploadedSize += file.size;

                // Log individual activity
                const uploadActivity = new Activity({
                    user_id: userId,
                    timestamp: new Date(),
                    action: 'upload',
                    file_name: file.originalname,
                    file_size: file.size,
                    description: `Uploaded file: ${file.originalname}`
                });
                await uploadActivity.save();

                uploadedFilesResponse.push({
                    originalName: originalFileName,
                    mimeType: file.mimetype,
                    encryptedFileName: encryptedFileNameOnDisk,
                    fileSize: file.size,
                    blockchainHash: newBlock.hasher
                });

            } catch (fileError) {
                console.error(`Error processing file ${originalFileName}:`, fileError);
                // Attempt to delete temporary file if it still exists due to an error
                if (originalFilePath && fs.existsSync(originalFilePath)) {
                    await fsp.unlink(originalFilePath).catch(e => console.error(`Failed to delete temp file ${originalFilePath} during error cleanup:`, e));
                }
                // Continue to next file, don't break the loop for one failed file
            }
        }

        // After processing all files, check blockchain validity and save state once
        if (instantDataBackupChain.isChainValid()) {
            console.log('Is chain valid? true');
            const blockchainState = await BlockchainState.findOne({});
            if (blockchainState) {
                blockchainState.chain = instantDataBackupChain.chain.map(block => ({
                    index: block.index,
                    timestamp: block.timestamp,
                    data: block.data,
                    previousHash: block.previousHash,
                    hasher: block.hasher,
                    nonce: block.nonce
                }));
                blockchainState.difficulty = instantDataBackupChain.difficulty;
                await blockchainState.save();
                console.log("Blockchain state updated and saved to DB.");
            } else {
                console.error("Error: Blockchain state document not found after initialization. Creating new one as fallback.");
                const newBlockchainState = new BlockchainState({
                    chain: instantDataBackupChain.chain.map(block => ({
                        index: block.index,
                        timestamp: block.timestamp,
                        data: block.data,
                        previousHash: block.previousHash,
                        hasher: block.hasher,
                        nonce: block.nonce
                    })),
                    difficulty: instantDataBackupChain.difficulty
                });
                await newBlockchainState.save();
            }
        } else {
            console.error('Is chain valid? false - Chain integrity compromised after upload!');
            // Implement robust error handling here if the chain is invalid (e.g., revert changes, alert admin)
            return res.status(500).json({ message: 'Blockchain integrity compromised during upload process.' });
        }


        // Update user's total storage usage after all successful uploads
        if (totalUploadedSize > 0) {
            await User.findByIdAndUpdate(userId, { $inc: { total_storage_used: totalUploadedSize } });
        }

        res.status(200).json({
            message: `${uploadedFilesResponse.length} file(s) uploaded, encrypted, stored locally, and metadata added to blockchain!`,
            uploadedFiles: uploadedFilesResponse // Return details of successfully processed files
        });

    } catch (error) {
        console.error('Overall File Upload/Encryption/Blockchain Error:', error);
        // Multer errors (e.g., file size limit) are caught here
        if (error instanceof multer.MulterError) {
            return res.status(400).json({ message: `Upload error: ${error.message}` });
        }
        res.status(500).json({ message: 'Server error during file upload and encryption.' });
    }
});

// Endpoint to view the entire Blockchain (can be public or protected, for now public for easy inspection)
app.get('/api/blockchain', async (req, res) => {
    try {
        const blockchainState = await BlockchainState.findOne({});
        if (blockchainState) {
            const loadedChainInstance = new Blockchain(blockchainState.chain, blockchainState.difficulty);
            res.status(200).json({
                chain: blockchainState.chain,
                isValid: loadedChainInstance.isChainValid(),
                totalBlocks: blockchainState.chain.length
            });
        } else {
            res.status(404).json({ message: "Blockchain not found or not initialized." });
        }
    } catch (error) {
        console.error("Error fetching blockchain:", error);
        res.status(500).json({ message: "Server error fetching blockchain." });
    }
});

// NEW: File Restore Endpoint (protected by authMiddleware and includes user ID check)
app.get('/api/restore/:encryptedFileName', authMiddleware, apiLimiter, async (req, res) => {
    const requestedEncryptedFileName = req.params.encryptedFileName;
    const encryptedDir = 'encrypted_files';

    try {
        const blockchainState = await BlockchainState.findOne({});
        if (!blockchainState || !blockchainState.chain || blockchainState.chain.length === 0) {
            return res.status(404).json({ message: "Blockchain is empty or not found. No files to restore." });
        }

        const currentBlockchain = new Blockchain(blockchainState.chain, blockchainState.difficulty);

        let fileMetadata = null;
        // Iterate from the end of the chain to get the latest metadata for a given file
        for (let i = currentBlockchain.chain.length - 1; i >= 0; i--) {
            const block = currentBlockchain.chain[i];
            if (block.data && typeof block.data === 'object' && block.data.encryptedFileName === requestedEncryptedFileName) {
                fileMetadata = block.data;
                break; // Found the latest relevant block for this file
            }
        }

        if (!fileMetadata) {
            return res.status(404).json({ message: "File metadata not found on the blockchain." });
        }

        // IMPORTANT: Authorization check
        if (fileMetadata.userId && fileMetadata.userId.toString() !== req.user.userId.toString()) { // Compare ObjectIds correctly
            console.warn(`Unauthorized restore attempt: User ${req.user.userId} tried to restore file belonging to ${fileMetadata.userId}`);
            return res.status(403).json({ message: 'Unauthorized: You can only restore your own files.' });
        }

        if (fileMetadata.status === 'deleted') {
            return res.status(400).json({ message: 'File is marked as deleted on the blockchain and cannot be restored. Please contact support if you need to recover it.' });
        }

        const encryptedFilePath = path.join(encryptedDir, fileMetadata.encryptedFileName);

        if (!fs.existsSync(encryptedFilePath)) {
            console.warn(`Encrypted file missing from disk: ${encryptedFilePath}. Metadata exists on blockchain.`);
            return res.status(404).json({ message: "Encrypted file not found on server disk, although metadata exists on blockchain. It might have been deleted or moved." });
        }

        const encryptedContentHex = await fsp.readFile(encryptedFilePath, 'utf8');
        const decryptedBuffer = decrypt(encryptedContentHex);

        const contentType = fileMetadata.mimeType || mime.lookup(fileMetadata.originalName) || 'application/octet-stream';
        console.log(`Restoring file '${fileMetadata.originalName}' with Content-Type: ${contentType}`);

        res.setHeader('Content-Type', contentType);
        res.setHeader('Content-Disposition', `inline; filename="${fileMetadata.originalName}"`); // 'inline' for preview, 'attachment' for download
        res.setHeader('Content-Length', decryptedBuffer.length);
        res.status(200).send(decryptedBuffer);

        console.log(`File '${fileMetadata.originalName}' restored successfully.`);

        // Log activity
        const downloadActivity = new Activity({
            user_id: req.user.userId,
            timestamp: new Date(),
            action: 'download',
            file_name: fileMetadata.originalName,
            description: `Downloaded file: ${fileMetadata.originalName}`
        });
        await downloadActivity.save();

    } catch (error) {
        console.error('File Restore Error:', error);
        res.status(500).json({ message: 'Server error during file restore', error: error.message });
    }
});

// NEW: User-Specific File Listing
app.get('/api/user/files', authMiddleware, apiLimiter, async (req, res) => {
    try {
        // IMPORTANT: Ensure req.user.userId is correctly populated by your authMiddleware.
        // Based on our previous discussion, it might be req.user.id.
        // Please confirm whether your JWT payload puts the user ID in 'id' or 'userId'.
        // I will keep 'req.user.userId' as per your provided code, but keep this in mind.
        const userId = req.user.userId; 

        const blockchainState = await BlockchainState.findOne({});
        if (!blockchainState || !blockchainState.chain || blockchainState.chain.length === 0) {
            return res.status(200).json({ files: [], message: "No files found for this user or blockchain is empty." });
        }

        // IMPORTANT: Your Blockchain constructor likely expects the chain as the first argument,
        // and difficulty as the second, but your previous code had `currentBlockchain = new Blockchain(difficulty)`
        // and later added the chain. Re-confirm how your Blockchain class is initialized.
        // For now, I'm assuming it takes the chain as the first argument and difficulty as the second
        // if you want to load from DB like this.
        // If your Blockchain class only takes difficulty, then currentBlockchain.chain needs to be set separately.
        const currentBlockchain = new Blockchain(blockchainState.chain, blockchainState.difficulty); 

        const fileStatuses = new Map();

        //  Iterate from the END of the blockchain to ensure the latest status for each file
        for (let i = currentBlockchain.chain.length - 1; i >= 0; i--) {
            const block = currentBlockchain.chain[i];
        
        //     // First, check if block.data exists and is an object.
        //     // Then, check if it has properties expected for file metadata: userId and encryptedFileName.
        //     // If it doesn't have both, it's not a file block we care about for user files.
             if (block.data && typeof block.data === 'object' && block.data.userId && block.data.encryptedFileName) {
        //         // Now that we've confirmed block.data.userId exists, it's safe to use toString()
        //         // since we are certain it's a file-related block.
        //         // The error indicates userId itself is undefined, not just its toString method.
        //         // So, the previous check `block.data.userId != null` or just `block.data.userId` should be sufficient.
                 if (block.data.userId.toString() === userId.toString()) {
                    const encryptedFileName = block.data.encryptedFileName;
                    if (encryptedFileName && !fileStatuses.has(encryptedFileName)) {
                        fileStatuses.set(encryptedFileName, { blockData: block.data, isDeleted: block.data.status === 'deleted' });
                    }
                }
            }
        }

        const userFiles = [];
        // Convert Map entries to an array and filter out deleted ones
        // Sort by uploadDate (oldest first for consistent display, or newest first if preferred)
        const activeFiles = Array.from(fileStatuses.values())
                                 .filter(({ isDeleted }) => !isDeleted)
                                 .map(({ blockData }) => ({
                                     originalName: blockData.originalName,
                                     encryptedFileName: blockData.encryptedFileName,
                                     fileSize: blockData.fileSize,
                                     uploadDate: blockData.uploadDate,
                                     blockchainHash: blockData.hasher, // Include blockchain hash of the block that recorded this file's state
                                     mimeType: blockData.mimeType
                                 }));

        // Sort by uploadDate, descending (newest first)
        activeFiles.sort((a, b) => new Date(b.uploadDate) - new Date(a.uploadDate));


        res.status(200).json({
            files: activeFiles,
            totalFiles: activeFiles.length,
            message: `Found ${activeFiles.length} active files for user ${req.user.username || req.user.email}`
        });

    } catch (error) {
        console.error('Error fetching user files:', error);
        res.status(500).json({ message: 'Server error fetching user files', error: error.message });
    }
});

// Multiple Files Delete Route
app.post('/api/delete-multiple', authMiddleware, apiLimiter, async (req, res) => {
    try {
        const { fileIds } = req.body; // Expecting an array of MongoDB File _id's
        if (!fileIds || !Array.isArray(fileIds) || fileIds.length === 0) {
            return res.status(400).json({ message: 'No file IDs provided for deletion.' });
        }

        // --- User ID validation ---
        if (!req.user || (req.user.userId === undefined && req.user.id === undefined)) {
            console.error("Authentication Error: req.user or user ID (userId/id) is missing in /api/delete-multiple.");
            return res.status(401).json({ message: 'Unauthorized: User information missing from token.' });
        }
        const userId = req.user.userId || req.user.id;
        if (!userId) {
            console.error("CRITICAL ERROR: userId variable is undefined in /api/delete-multiple.");
            return res.status(500).json({ message: 'Server configuration error: User ID could not be determined.' });
        }
        console.log(`DEBUG: User ${userId} requested deletion for file IDs:`, fileIds);

        const encryptedDir = 'encrypted_files'; // Ensure this matches your storage directory
        let filesDeletedCount = 0;
        let totalBytesFreed = 0;

        // Fetch all files at once to ensure they belong to the user
        const filesToDelete = await File.find({ _id: { $in: fileIds }, userId: userId });

        if (filesToDelete.length === 0) {
            return res.status(404).json({ message: 'No files found for deletion or not owned by user.' });
        }

        for (const fileMetadata of filesToDelete) {
            const encryptedFilePath = path.join(encryptedDir, fileMetadata.encryptedFileName);

            try {
                // 1. Delete the encrypted file from disk
                if (fs.existsSync(encryptedFilePath)) {
                    await fsp.unlink(encryptedFilePath);
                    console.log(`Deleted file from disk: ${encryptedFilePath}`);
                } else {
                    console.warn(`File not found on disk, but found in DB: ${encryptedFilePath}. Skipping disk deletion.`);
                }

                // 2. Delete the metadata from MongoDB
                await File.deleteOne({ _id: fileMetadata._id });
                console.log(`Deleted file metadata from DB: ${fileMetadata.originalName} (ID: ${fileMetadata._id})`);
                filesDeletedCount++;
                totalBytesFreed += fileMetadata.fileSize;

                // 3. Log activity
                const deleteActivity = new Activity({
                    user_id: userId,
                    timestamp: new Date(),
                    action: 'delete',
                    file_name: fileMetadata.originalName,
                    file_size: fileMetadata.fileSize,
                    description: `Deleted file: ${fileMetadata.originalName}`
                });
                await deleteActivity.save();

                // 4. Update blockchain (if you want to record deletions)
                // You could add a 'file_deletion' block here if your blockchain schema supports it
                // and you deem it necessary to immutably record deletions.
                // This would be similar to how you add an 'upload' block.

            } catch (fileError) {
                console.error(`Error deleting file ${fileMetadata.originalName} (ID: ${fileMetadata._id}):`, fileError);
                // Continue to next file if one fails, don't stop the entire operation
            }
        }

        // 5. Update user's total_storage_used
        if (totalBytesFreed > 0) {
            await User.findByIdAndUpdate(userId, { $inc: { total_storage_used: -totalBytesFreed } });
            console.log(`Updated user ${userId} storage: freed ${totalBytesFreed} bytes.`);
        }

        res.status(200).json({
            message: `Successfully deleted ${filesDeletedCount} file(s).`,
            deletedCount: filesDeletedCount
        });

    } catch (error) {
        console.error('Overall Multiple File Deletion Error:', error);
        res.status(500).json({ message: 'Server error during multiple file deletion.' });
    }
});

// NEW: User-Specific File Deletion
app.delete('/api/delete/:encryptedFileName', authMiddleware, apiLimiter, async (req, res) => {
    const requestedEncryptedFileName = req.params.encryptedFileName;
    const userId = req.user.userId;
    const encryptedDir = 'encrypted_files';

    try {
        const blockchainState = await BlockchainState.findOne({});
        if (!blockchainState || !blockchainState.chain || blockchainState.chain.length === 0) {
            return res.status(404).json({ message: "Blockchain is empty or not found. No files to delete." });
        }

        const currentBlockchain = new Blockchain(blockchainState.chain, blockchainState.difficulty);

        let fileMetadataToDelete = null;

        // Iterate from the END of the chain to find the most recent block for this file
        for (let i = currentBlockchain.chain.length - 1; i >= 0; i--) {
            const block = currentBlockchain.chain[i];
            if (block.data && typeof block.data === 'object' && block.data.encryptedFileName === requestedEncryptedFileName) {
                // IMPORTANT: Ensure the file belongs to the authenticated user
                if (block.data.userId && block.data.userId.toString() === userId.toString()) {
                    fileMetadataToDelete = block.data;
                    break; // Found the latest relevant block for the current user
                } else {
                    // If a file with this encryptedFileName exists but belongs to another user,
                    // we should still return unauthorized to avoid leaking info.
                    console.warn(`Unauthorized delete attempt: User ${userId} tried to delete file ${requestedEncryptedFileName} belonging to ${block.data.userId}`);
                    return res.status(403).json({ message: 'Unauthorized: You can only delete your own files.' });
                }
            }
        }

        if (!fileMetadataToDelete) {
            return res.status(404).json({ message: "File metadata not found on the blockchain for this user." });
        }

        // Check if the file is already marked as deleted
        if (fileMetadataToDelete.status === 'deleted') {
            return res.status(400).json({ message: 'File is already marked as deleted on the blockchain.' });
        }

        const encryptedFilePath = path.join(encryptedDir, fileMetadataToDelete.encryptedFileName);
        if (fs.existsSync(encryptedFilePath)) {
            await fsp.unlink(encryptedFilePath);
            console.log(`Encrypted file '${encryptedFilePath}' deleted from disk.`);
        } else {
            console.warn(`Encrypted file '${encryptedFilePath}' not found on disk, but metadata exists on blockchain. Proceeding to update blockchain.`);
        }

        // Deduct storage usage
        await User.findByIdAndUpdate(req.user.userId, { $inc: { total_storage_used: -(fileMetadataToDelete.fileSize || 0) } });


        // Create a new block to record the logical deletion on the blockchain
        const deletionMetadata = {
            ...fileMetadataToDelete, // Copy existing metadata
            status: 'deleted',       // Mark as deleted
            deletionDate: new Date().toISOString(),
            deletedBy: userId,
        };
        const newDeletionBlock = new Block(
            currentBlockchain.chain.length,
            Date.now(),
            deletionMetadata,
            currentBlockchain.getLatestBlock().hasher
        );
        currentBlockchain.addBlock(newDeletionBlock);
        console.log("New deletion block added to the blockchain:", newDeletionBlock.hasher);
        console.log("Is chain valid?", currentBlockchain.isChainValid());

        const latestBlockchainState = await BlockchainState.findOne({});
        if (latestBlockchainState) {
            latestBlockchainState.chain = currentBlockchain.chain.map(block => ({
                index: block.index,
                timestamp: block.timestamp,
                data: block.data,
                previousHash: block.previousHash,
                hasher: block.hasher,
                nonce: block.nonce
            }));
            latestBlockchainState.difficulty = currentBlockchain.difficulty;
            await latestBlockchainState.save();
            console.log("Blockchain state updated in DB with deletion record.");
        } else {
            console.error("Error: Blockchain state document not found during delete update. This should not happen if initialized.");
            return res.status(500).json({ message: "Blockchain state not found in DB." });
        }

        // Log activity
        const deleteActivity = new Activity({
            user_id: req.user.userId,
            timestamp: new Date(),
            action: 'delete',
            file_name: fileMetadataToDelete.originalName,
            description: `Deleted file: ${fileMetadataToDelete.originalName}`
        });
        await deleteActivity.save();

        res.status(200).json({
            message: `File '${fileMetadataToDelete.originalName}' (encrypted: ${fileMetadataToDelete.encryptedFileName}) marked as deleted on blockchain and removed from disk.`,
            deletedFileName: fileMetadataToDelete.encryptedFileName,
            blockchainHashOfDeletionRecord: newDeletionBlock.hasher
        });
    } catch (error) {
        console.error('File Delete Error:', error);
        res.status(500).json({ message: 'Server error during file deletion', error: error.message });
    }
});
// Multiple Files Download Route
app.post('/api/download-multiple', authMiddleware, apiLimiter, async (req, res) => {
    try {
        const { fileIds } = req.body; // Expecting an array of MongoDB File _id's
        if (!fileIds || !Array.isArray(fileIds) || fileIds.length === 0) {
            return res.status(400).json({ message: 'No file IDs provided for download.' });
        }

        // --- User ID validation ---
        if (!req.user || (req.user.userId === undefined && req.user.id === undefined)) {
            console.error("Authentication Error: req.user or user ID (userId/id) is missing in /api/download-multiple.");
            return res.status(401).json({ message: 'Unauthorized: User information missing from token.' });
        }
        const userId = req.user.userId || req.user.id;
        if (!userId) {
            console.error("CRITICAL ERROR: userId variable is undefined in /api/download-multiple.");
            return res.status(500).json({ message: 'Server configuration error: User ID could not be determined.' });
        }
        console.log(`DEBUG: User ${userId} requested download for file IDs:`, fileIds);

        // --- Fetch user's encryption key if needed ---
        let userEncryptionKey = null;
        // IF YOUR DECRYPT FUNCTION REQUIRES A USER-SPECIFIC KEY:
        // You'll need to fetch the user document to get their key.
        // const user = await User.findById(userId);
        // if (!user || !user.encryptionKey) {
        //     return res.status(500).json({ message: 'User encryption key not found.' });
        // }
        // userEncryptionKey = user.encryptionKey; // Assign the key

        // --- Prepare for Zipping ---
        const archive = archiver('zip', {
            zlib: { level: 9 } // Sets the compression level.
        });

        const archiveName = `InstantBackup_Files_${Date.now()}.zip`; // Unique name for the zip file
        res.attachment(archiveName); // Set the filename for the client

        // Pipe the archive to the response
        archive.pipe(res);

        const encryptedDir = 'encrypted_files'; // Assuming this is where encrypted files are stored

        // --- Process each file ---
        for (const fileId of fileIds) {
            // Find the file metadata in your MongoDB
            const fileMetadata = await File.findOne({ _id: fileId, userId: userId });

            if (!fileMetadata) {
                console.warn(`File with ID ${fileId} not found or not owned by user ${userId}. Skipping.`);
                // Optionally, you could collect these skipped files and inform the user.
                continue; // Skip to the next file
            }

            const encryptedFilePath = path.join(encryptedDir, fileMetadata.encryptedFileName);

            // Check if encrypted file exists on disk
            if (!fs.existsSync(encryptedFilePath)) {
                console.error(`Encrypted file not found on disk: ${encryptedFilePath}. Skipping.`);
                continue;
            }

            try {
                // Read the encrypted file content
                const encryptedContentBuffer = await fsp.readFile(encryptedFilePath);

                // Decrypt the content
                // IMPORTANT: Pass userEncryptionKey if your decrypt function needs it.
                const decryptedContentBuffer = decrypt(encryptedContentBuffer, userEncryptionKey /*, IV_IF_NEEDED */);

                // Append decrypted file to the zip archive
                archive.append(decryptedContentBuffer, { name: fileMetadata.originalName });
                console.log(`Added ${fileMetadata.originalName} to archive.`);

                // Log activity for each downloaded file
                const downloadActivity = new Activity({
                    user_id: userId,
                    timestamp: new Date(),
                    action: 'download',
                    file_name: fileMetadata.originalName,
                    file_size: fileMetadata.fileSize,
                    description: `Downloaded file: ${fileMetadata.originalName}`
                });
                await downloadActivity.save();

            } catch (fileError) {
                console.error(`Error processing file ${fileMetadata.originalName} (ID: ${fileId}) for download:`, fileError);
                // Continue to the next file if one fails
            }
        }

        // Finalize the archive. This will send the data to the response stream.
        archive.finalize();

        // Listen for all archive data to be written
        archive.on('end', () => {
            console.log('Archive data has been finalized and output sent.');
            // res.end() is implicitly called by stream piping, but good to know
        });

        // Handle errors during archiving
        archive.on('error', (err) => {
            console.error('Archiver error:', err);
            res.status(500).json({ message: 'Error creating file archive.' });
        });

    } catch (error) {
        console.error('Overall Multiple File Download Error:', error);
        res.status(500).json({ message: 'Server error during multiple file download.' });
    }
});
// Endpoint to get user's storage usage
app.get('/api/user/storage-usage', authMiddleware, apiLimiter, async (req, res) => {
    try {
        const userId = req.user.userId;
        const user = await User.findById(userId);

        if (!user) {
            return res.status(404).json({ message: 'User not found.' });
        }

        res.status(200).json({
            total_storage_used: user.total_storage_used || 0,
            message: `Storage usage for user ${user.username || user.email}`
        });

    } catch (error) {
        console.error('Error fetching storage usage:', error);
        res.status(500).json({ message: 'Server error fetching storage usage.', error: error.message });
    }
});

// Endpoint to get user's activity logs
app.get('/api/user/activities', authMiddleware, apiLimiter, async (req, res) => {
    try {
        const userId = req.user.userId;
        // Find activities for the user, sorted by timestamp descending
        const activities = await Activity.find({ user_id: userId }).sort({ timestamp: -1 });

        res.status(200).json({
            activities: activities,
            totalActivities: activities.length,
            message: `Found ${activities.length} activities for user ${req.user.username || req.user.email}`
        });

    } catch (error) {
        console.error('Error fetching user activities:', error);
        res.status(500).json({ message: 'Server error fetching user activities.', error: error.message });
    }
});


// --- Serve Frontend HTML Files ---
// Serve specific HTML files directly (order matters for specific paths)
app.get('/login.html', (req, res) => res.sendFile(path.join(__dirname, 'frontend', 'login.html')));
app.get('/register.html', (req, res) => res.sendFile(path.join(__dirname, 'frontend', 'register.html')));
app.get('/forgot-password.html', (req, res) => res.sendFile(path.join(__dirname, 'frontend', 'forgot-password.html')));
app.get('/resetpassword/:token', (req, res) => res.sendFile(path.join(__dirname, 'frontend', 'reset-password.html')));
app.get('/dashboard.html', (req, res) => res.sendFile(path.join(__dirname, 'frontend', 'dashboard.html')));

// Catch-all route for the root, redirects to welcome page
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'frontend', 'index.html')); // index.html is now the welcome page
});

// Serve static assets from 'frontend' directory for all other paths (must be after specific routes)
app.use(express.static(path.join(__dirname, 'frontend')));
// --- End Serve Frontend HTML Files ---


// --- Server Startup Logic ---
initializeBlockchain().then(() => {
    app.listen(port, () => {
        console.log(`Server listening at http://localhost:${port}`);
    });
}).catch(err => {
    console.error("Failed to start server due to critical initialization error:", err);
    process.exit(1); // Exit if blockchain init fails
});