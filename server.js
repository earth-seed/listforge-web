require('dotenv').config();

const express = require('express');
const { initializeApp } = require('firebase/app');
const { 
  getAuth, 
  createUserWithEmailAndPassword,
  signInWithEmailAndPassword 
} = require('firebase/auth');
const { 
  getFirestore, 
  collection, 
  doc, 
  setDoc,
  getDoc,
  getDocs,
  query,
  where
} = require('firebase/firestore');
const admin = require('firebase-admin');
const crypto = require('crypto');
const nodemailer = require('nodemailer');

const app = express();
app.use(express.json());

// Configure Nodemailer
const transporter = nodemailer.createTransport({
    host: 'smtp.gmail.com',
    port: 465,
    secure: true,
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASSWORD
    },
    debug: true // Enable debug logs
});

// Verify the transporter configuration
transporter.verify(function(error, success) {
    if (error) {
        console.log('Nodemailer configuration error:', error);
    } else {
        console.log('Nodemailer is ready to send emails');
    }
});

// Initialize Firebase Admin with service account from environment variable
let serviceAccount;
try {
    serviceAccount = process.env.FIREBASE_SERVICE_ACCOUNT ? 
        JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT) : 
        require('./serviceAccount.json');
} catch (error) {
    console.error('Error loading service account:', error);
    serviceAccount = require('./serviceAccount.json');
}

// Initialize Firebase Admin
admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
});

// Initialize regular Firebase (for client operations)
const firebaseConfig = {
    apiKey: "AIzaSyDq3K_X-GCGvPP_IdzyOg8duE3Q6b5Udqs",
    authDomain: "listforge-8943a.firebaseapp.com",
    projectId: "listforge-8943a",
    storageBucket: "listforge-8943a.firebasestorage.app",
    messagingSenderId: "804960523648",
    appId: "1:804960523648:web:262d50bf6a8b2f38565d65",
    measurementId: "G-KNTJV4WMG1"
};

const firebaseApp = initializeApp(firebaseConfig);
const auth = getAuth(firebaseApp);
const db = getFirestore(firebaseApp);

// Middleware to handle authentication
const checkAuth = async (req, res, next) => {
    const token = req.headers.authorization?.split('Bearer ')[1];
    if (!token) {
        return res.status(401).json({ error: 'Unauthorized' });
    }
    try {
        const decodedToken = await auth.verifyIdToken(token);
        req.user = decodedToken;
        next();
    } catch (error) {
        res.status(401).json({ error: 'Unauthorized' });
    }
};

// Registration endpoint
app.post('/auth/register', async (req, res) => {
    try {
        const { email, username, password } = req.body;
        
        // Basic validation
        if (!email || !username || !password) {
            return res.status(400).json({ error: 'All fields are required' });
        }
        
        if (password.length < 6) {
            return res.status(400).json({ error: 'Password must be at least 6 characters' });
        }
        
        // Check if username already exists
        const usernameSnapshot = await admin.firestore()
            .collection('users')
            .where('username', '==', username)
            .get();
            
        if (!usernameSnapshot.empty) {
            return res.status(400).json({ error: 'This username is already taken. Please choose another one.' });
        }
        
        // Create user in Firebase Auth
        try {
            const userRecord = await admin.auth().createUser({
                email,
                password,
                displayName: username
            });
            
            // Store additional user data in Firestore
            await admin.firestore().collection('users').doc(userRecord.uid).set({
                username,
                email,
                createdAt: admin.firestore.FieldValue.serverTimestamp(),
                subscription: {
                    status: 'inactive'
                }
            });
            
            // Create custom token for immediate login
            const token = await admin.auth().createCustomToken(userRecord.uid);
            
            res.status(201).json({ token });
            
        } catch (firebaseError) {
            console.error('Firebase auth error:', firebaseError);
            
            // Handle specific Firebase errors with user-friendly messages
            if (firebaseError.code === 'auth/email-already-exists' || 
                firebaseError.code === 'auth/email-already-in-use') {
                return res.status(400).json({ 
                    error: 'This email is already registered. Please use a different email or try logging in.' 
                });
            } else if (firebaseError.code === 'auth/invalid-email') {
                return res.status(400).json({ 
                    error: 'Please enter a valid email address.' 
                });
            } else if (firebaseError.code === 'auth/weak-password') {
                return res.status(400).json({ 
                    error: 'Your password is too weak. Please choose a stronger password.' 
                });
            } else {
                return res.status(400).json({ 
                    error: 'There was a problem creating your account. Please try again.' 
                });
            }
        }
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ 
            error: 'We couldn\'t complete your registration. Please try again later.' 
        });
    }
});

// Login endpoint
app.post('/auth/login', async (req, res) => {
    try {
        const { login, password } = req.body;
        
        // Check if login is email or username
        let email = login;
        
        // If login doesn't look like an email, try to find the user by username
        if (!login.includes('@')) {
            const usersSnapshot = await admin.firestore()
                .collection('users')
                .where('username', '==', login)
                .limit(1)
                .get();
                
            if (usersSnapshot.empty) {
                return res.status(401).json({ error: 'Invalid username or password' });
            }
            
            // Get the email from the found user
            email = usersSnapshot.docs[0].data().email;
        }
        
        // Sign in with email and password
        const userCredential = await signInWithEmailAndPassword(auth, email, password);
        const user = userCredential.user;
        
        // Get ID token
        const token = await user.getIdToken();
        
        // Check if user exists in Firestore, if not create a record
        const userDoc = await admin.firestore().collection('users').doc(user.uid).get();
        
        if (!userDoc.exists) {
            // Create user document if it doesn't exist
            await admin.firestore().collection('users').doc(user.uid).set({
                email: user.email,
                username: login.includes('@') ? user.email.split('@')[0] : login,
                createdAt: admin.firestore.FieldValue.serverTimestamp(),
                subscription: {
                    status: 'inactive'
                }
            });
        }
        
        res.json({ token });
    } catch (error) {
        console.error('Login error:', error);
        
        if (error.code === 'auth/user-not-found' || error.code === 'auth/wrong-password') {
            return res.status(401).json({ error: 'Invalid email or password' });
        }
        
        res.status(500).json({ error: 'Login failed. Please try again.' });
    }
});

// Auth check endpoint
app.get('/auth/check', async (req, res) => {
    try {
        const token = req.headers.authorization?.split('Bearer ')[1];
        if (!token) {
            return res.status(401).json({ error: 'No token provided' });
        }

        // Verify the token using admin SDK
        const decodedToken = await admin.auth().verifyIdToken(token);
        if (!decodedToken) {
            return res.status(401).json({ error: 'Invalid token' });
        }

        // Get user data from Firebase Auth
        const userRecord = await admin.auth().getUser(decodedToken.uid);
        
        // Get user data from Firestore
        const userDoc = await admin.firestore().collection('users').doc(decodedToken.uid).get();
        const userData = userDoc.exists ? userDoc.data() : {};

        console.log('User data from Firestore:', userData);
        console.log('User record from Auth:', userRecord);

        res.json({ 
            authenticated: true, 
            uid: decodedToken.uid,
            username: userData.username || userRecord.displayName || 'Member',
            email: userRecord.email,
            subscription: userData.subscription || { status: 'inactive' },
            createdAt: userData.createdAt
        });
    } catch (error) {
        console.error('Auth check error:', error);
        res.status(401).json({ error: error.message });
    }
});

// Logout endpoint
app.post('/auth/logout', async (req, res) => {
    try {
        await auth.signOut();
        res.json({ message: 'Logged out successfully' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Add this endpoint to handle PayPal subscription updates
app.post('/auth/update-subscription', async (req, res) => {
    try {
        const token = req.headers.authorization?.split('Bearer ')[1];
        if (!token) {
            return res.status(401).json({ error: 'No token provided' });
        }

        const decodedToken = await admin.auth().verifyIdToken(token);
        const userId = decodedToken.uid;
        
        const { 
            subscriptionId, 
            plan,             // 'monthly' or 'yearly'
            status,           // 'active', 'cancelled', etc.
            paymentProvider,  // 'paypal'
            orderId           // PayPal order ID
        } = req.body;
        
        // Update user's subscription status in Firestore
        await admin.firestore().collection('users').doc(userId).update({
            subscription: {
                id: subscriptionId,
                plan: plan,
                status: status || 'active',
                startDate: admin.firestore.FieldValue.serverTimestamp(),
                expiryDate: null, // Will be calculated based on plan
                paymentProvider: paymentProvider || 'paypal',
                orderId: orderId,
                updatedAt: admin.firestore.FieldValue.serverTimestamp()
            }
        });

        // Also store subscription in a separate collection for easier querying
        await admin.firestore().collection('subscriptions').doc(subscriptionId).set({
            userId: userId,
            plan: plan,
            status: status || 'active',
            startDate: admin.firestore.FieldValue.serverTimestamp(),
            paymentProvider: paymentProvider || 'paypal',
            orderId: orderId,
            updatedAt: admin.firestore.FieldValue.serverTimestamp()
        });

        res.json({ success: true });
    } catch (error) {
        console.error('Subscription update error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Add this endpoint to check subscription status
app.get('/auth/subscription-status', async (req, res) => {
    try {
        const token = req.headers.authorization?.split('Bearer ')[1];
        if (!token) {
            return res.status(401).json({ error: 'No token provided' });
        }

        const decodedToken = await admin.auth().verifyIdToken(token);
        const userId = decodedToken.uid;
        
        const userDoc = await admin.firestore().collection('users').doc(userId).get();
        const userData = userDoc.data();
        
        if (!userData || !userData.subscription) {
            return res.json({
                isSubscribed: false,
                plan: null,
                status: 'inactive'
            });
        }
        
        const subscription = userData.subscription;
        
        res.json({
            isSubscribed: subscription.status === 'active',
            plan: subscription.plan,
            status: subscription.status,
            startDate: subscription.startDate,
            paymentProvider: subscription.paymentProvider
        });
    } catch (error) {
        console.error('Subscription status check error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Add this endpoint to cancel a subscription
app.post('/auth/cancel-subscription', async (req, res) => {
    try {
        const token = req.headers.authorization?.split('Bearer ')[1];
        if (!token) {
            return res.status(401).json({ error: 'No token provided' });
        }

        const decodedToken = await admin.auth().verifyIdToken(token);
        const userId = decodedToken.uid;
        
        const userDoc = await admin.firestore().collection('users').doc(userId).get();
        const userData = userDoc.data();
        
        if (!userData || !userData.subscription || userData.subscription.status !== 'active') {
            return res.status(400).json({ error: 'No active subscription found' });
        }
        
        const subscriptionId = userData.subscription.id;
        
        // Update user's subscription status in Firestore
        await admin.firestore().collection('users').doc(userId).update({
            'subscription.status': 'cancelled',
            'subscription.cancelledAt': admin.firestore.FieldValue.serverTimestamp()
        });
        
        // Update subscription in subscriptions collection
        await admin.firestore().collection('subscriptions').doc(subscriptionId).update({
            status: 'cancelled',
            cancelledAt: admin.firestore.FieldValue.serverTimestamp()
        });
        
        // Note: You would also need to call PayPal's API to cancel the subscription there
        // This is just updating your database
        
        res.json({ success: true });
    } catch (error) {
        console.error('Subscription cancellation error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Helper function to check if a user has premium access
async function hasUserPremiumAccess(userId) {
    try {
        const userDoc = await admin.firestore().collection('users').doc(userId).get();
        const userData = userDoc.data();
        
        if (!userData || !userData.subscription) {
            return false;
        }
        
        return userData.subscription.status === 'active';
    } catch (error) {
        console.error('Error checking premium access:', error);
        return false;
    }
}

// Helper function to validate and apply promo code
async function applyPromoCode(userId, promoCode) {
    try {
        // Get the promo code from Firestore
        const promoDoc = await admin.firestore()
            .collection('promo_codes')
            .doc(promoCode)
            .get();

        if (!promoDoc.exists) {
            return { success: false, error: 'Invalid promo code' };
        }

        const promoData = promoDoc.data();

        // Check if promo code is expired
        if (promoData.expiresAt && promoData.expiresAt.toDate() < new Date()) {
            return { success: false, error: 'Promo code has expired' };
        }

        // Check if promo code has been used too many times
        if (promoData.maxUses && promoData.uses >= promoData.maxUses) {
            return { success: false, error: 'Promo code has reached its maximum uses' };
        }

        // Check if user has already used this promo code
        const userPromoDoc = await admin.firestore()
            .collection('user_promo_codes')
            .doc(`${userId}_${promoCode}`)
            .get();

        if (userPromoDoc.exists) {
            return { success: false, error: 'You have already used this promo code' };
        }

        // Calculate expiration date (30 days from now)
        const expirationDate = new Date();
        expirationDate.setDate(expirationDate.getDate() + 365);

        // Update user's subscription
        await admin.firestore().collection('users').doc(userId).update({
            subscription: {
                status: 'active',
                plan: 'yearly',
                startDate: admin.firestore.FieldValue.serverTimestamp(),
                expiryDate: admin.firestore.Timestamp.fromDate(expirationDate),
                paymentProvider: 'promo',
                promoCode: promoCode,
                updatedAt: admin.firestore.FieldValue.serverTimestamp()
            }
        });

        // Record promo code usage
        await admin.firestore()
            .collection('user_promo_codes')
            .doc(`${userId}_${promoCode}`)
            .set({
                userId,
                promoCode,
                usedAt: admin.firestore.FieldValue.serverTimestamp()
            });

        // Update promo code usage count
        await admin.firestore()
            .collection('promo_codes')
            .doc(promoCode)
            .update({
                uses: admin.firestore.FieldValue.increment(1)
            });

        return { success: true };
    } catch (error) {
        console.error('Error applying promo code:', error);
        return { success: false, error: 'An error occurred while applying the promo code' };
    }
}

// Endpoint to apply promo code
app.post('/auth/apply-promo', async (req, res) => {
    try {
        const token = req.headers.authorization?.split('Bearer ')[1];
        if (!token) {
            return res.status(401).json({ error: 'No token provided' });
        }

        const decodedToken = await admin.auth().verifyIdToken(token);
        const userId = decodedToken.uid;
        const { promoCode } = req.body;

        if (!promoCode) {
            return res.status(400).json({ error: 'Promo code is required' });
        }

        const result = await applyPromoCode(userId, promoCode);
        
        if (result.success) {
            res.json({ success: true });
        } else {
            res.status(400).json({ error: result.error });
        }
    } catch (error) {
        console.error('Promo code application error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Example of a protected endpoint that requires premium
app.get('/api/premium-feature', async (req, res) => {
    try {
        const token = req.headers.authorization?.split('Bearer ')[1];
        if (!token) {
            return res.status(401).json({ error: 'No token provided' });
        }

        const decodedToken = await admin.auth().verifyIdToken(token);
        const userId = decodedToken.uid;
        
        // Check if user has premium access
        const hasPremium = await hasUserPremiumAccess(userId);
        
        if (!hasPremium) {
            return res.status(403).json({ 
                error: 'Premium subscription required',
                subscriptionRequired: true
            });
        }
        
        // Provide premium feature
        res.json({
            premiumData: "This is premium content"
        });
    } catch (error) {
        console.error('Premium feature error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Password reset endpoint
app.post('/auth/forgot-password', async (req, res) => {
    try {
        const { email } = req.body;
        
        if (!email) {
            return res.status(400).json({ error: 'Email is required' });
        }
        
        // Check if user exists
        const userSnapshot = await admin.firestore()
            .collection('users')
            .where('email', '==', email)
            .limit(1)
            .get();
            
        if (userSnapshot.empty) {
            // For security reasons, don't reveal if the email exists or not
            return res.json({ success: true });
        }
        
        const userId = userSnapshot.docs[0].id;
        
        // Generate a password reset token
        const resetToken = crypto.randomBytes(20).toString('hex');
        const resetExpires = Date.now() + 3600000; // 1 hour
        
        // Store the token in the user's document
        await admin.firestore().collection('users').doc(userId).update({
            resetPasswordToken: resetToken,
            resetPasswordExpires: resetExpires
        });
        
        // Create reset URL
        const resetUrl = `${req.protocol}://${req.get('host')}/reset-password.html?token=${resetToken}`;
        
        // Send email
        const mailOptions = {
            from: `"ListForge Support" <${process.env.EMAIL_USER}>`,
            to: email,
            subject: 'ListForge Password Reset Request',
            html: `
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                    <h2 style="color: #2d3748; margin-bottom: 20px;">Password Reset Request</h2>
                    <p style="color: #4a5568; margin-bottom: 20px;">You recently requested to reset your password for your ListForge account. Click the button below to reset it:</p>
                    <div style="text-align: center; margin: 30px 0;">
                        <a href="${resetUrl}" style="background-color: #2d3748; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; display: inline-block;">Reset Your Password</a>
                    </div>
                    <p style="color: #4a5568; margin-bottom: 10px;">If you did not request a password reset, please ignore this email or contact support if you have concerns.</p>
                    <p style="color: #4a5568; margin-bottom: 20px;">This password reset link is only valid for 1 hour.</p>
                    <hr style="border: none; border-top: 1px solid #e2e8f0; margin: 20px 0;">
                    <p style="color: #718096; font-size: 12px;">If you're having trouble clicking the password reset button, copy and paste the URL below into your web browser:</p>
                    <p style="color: #718096; font-size: 12px; word-break: break-all;">${resetUrl}</p>
                </div>
            `
        };
        
        await transporter.sendMail(mailOptions);
        
        res.json({ success: true });
        
    } catch (error) {
        console.error('Password reset error:', error);
        res.status(500).json({ error: 'An error occurred while processing your request' });
    }
});

// Reset password endpoint
app.post('/auth/reset-password', async (req, res) => {
    try {
        const { token, password } = req.body;
        
        if (!token || !password) {
            return res.status(400).json({ error: 'Token and password are required' });
        }
        
        // Find user with matching reset token
        const usersSnapshot = await admin.firestore()
            .collection('users')
            .where('resetPasswordToken', '==', token)
            .where('resetPasswordExpires', '>', Date.now())
            .limit(1)
            .get();
            
        if (usersSnapshot.empty) {
            return res.status(400).json({ error: 'Invalid or expired reset token' });
        }
        
        const userId = usersSnapshot.docs[0].id;
        const userEmail = usersSnapshot.docs[0].data().email;
        
        // Update user's password in Firebase Auth
        await admin.auth().updateUser(userId, {
            password: password
        });
        
        // Clear reset token
        await admin.firestore().collection('users').doc(userId).update({
            resetPasswordToken: null,
            resetPasswordExpires: null
        });
        
        res.json({ success: true });
        
    } catch (error) {
        console.error('Password reset error:', error);
        res.status(500).json({ error: 'An error occurred while resetting your password' });
    }
});

// Password change endpoint
app.post('/auth/change-password', async (req, res) => {
    try {
        const token = req.headers.authorization?.split('Bearer ')[1];
        if (!token) {
            return res.status(401).json({ error: 'No token provided' });
        }

        const decodedToken = await admin.auth().verifyIdToken(token);
        const { newPassword } = req.body;

        if (!newPassword) {
            return res.status(400).json({ error: 'New password is required' });
        }

        if (newPassword.length < 6) {
            return res.status(400).json({ error: 'New password must be at least 6 characters long' });
        }

        // Update the password
        await admin.auth().updateUser(decodedToken.uid, {
            password: newPassword
        });

        res.json({ success: true, message: 'Password updated successfully' });
    } catch (error) {
        console.error('Password change error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Serve static files
app.use(express.static('public'));

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server running on port ${PORT}`);
}); 