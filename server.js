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
const serviceAccount = require('./serviceAccount.json');  // Import your service account file

const app = express();
app.use(express.json());

// Initialize Firebase Admin with your service account
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
            email: userRecord.email
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

// Serve static files
app.use(express.static('public'));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
}); 