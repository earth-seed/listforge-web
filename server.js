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

// Register endpoint
app.post('/auth/register', async (req, res) => {
    try {
        const { email, password, username } = req.body;
        
        // Create user in Firebase Auth
        const userCredential = await createUserWithEmailAndPassword(auth, email, password);
        
        // Store additional user data in Firestore
        await setDoc(doc(db, 'users', userCredential.user.uid), {
            username,
            email,
            createdAt: new Date().toISOString()
        });

        // Get token for immediate login
        const token = await userCredential.user.getIdToken();
        
        res.json({ 
            token,
            success: true 
        });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// Login endpoint
app.post('/auth/login', async (req, res) => {
    try {
        const { login, password } = req.body;
        
        // Determine if login is email or username
        let email = login;
        if (!login.includes('@')) {
            // If username, get email from Firestore
            const usersRef = collection(db, 'users');
            const snapshot = await getDocs(query(usersRef, where('username', '==', login)));
            if (snapshot.empty) {
                throw new Error('User not found');
            }
            email = snapshot.docs[0].data().email;
        }

        const userCredential = await signInWithEmailAndPassword(auth, email, password);
        const token = await userCredential.user.getIdToken();
        
        res.json({ 
            token,
            success: true 
        });
    } catch (error) {
        res.status(400).json({ error: error.message });
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

        // Get user data from Firestore
        const userDoc = await admin.firestore().collection('users').doc(decodedToken.uid).get();
        const userData = userDoc.data();

        res.json({ 
            authenticated: true, 
            uid: decodedToken.uid,
            username: userData.username // Send username to client
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

// Add this endpoint to track subscriptions
app.post('/auth/update-subscription', async (req, res) => {
    try {
        const token = req.headers.authorization?.split('Bearer ')[1];
        const decodedToken = await admin.auth().verifyIdToken(token);
        const userId = decodedToken.uid;
        
        const { subscriptionId, plan } = req.body;
        
        // Update user's subscription status in Firestore
        await admin.firestore().collection('users').doc(userId).update({
            subscription: {
                id: subscriptionId,
                plan: plan,
                status: 'active',
                startDate: admin.firestore.FieldValue.serverTimestamp(),
                paymentProvider: 'paypal'
            }
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
        const decodedToken = await admin.auth().verifyIdToken(token);
        const userId = decodedToken.uid;
        
        const userDoc = await admin.firestore().collection('users').doc(userId).get();
        const userData = userDoc.data();
        
        res.json({
            hasSubscription: userData?.subscription?.status === 'active',
            plan: userData?.subscription?.plan
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Serve static files
app.use(express.static('public'));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
}); 