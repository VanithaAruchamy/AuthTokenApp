const { app } = require('@azure/functions');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

// Dummy user data - in a real app, you would query the database
const users = {
    "testuser": {
        passwordHash: bcrypt.hashSync("password123", 10), // hashed password
        username: "testuser"
    }
};

app.http('auth', {
    methods: [ 'POST'],
    authLevel: 'anonymous', // Can be 'anonymous', 'function', 'admin', etc.
    handler: async (request, context) => {
        context.log(`Http function processed request for url "${request.url}"`);

        // Check if the request method is POST
        if (request.method === 'POST') {
            const { username, password } = await request.json();

            if (!username || !password) {
                context.res = {
                    status: 400,
                    body: "Please provide a username and password"
                };
                return;
            }

            const user = users[username];

            if (!user || !bcrypt.compareSync(password, user.passwordHash)) {
                context.res = {
                    status: 401,
                    body: "Invalid credentials"
                };
                return;
            }

            // Create JWT token
            const secret = process.env.JWT_SECRET || "your_secret_key";
            const token = jwt.sign({ username: user.username }, secret, { expiresIn: '1h' });

            context.res = {
                status: 200,
                body: {
                    message: "Login successful",
                    token: token
                }
            };
        } 
    }
});
