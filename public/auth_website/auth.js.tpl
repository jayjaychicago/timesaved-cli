const poolData = {
  UserPoolId: '{{{user_pool_id}}}',
  ClientId: '{{{client_id}}}'
};

const userPool = new AmazonCognitoIdentity.CognitoUserPool(poolData);

document.getElementById('signupForm').addEventListener('submit', function(e) {
    e.preventDefault();
    const username = document.getElementById('signupUsername').value;
    const email = document.getElementById('signupEmail').value;
    const password = document.getElementById('signupPassword').value;

    userPool.signUp(username, password, [
        new AmazonCognitoIdentity.CognitoUserAttribute({ Name: "email", Value: email })
    ], null, (err, result) => {
        if (err) {
            alert(err.message || JSON.stringify(err));
            return;
        }
        alert('Sign up successful. Please check your email for the confirmation code.');
    });
});

document.getElementById('confirmForm').addEventListener('submit', function(e) {
    e.preventDefault();
    const username = document.getElementById('confirmUsername').value;
    const code = document.getElementById('confirmCode').value;

    const userData = {
        Username: username,
        Pool: userPool
    };

    const cognitoUser = new AmazonCognitoIdentity.CognitoUser(userData);

    cognitoUser.confirmRegistration(code, true, (err, result) => {
        if (err) {
            alert(err.message || JSON.stringify(err));
            return;
        }
        alert('Confirmation successful. You can now sign in.');
    });
});

document.getElementById('signinForm').addEventListener('submit', function(e) {
    e.preventDefault();
    const username = document.getElementById('signinUsername').value;
    const password = document.getElementById('signinPassword').value;

    const authenticationData = {
        Username: username,
        Password: password,
    };
    const authenticationDetails = new AmazonCognitoIdentity.AuthenticationDetails(authenticationData);

    const userData = {
        Username: username,
        Pool: userPool
    };
    const cognitoUser = new AmazonCognitoIdentity.CognitoUser(userData);

    cognitoUser.authenticateUser(authenticationDetails, {
        onSuccess: function(result) {
            const idToken = result.getIdToken().getJwtToken();
            document.getElementById('tokenDisplay').innerHTML = `
    <h3>Authentication Successful</h3>
    <p>Your ID Token (use this for API requests):</p>
    <textarea readonly>$${idToken}</textarea>
`;
        },
        onFailure: function(err) {
            alert(err.message || JSON.stringify(err));
        },
    });
});