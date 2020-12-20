# V-OS Cloud Authentication
<p>Deployed from V-OS Cloud, a customisable app is configured to your organisational needs
and is individualized for each employee. The cloud platform provides operational efficiency
in the deployment of Trusted Identity services. It also optimises the cost of implementation
and maintenance, and focuses on ensuring usability on any IOS or Android device.</p>

## Experience V-OS Trusted Identity Services in 5 simple steps.
1. User launches VPN/Microsoft 365/Enterprise software on laptop
2. Authentication process is triggered and user inputs Username & Password (1FA) on laptop
3. Upon successful verification of 1FA, V-Key App on user’s mobile device will receive 2FA
push notification from V-OS Cloud
4. User need to verify (either fingerprint, facial recognition or passcode) their identity
through the V-Key App
5. When the 2FA is successfully verified, user will be able to access the services

![V-key](https://www.v-key.com/wp-content/uploads/2019/07/Layman-Terms-V-Key-2FA-copy.jpg)


## 2FA for VPN/RADIUS Flow Diagram
![VPN/RADIUS](https://cloud.v-key.com/assets/docs/static/img/f447b8860e9e9de9326977bad7c2b415.png)

1. End-user logs in to the VPN client app.
1. Primary authentication initiated to RADIUS service.
1. An authentication request triggered to RADIUS connector.
1. Primary authentication using directory connector integrating with the organization's directory service.
1. Secondary authentication is triggered by V-OS Cloud's PKI Suite.
1. The end-user uses the V-Key app to approve the login request.
1. V-OS Cloud IDM receives authentication respond.
1. V-OS Cloud IDM replies to the RADIUS server.
1. VPN client access is granted.

## 2FA in Actions

### 1. Login application portal.
![PulseSecure](/images/pulse-secure.png)

### 2. V-Key application push notification to input pin.
![V-Key](/images/v-key.png)

### 3. Successful with 2FA.


##### Members
- Bhoomjit Bhoominath
- Piyawit Khumkrong
