# V-OS Cloud Authentication
<p>Deployed from V-OS Cloud, a customisable app is configured to your organisational needs
and is individualized for each employee. The cloud platform provides operational efficiency
in the deployment of Trusted Identity services. It also optimises the cost of implementation
and maintenance, and focuses on ensuring usability on any IOS or Android device.</p>

## How V-Key Secures VPN Connections Using V-Key 2FA
![V-key](https://www.v-key.com/wp-content/uploads/2019/07/Layman-Terms-V-Key-2FA-copy.jpg)

1. User launches VPN software on laptop to access corporate network
1. Authentication process starts with user’s inputs of Username & Password (1FA) on laptop,
1. Upon successful verification of 1FA, V-Key App on user’s mobile device will be activate to request for 2FA
1. User will further verify (either facial/fingerprint biometrics or passcode) their identity through the V-Key App1.
1. When the 2FA is successfully verified, user will be able to access the corporate network

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
